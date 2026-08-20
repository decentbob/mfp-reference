// The transparent sequencer (§C2).
//
// A sequencer serves the backings whose E field names its operator key. It is
// the front door to the claim layer: clients submit signed operations, the
// sequencer drives the transparent ledger underneath, and returns an operator
// co-signed receipt bound to the operation's position in the committed log. At
// a declared interval it publishes a commitment over the state it serves.
//
// It never holds funds. Its added value in the transparent setting (where the
// ledger already prevents double-spends) is fourfold:
//   - witnessed order: a receipt binds an operation to its committed position;
//   - idempotent replay (invariant 26): the same operation resubmitted returns
//     the identical prior receipt, and a different operation at an
//     already-spent nonce is declined by the ledger's NonceError — the
//     sequencer "refuses a second spend by declining to sign";
//   - commitments (invariants 22, 23): periodic signed roots over served
//     state, so a third party can verify state without trusting the
//     operator's live word;
//   - a witnessed clock: presentation (§C3) turns on indices, and invariant 21
//     forbids a time a party asserts alone, so the index comes from the venue —
//     which advances whether or not this operator publishes, so a sequencer
//     cannot freeze a deadline by going quiet.
//
// One venue per sequencer, taken at construction. The spec names the venue in E
// beside the operator; E carries only the operator key here, so one venue for
// the operator is the honest simplification — and it means there is exactly one
// clock, where a venue passed per call could give two answers to one predicate.
//
// Boundaries, per the design rules: the sequencer owns routing (is this
// backing mine?) and the clock, and raises SequencerError; the ledger owns the
// law and funds and raises LedgerError/NonceError; malformed fields raise
// EncodingError from the encoder. No layer re-checks or relabels another's
// verdict.
//
// **Coming back from silence.** §C2b: "a sequencer returning from silence adopts
// every nullifier witnessed during the gap before co-signing again." Adoption is
// enforced structurally rather than by a flag: `submit` adopts before it applies
// anything, and `commit` before it snapshots, so there is no order of calls in
// which this operator co-signs while ignoring what the venue witnessed without
// it. Each adopted operation is judged at the index the VENUE stamped it with,
// so adoption is reproducible by anyone holding the same record — the sequencer
// asserts nothing about when.
//
// NOTE (later slices, see DECISIONS.md): non-service grades, revocation,
// successor sequencers, dated instruments, multi-sequencer transfers, and
// prepare–decide–commit (§C3's atomicity across operators) are out of scope.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { makeBacking, type Backing } from "./backing.js";
import { compareBytes, copyBytes } from "./bytes.js";
import { signCommitment, stateRoot, type Commitment } from "./commitment.js";
import {
  replayLog,
  TransparentLedger,
  type BackingSnapshot,
  type DemandRecord,
} from "./ledger.js";
import {
  encodeBurn,
  encodeIssuance,
  encodeTransfer,
  type BurnOp,
  type IssuanceOp,
  type TransferOp,
} from "./messages.js";
import { opHashOfEntry, type OpLogEntry, type PublishedOp } from "./oplog.js";
import {
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
  encodeWithdrawal,
  type AcceptanceOp,
  type DemandOp,
  type ReleaseOp,
  type WithdrawalOp,
} from "./presentation.js";
import { copyReceipt, signReceipt, type Receipt } from "./receipt.js";
import { committedLogFor, type ServedState } from "./commitment.js";
import { isNamedSuccessor, operatorAt } from "./replacement.js";
import { gapLegsFor, venueIsDeclared } from "./recovery.js";
import { Venue } from "./venue.js";

/** This operator declines to serve you. */
export class SequencerError extends Error {}

export class Sequencer {
  private readonly ledger = new TransparentLedger();
  // opHash (hex) -> the receipt returned when it was first accepted. Retained
  // to make replays idempotent (invariant 26); a later slice prunes entries an
  // eventual commitment has finalized.
  private readonly receipts = new Map<string, Receipt>();

  // Backing name hex -> this sequencer's own copy. Adoption needs the terms —
  // the silence duration in E is what dates a gap — and `commit` needs to reach
  // every backing it serves without the ledger handing out a Backing object,
  // which would be handing out the obligor key that authorises issuance.
  private readonly backings = new Map<string, Backing>();

  private readonly operatorSecret: Uint8Array;
  private readonly operatorKey: Uint8Array;

  constructor(operatorSecret: Uint8Array, private readonly venue: Venue) {
    // The sequencer's own copy of both halves of its identity. Retaining the
    // caller's secret array would let a later mutation split signing from
    // routing: it would keep serving as the operator E names while co-signing as
    // another, so its declared identity would read as having gone quiet.
    this.operatorSecret = copyBytes(operatorSecret);
    this.operatorKey = ed25519.getPublicKey(this.operatorSecret);
  }

  /**
   * This operator's verification key, as a copy. A public Uint8Array field would
   * be a write path into the key this sequencer routes and commits by — and
   * `readonly` is erased at runtime, so it is no boundary at all.
   */
  get operator(): Uint8Array {
    return copyBytes(this.operatorKey);
  }

  /**
   * Take on a backing whose E names this operator. Rejects a backing served by
   * a different operator, and (via the ledger) one without a valid obligor
   * signature over its name.
   */
  register(backing: Backing, backingSignature: Uint8Array): void {
    // makeBacking has already established that the operator key is a valid
    // non-small-order point; the only question left here is whether it is mine.
    // In force, or named to take over. §C2 gives a successor force only from
    // its own first commitment, and it cannot commit a state it was never
    // allowed to take on — so being named is what lets it serve, and being in
    // force is what lets it co-sign (submit, below).
    if (
      compareBytes(operatorAt(backing, this.venue, this.venue.witnessedIndex()), this.operatorKey) !==
        0 &&
      !isNamedSuccessor(backing, this.venue, this.operatorKey)
    ) {
      throw new SequencerError("this sequencer does not serve that backing");
    }
    // The second half of the same routing question. A backing declaring a venue
    // this sequencer does not publish at would have its commitments witnessed
    // somewhere its own terms do not name, so nobody reading correctly could
    // find them — and the operator would look permanently silent to everyone.
    if (!venueIsDeclared(this.venue, backing)) {
      throw new SequencerError("this sequencer does not publish at that backing's venue");
    }
    this.ledger.register(backing, backingSignature);
    this.backings.set(backing.nameHex, makeBacking(backing));
  }

  /**
   * Whether this operator is the one in force for this backing right now — the
   * question §C2 answers with "until then the predecessor's last commitment
   * governs, no new co-signatures issue".
   */
  private isInForce(backing: Backing): boolean {
    return (
      compareBytes(
        operatorAt(backing, this.venue, this.venue.witnessedIndex()),
        this.operatorKey,
      ) === 0
    );
  }

  /**
   * Take on the state a predecessor committed, so that this operator can commit
   * it as its own and thereby take force (§C2: a replacement "takes effect only
   * from the first index at which it has published its own commitment over a
   * spent set it serves in full").
   *
   * **The whole committed log, replayed through the same law.** Every entry goes
   * through the one door `apply`, so a state that could not have happened is
   * refused here rather than adopted, and the positions come out identical
   * because they are the log's own append indices.
   *
   * The clock is undefined, which is the boundary a replay always has: a served
   * log does not record the index each operation was accepted at. It is the same
   * weakness `replayLog` has and for the same reason.
   *
   * What is NOT taken on is the predecessor's uncommitted tail. That is not a
   * transparent problem and is not rescued: a payment is final when witnessed
   * rather than co-signed, and an operation the predecessor accepted and never
   * committed died with it in every construction (CLAUDE.md).
   *
   * **`incumbentLatest` is evidence, and it is needed in exactly one case.**
   * Normally the state taken on must be the incumbent's latest, or an older one
   * would silently drop everything committed since. But an incumbent that has
   * dropped this backing from its commitments has no latest state carrying it,
   * and refusing on that ground made §C2b's own remedy unexecutable: the
   * non-service grade fires, opens E's replacement rule, and the successor
   * could take nothing. So an earlier state is licensed by exhibiting the
   * incumbent's latest and showing it carries no log for this backing.
   *
   * **Bounded rather than checked**, which is the same limit slice 13 recorded.
   * WHICH state was the last to carry the backing is not readable from a root,
   * so a successor could take an earlier one than it should. That is not
   * licensed here, it is provable: any holder of the later state shows it with
   * isRewrittenHistory, against the successor, which is exactly why slice 14
   * extended that predicate across a handover.
   */
  takeOver(backing: Backing, served: ServedState, incumbentLatest?: ServedState): void {
    this.requireServed(backing);
    const held = this.backings.get(backing.nameHex) as Backing;
    if (this.isInForce(held)) {
      throw new SequencerError("this sequencer is already in force for that backing");
    }
    // Onto an empty log, or it is not a takeover. Applying a second time would
    // meet its own spent nonces and refuse in the ledger's voice, which names
    // the wrong boundary for what is a sequencer's own precondition.
    if (this.ledger.opLog(held).length > 0) {
      throw new SequencerError("this sequencer has already taken over that backing");
    }
    const committed = committedLogFor(held, this.venue, served);
    if (committed === undefined || committed.kind === "dropped") {
      throw new SequencerError("that is not a state this backing's operator committed");
    }
    // The predecessor's LAST commitment, and the predecessor is whoever is in
    // force. Taking on an older one would drop everything committed since.
    const incumbent = operatorAt(held, this.venue, this.venue.witnessedIndex());
    const latest = this.venue.latestFor(incumbent);
    if (latest === undefined || compareBytes(served.commitment.operator, incumbent) !== 0) {
      throw new SequencerError("that is not the incumbent's latest committed state");
    }
    if (compareBytes(served.commitment.root, latest.root) !== 0) {
      this.requireDroppedBy(held, incumbentLatest, latest);
      // And it must really precede that latest. A state at or past it is not an
      // earlier one this evidence excuses; it is a state the incumbent never
      // published, and one signed at a sequence it did publish is equivocation
      // that isEquivocation names on its own.
      if (committed.sequence >= latest.sequence) {
        throw new SequencerError("that state does not precede the incumbent's latest");
      }
    }
    // All or nothing. committedLogFor checks the root and the signature and
    // deliberately does not replay the law, so a well-rooted log that is not a
    // history that could have happened would otherwise apply until one entry
    // was refused — leaving a truncated state this operator would then commit,
    // which is the very fault isRewrittenHistory watches a handover for. The
    // ledger is atomic per operation; this is the one place that applies many.
    if (replayLog(held, committed.opLog) === undefined) {
      throw new SequencerError("that committed state is not a history that could have happened");
    }
    for (const entry of committed.opLog) this.ledger.apply(held, entry, undefined);
  }

  /**
   * The evidence that licenses taking on an earlier state: the incumbent's
   * latest committed state, carrying no log for this backing.
   *
   * It has to be the **latest**, not merely one the incumbent once signed. A
   * superseded state that dropped the backing says nothing about what the
   * incumbent serves now — it may have picked it up again in the next
   * commitment — so pinning the evidence to the venue's own latest record is
   * what keeps the exception as narrow as the case that forced it.
   */
  private requireDroppedBy(
    backing: Backing,
    evidence: ServedState | undefined,
    latest: Commitment,
  ): void {
    if (evidence === undefined) {
      throw new SequencerError("that is not the incumbent's latest committed state");
    }
    if (
      evidence.commitment.sequence !== latest.sequence ||
      compareBytes(evidence.commitment.root, latest.root) !== 0 ||
      compareBytes(evidence.commitment.operator, latest.operator) !== 0
    ) {
      throw new SequencerError("that evidence is not the incumbent's latest committed state");
    }
    // committedLogFor re-roots the evidence against its own commitment, so a
    // state that merely claims the latest root does not pass.
    if (committedLogFor(backing, this.venue, evidence)?.kind !== "dropped") {
      throw new SequencerError("the incumbent's latest commitment still carries this backing");
    }
  }

  /**
   * Take on everything the venue witnessed against this backing while this
   * operator was dark (§C2b), in the order it was witnessed. Each operation is
   * applied at the index the venue stamped it with, never at the index adoption
   * happens to run at — a leg is judged by when it was published, and by the
   * time a sequencer can adopt it the silence has ended by definition.
   *
   * A publication the law refuses is skipped rather than fatal: anyone may
   * publish anything at the venue, so noise there is ordinary and must not stop
   * this operator serving. Idempotent for the same reason a resubmission is —
   * an operation already in the log fails on its own spent nonce.
   */
  adopt(backing: Backing): void {
    this.requireServed(backing);
    const served = this.backings.get(backing.nameHex) as Backing;
    // "No new co-signatures issue" until this operator is in force. Adoption is
    // co-signing, so a successor that has taken over but not yet committed
    // leaves the gap legs for its own first serving moment rather than
    // answering for them now.
    //
    // Asked once rather than per leg: the answer is the same for all of them,
    // and asking walks the chain, which verifies a signature per published
    // replacement — both counts being the adversary's to grow.
    if (!this.isInForce(served)) return;
    for (const witnessed of gapLegsFor(this.venue, served)) {
      this.adoptOne(served, witnessed.op, witnessed.at);
    }
  }

  /**
   * One adopted operation, co-signed as if it had been submitted. The holder had
   * to publish it at the venue because this operator was not there to take it,
   * and invariant 26 does not care where a request arrived: it is an accepted
   * operation, so it gets the receipt it would have got.
   */
  private adoptOne(backing: Backing, op: PublishedOp, at: bigint): void {
    const key = bytesToHex(opHashOfEntry(backing.name, op));
    if (this.receipts.has(key)) return;
    let entry: OpLogEntry;
    try {
      entry = this.ledger.apply(backing, op, at);
    } catch {
      return;
    }
    this.receipts.set(
      key,
      signReceipt(this.operatorSecret, backing.name, opHashOfEntry(backing.name, op), BigInt(entry.position)),
    );
  }

  submitIssue(op: IssuanceOp, signature: Uint8Array): Receipt {
    this.requireServed(op.backing);
    return this.submit(op.backing, encodeIssuance(op), () => this.ledger.issue(op, signature));
  }

  submitTransfer(op: TransferOp, signature: Uint8Array): Receipt {
    this.requireServed(op.backing);
    return this.submit(op.backing, encodeTransfer(op), () => this.ledger.transfer(op, signature));
  }

  submitBurn(op: BurnOp, signature: Uint8Array): Receipt {
    this.requireServed(op.backing);
    return this.submit(op.backing, encodeBurn(op), () => this.ledger.burn(op, signature));
  }

  /**
   * Presentation (§C3), through the same path. Each of the four takes the
   * witnessed index from this operator's latest commitment — read inside the
   * apply thunk, so a replay is answered from the receipt store without
   * consulting the clock at all. That is what invariant 26 requires of a
   * partition recovery: repeating the request cannot change the answer, even if
   * the deadline it turned on has since passed.
   */
  submitDemand(op: DemandOp, signature: Uint8Array): Receipt {
    this.requireServed(op.backing);
    return this.submit(op.backing, encodeDemand(op), () =>
      this.ledger.demand(op, signature, this.witnessedIndex()),
    );
  }

  submitAcceptance(op: AcceptanceOp, signature: Uint8Array): Receipt {
    this.requireServed(op.backing);
    return this.submit(op.backing, encodeAcceptance(op), () =>
      this.ledger.accept(op, signature, this.witnessedIndex()),
    );
  }

  submitRelease(op: ReleaseOp, signature: Uint8Array): Receipt {
    this.requireServed(op.backing);
    return this.submit(op.backing, encodeRelease(op), () =>
      this.ledger.release(op, signature, this.witnessedIndex()),
    );
  }

  submitWithdrawal(op: WithdrawalOp, signature: Uint8Array): Receipt {
    this.requireServed(op.backing);
    return this.submit(op.backing, encodeWithdrawal(op), () =>
      this.ledger.withdraw(op, signature, this.witnessedIndex()),
    );
  }

  /**
   * Routing is refused before an operation is even encoded, and before any read
   * is answered. "Is this backing mine?" is the sequencer's question, so a
   * client can tell an operator that does not serve them from the law refusing
   * them — the ledger would answer with a LedgerError, which names the wrong
   * boundary.
   */
  private requireServed(backing: Backing): void {
    if (!this.ledger.has(backing)) {
      throw new SequencerError("backing not served by this sequencer");
    }
  }

  /**
   * Publish a commitment over the served state. The index comes from the
   * venue's record of this operator, so a failed publish does not burn one.
   */
  commit(): Commitment {
    for (const backing of this.backings.values()) this.adopt(backing);
    const root = stateRoot(this.snapshot());
    const commitment = signCommitment(
      this.operatorSecret,
      this.venue.nextSequenceFor(this.operatorKey),
      root,
    );
    this.venue.publish(commitment);
    return commitment;
  }

  /**
   * The index every time-dependent decision is read at: the venue's, never this
   * operator's own publication history. "Finality means witnessed rather than
   * co-signed" (§C2b) — and a clock an operator could stop by going quiet would
   * hand it every deadline in its book.
   */
  witnessedIndex(): bigint {
    return this.venue.witnessedIndex();
  }

  /** The served state, as it would be published for a verifier (invariant 23). */
  snapshot(): BackingSnapshot[] {
    return this.ledger.snapshotAll();
  }

  outstanding(backing: Backing): bigint {
    this.requireServed(backing);
    return this.ledger.outstanding(backing);
  }

  balance(backing: Backing, holder: Uint8Array): bigint {
    this.requireServed(backing);
    return this.ledger.balance(backing, holder);
  }

  /** Units this holder can still spend: held minus committed by open demands. */
  availableBalance(backing: Backing, holder: Uint8Array): bigint {
    this.requireServed(backing);
    return this.ledger.availableBalance(backing, holder);
  }

  /** The standing demand record (invariant 23), as copies. */
  openDemands(backing: Backing): DemandRecord[] {
    this.requireServed(backing);
    return this.ledger.openDemands(backing);
  }

  /** A copy of the full operation log, all seven kinds. */
  opLog(backing: Backing): OpLogEntry[] {
    this.requireServed(backing);
    return this.ledger.opLog(backing);
  }

  nextNonce(signer: Uint8Array, backing: Backing): bigint {
    this.requireServed(backing);
    return this.ledger.nextNonce(signer, backing);
  }

  /**
   * The shared submit path: routing, then idempotency, then the ledger, then
   * the co-signed receipt. A replay of an accepted operation returns the
   * identical prior receipt without touching the ledger (invariant 26), and a
   * rejected operation records nothing, so a later valid operation at that
   * nonce still succeeds.
   */
  private submit(backing: Backing, opMessage: Uint8Array, apply: () => OpLogEntry): Receipt {
    // §C2: "Until then the predecessor's last commitment governs, no new
    // co-signatures issue." A successor that has taken over the state but not
    // yet committed it is not the operator yet, and a receipt from it would be
    // a co-signature nobody's chain accounts for.
    if (!this.isInForce(backing)) {
      throw new SequencerError("this sequencer is not yet in force for that backing");
    }
    // Before anything is co-signed, and before an idempotent replay is answered:
    // what the venue witnessed during a gap comes first, or this operator would
    // be serving a history the record has already moved past.
    this.adopt(backing);
    const opHash = sha256(opMessage);
    const key = bytesToHex(opHash);
    const existing = this.receipts.get(key);
    // A copy on both paths: the stored receipt is the operator's record of what
    // it co-signed, and a caller that could reach into it would decide what
    // every later replay is answered with.
    if (existing !== undefined) return copyReceipt(existing);

    const entry = apply();
    const receipt = signReceipt(this.operatorSecret, backing.name, opHash, BigInt(entry.position));
    this.receipts.set(key, receipt);
    return copyReceipt(receipt);
  }
}
