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
// NOTE (later slices, see DECISIONS.md): dated instruments, multi-sequencer
// transfers, and prepare–decide–commit (§C3's atomicity across operators) are
// out of scope.

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
  demandHash,
  type AcceptanceOp,
  type DemandOp,
  type LockOp,
  type ReleaseOp,
  type WithdrawalOp,
} from "./presentation.js";
import { copyReceipt, signReceipt, type Receipt } from "./receipt.js";
import { committedLogFor, type ServedState } from "./commitment.js";
import { isNamedSuccessor, operatorAt } from "./replacement.js";
import { gapLegsFor, venueIsDeclared } from "./recovery.js";
import { revokedAt } from "./revocation.js";
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
  /**
   * Whether this operator may take a gap publication on this backing at all.
   *
   * **A demand on a backing with reliance is refused here**, because the legs
   * cannot come with it: invariant 13 wants q·cᵢ units of each target reserved,
   * a lock is not a gap leg (recovery.ts), and the law is per backing so nothing
   * below can see the shortfall. Adopted anyway, a holder settles the set during
   * a gap and keeps the whole accompaniment — 40 units to the backer with none
   * of what must accompany them.
   *
   * Settling a set locked BEFORE the gap is untouched: each leg's own release is
   * an ordinary gap leg, so the set resolves wherever it was already reserved.
   * What is refused is opening a new reliant presentation with no operator to
   * take the locks — and refusing is §C2b's own posture, since claims "go
   * illiquid rather than dead" while the operator is away.
   */
  private mayAdopt(backing: Backing, op: PublishedOp): boolean {
    return !(op.kind === "demand" && backing.reliance.length > 0);
  }

  private adoptOne(backing: Backing, op: PublishedOp, at: bigint): void {
    if (!this.mayAdopt(backing, op)) return;
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

  /**
   * **Refused once this backing's obligor key is revoked** (§C2b: "no further
   * issuance is valid"). Only issuance — transfers, burns and every presentation
   * leg go on, because "existing claims keep their terms", and an operator that
   * stopped serving those would strand the holders the revocation exists to
   * protect.
   *
   * The tie at the revocation's own index goes against this operator, which is
   * the rule slice 8 settled for a publication judged "against the record as it
   * stood strictly before its own index": the operator is the party watching the
   * venue, and the tie must not go to it.
   *
   * **Refusal here, and nothing in the law.** The ledger applies a post-boundary
   * issuance perfectly happily, and that is deliberate — see standingOutstanding
   * (recovery.ts) for why refusing it in the replay would make every holder of
   * the backing unable to prove anything at all.
   */
  submitIssue(op: IssuanceOp, signature: Uint8Array): Receipt {
    const backing = this.served(op.backing);
    if (revokedAt(this.venue, backing) !== undefined) {
      throw new SequencerError("this backing's obligor key is revoked: no further issuance");
    }
    const { recipient, quantity, nonce } = op;
    return this.submit([
      { backing, op: { kind: "issue", recipient, quantity, nonce, signature } },
    ]);
  }

  submitTransfer(op: TransferOp, signature: Uint8Array): Receipt {
    const backing = this.served(op.backing);
    const { from, to, quantity, nonce } = op;
    return this.submit([
      { backing, op: { kind: "transfer", from, to, quantity, nonce, signature } },
    ]);
  }

  submitBurn(op: BurnOp, signature: Uint8Array): Receipt {
    const backing = this.served(op.backing);
    const { holder, quantity, nonce } = op;
    return this.submit([{ backing, op: { kind: "burn", holder, quantity, nonce, signature } }]);
  }

  /**
   * File a demand, and reserve its reliance legs in the same act.
   *
   * §C3: "Single-phase wherever every lock in the set can be taken in one
   * atomically signed decision... the whole set and the paying leg inside one
   * operator." This operator serves the whole set, so it takes the demand and
   * every lock together or refuses the lot.
   *
   * **The locks are the holder's to sign, and this only checks they are the
   * right ones**: exactly one per entry in R(b), each for q·cᵢ units (invariant
   * 13), each naming this demand and paying the demanded backing's obligor.
   * Building them here instead would be co-signing a commitment of somebody's
   * units they never authorised, which is the path invariant 8 forbids.
   */
  submitDemand(
    op: DemandOp,
    signature: Uint8Array,
    legs: readonly { readonly op: LockOp; readonly signature: Uint8Array }[] = [],
  ): Receipt {
    const backing = this.served(op.backing);
    const { holder, quantity, instant, deadline, nonce } = op;
    const demand: PublishedOp = {
      kind: "demand",
      holder,
      quantity,
      instant,
      deadline,
      nonce,
      signature,
    };
    return this.submit([
      { backing, op: demand },
      ...this.legSet(backing, demandHash(op), op.holder, op.quantity, legs),
    ]);
  }

  submitAcceptance(op: AcceptanceOp, signature: Uint8Array): Receipt {
    const backing = this.served(op.backing);
    const { demandHash: hash, instant, deadline, nonce } = op;
    return this.submit([
      { backing, op: { kind: "acceptance", demandHash: hash, instant, deadline, nonce, signature } },
    ]);
  }

  /**
   * Settle, set and all. §C3 settles on one release, so every backing in the set
   * resolves its own part: the demanded backing moves the claims, each leg moves
   * the accompaniment to the beneficiary its lock names. All or none, for the
   * reason the demand and its locks were taken that way.
   */
  submitRelease(
    op: ReleaseOp,
    signature: Uint8Array,
    legs: readonly { readonly op: ReleaseOp; readonly signature: Uint8Array }[] = [],
  ): Receipt {
    return this.endDemand("release", op, signature, legs);
  }

  /** The other exit, on the same terms: the demand ends and every lock frees. */
  submitWithdrawal(
    op: WithdrawalOp,
    signature: Uint8Array,
    legs: readonly { readonly op: WithdrawalOp; readonly signature: Uint8Array }[] = [],
  ): Receipt {
    return this.endDemand("withdrawal", op, signature, legs);
  }

  private endDemand(
    kind: "release" | "withdrawal",
    op: ReleaseOp | WithdrawalOp,
    signature: Uint8Array,
    legs: readonly { readonly op: ReleaseOp | WithdrawalOp; readonly signature: Uint8Array }[],
  ): Receipt {
    const backing = this.served(op.backing);
    // **The head of the set, not one of its legs.** A leg's own state resolves a
    // release by the lock it holds, and the law cannot tell a head from a leg —
    // a release names a demand hash and each backing answers for whatever record
    // it has under it. So a leg submitted on its own would settle its
    // accompaniment to the backer with no demand settled and no acceptance
    // needed, which is the whole of what taking the set together prevents.
    // Found reviewing the slice; review-leg-adjacent.
    if (this.ledger.hasLock(backing, op.demandHash)) {
      throw new SequencerError("that backing is a leg of this demand, not the demand it accompanies");
    }
    const head: PublishedOp = { kind, demandHash: op.demandHash, nonce: op.nonce, signature };
    const items = [{ backing, op: head }];
    // Exactly the backings this demand has locks on, and no others: a leg the
    // set does not name would be resolving somebody else's reservation.
    const expected = new Set(backing.reliance.map((entry) => bytesToHex(entry.target)));
    if (legs.length !== expected.size) {
      throw new SequencerError("the set must name every reliance leg, and only those");
    }
    for (const leg of legs) {
      const legBacking = this.served(leg.op.backing);
      if (!expected.delete(legBacking.nameHex)) {
        throw new SequencerError("that backing is not a reliance leg of this demand");
      }
      if (compareBytes(leg.op.demandHash, op.demandHash) !== 0) {
        throw new SequencerError("a leg must name the demand being settled");
      }
      const legOp: PublishedOp = {
        kind,
        demandHash: leg.op.demandHash,
        nonce: leg.op.nonce,
        signature: leg.signature,
      };
      items.push({ backing: legBacking, op: legOp });
    }
    return this.submit(items);
  }

  /**
   * The locks a demand on this backing must carry, checked against R(b) rather
   * than taken on the caller's word.
   */
  private legSet(
    backing: Backing,
    hash: Uint8Array,
    holder: Uint8Array,
    quantity: bigint,
    legs: readonly { readonly op: LockOp; readonly signature: Uint8Array }[],
  ): { backing: Backing; op: PublishedOp }[] {
    if (legs.length !== backing.reliance.length) {
      throw new SequencerError("a demand must lock every reliance leg, and only those");
    }
    return backing.reliance.map((entry) => {
      const supplied = legs.find(
        (leg) => compareBytes(leg.op.backing.name, entry.target) === 0,
      );
      if (supplied === undefined) throw new SequencerError("a reliance leg is not locked");
      const legBacking = this.served(supplied.op.backing);
      // Invariant 13's arithmetic, and the only place it is applied: q units of
      // the claim need q·cᵢ of each target.
      if (supplied.op.quantity !== quantity * entry.count) {
        throw new SequencerError("a lock does not cover q·c units of its leg");
      }
      if (compareBytes(supplied.op.demandHash, hash) !== 0) {
        throw new SequencerError("a lock must name the demand it accompanies");
      }
      if (compareBytes(supplied.op.holder, holder) !== 0) {
        throw new SequencerError("a lock must commit the demanding holder's units");
      }
      // Where the accompaniment goes: the DEMANDED backing's obligor, who takes
      // in the set and may then present at this leg itself.
      if (compareBytes(supplied.op.beneficiary, backing.obligor) !== 0) {
        throw new SequencerError("a lock must pay the demanded backing's obligor");
      }
      // Built field by field rather than cast: a cast here suppressed the
      // exhaustiveness that catches a field added to the kind and forgotten,
      // and the lock's timeout was forgotten exactly that way.
      const op: PublishedOp = {
        kind: "lock",
        demandHash: supplied.op.demandHash,
        holder: supplied.op.holder,
        beneficiary: supplied.op.beneficiary,
        quantity: supplied.op.quantity,
        timeout: supplied.op.timeout,
        nonce: supplied.op.nonce,
        signature: supplied.signature,
      };
      return { backing: legBacking, op };
    });
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
   * Routing and the sequencer's own copy in one step. The copy matters: terms
   * reached through it are the ones this operator registered, not whatever the
   * caller handed in beside a matching name.
   */
  private served(backing: Backing): Backing {
    this.requireServed(backing);
    return this.backings.get(backing.nameHex) as Backing;
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
  private submit(items: readonly { readonly backing: Backing; readonly op: PublishedOp }[]): Receipt {
    // §C2: "Until then the predecessor's last commitment governs, no new
    // co-signatures issue." A successor that has taken over the state but not
    // yet committed it is not the operator yet, and a receipt from it would be
    // a co-signature nobody's chain accounts for. Asked of every backing in the
    // set before any of it is applied.
    for (const item of items) {
      if (!this.isInForce(item.backing)) {
        throw new SequencerError("this sequencer is not yet in force for that backing");
      }
    }
    // Before anything is co-signed, and before an idempotent replay is answered:
    // what the venue witnessed during a gap comes first, or this operator would
    // be serving a history the record has already moved past.
    for (const item of items) this.adopt(item.backing);

    const hashes = items.map((item) => opHashOfEntry(item.backing.name, item.op));
    // Keyed on the FIRST operation, which is the one the caller asked for: a
    // demand and its locks are one act, so a replay of the demand answers for
    // the set exactly as it was accepted (invariant 26).
    const key = bytesToHex(hashes[0] as Uint8Array);
    const existing = this.receipts.get(key);
    // A copy on both paths: the stored receipt is the operator's record of what
    // it co-signed, and a caller that could reach into it would decide what
    // every later replay is answered with.
    if (existing !== undefined) return copyReceipt(existing);

    const entries = this.ledger.applyAll(items, this.witnessedIndex());
    const receipts = entries.map((entry, i) =>
      signReceipt(
        this.operatorSecret,
        (items[i] as { readonly backing: Backing }).backing.name,
        hashes[i] as Uint8Array,
        BigInt(entry.position),
      ),
    );
    // Every accepted operation is co-signed, legs included: an operator cannot
    // deny having taken one, and the holder's reservation is as attributable as
    // the demand it accompanies.
    receipts.forEach((receipt, i) => this.receipts.set(bytesToHex(hashes[i] as Uint8Array), receipt));
    return copyReceipt(receipts[0] as Receipt);
  }
}
