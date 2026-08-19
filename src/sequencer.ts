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
// NOTE (later slices, see DECISIONS.md): recovery / snapshot redemption /
// non-membership proofs (§C2b), silence and non-service grades, revocation,
// successor sequencers, dated instruments, multi-sequencer transfers, and
// prepare–decide–commit (§C3's atomicity across operators) are out of scope.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { type Backing } from "./backing.js";
import { compareBytes, copyBytes } from "./bytes.js";
import { signCommitment, stateRoot, type Commitment } from "./commitment.js";
import { isValidPublicKey } from "./keys.js";
import {
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
import { type OpLogEntry } from "./oplog.js";
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
import { Venue } from "./venue.js";

/** This operator declines to serve you. */
export class SequencerError extends Error {}

export class Sequencer {
  private readonly ledger = new TransparentLedger();
  // opHash (hex) -> the receipt returned when it was first accepted. Retained
  // to make replays idempotent (invariant 26); a later slice prunes entries an
  // eventual commitment has finalized.
  private readonly receipts = new Map<string, Receipt>();

  private readonly operatorKey: Uint8Array;

  constructor(
    private readonly operatorSecret: Uint8Array,
    private readonly venue: Venue,
  ) {
    this.operatorKey = ed25519.getPublicKey(operatorSecret);
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
    if (!isValidPublicKey(backing.evidence.operator)) {
      throw new SequencerError("backing operator key is not a valid Ed25519 point");
    }
    if (compareBytes(backing.evidence.operator, this.operatorKey) !== 0) {
      throw new SequencerError("this sequencer does not serve that backing");
    }
    this.ledger.register(backing, backingSignature);
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

  /** Routing is refused before an operation is even encoded. */
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
    return this.ledger.outstanding(backing);
  }

  balance(backing: Backing, holder: Uint8Array): bigint {
    return this.ledger.balance(backing, holder);
  }

  /** Units this holder can still spend: held minus committed by open demands. */
  availableBalance(backing: Backing, holder: Uint8Array): bigint {
    return this.ledger.availableBalance(backing, holder);
  }

  /** The standing demand record (invariant 23), as copies. */
  openDemands(backing: Backing): DemandRecord[] {
    return this.ledger.openDemands(backing);
  }

  /** A copy of the full operation log, all seven kinds. */
  opLog(backing: Backing): OpLogEntry[] {
    return this.ledger.opLog(backing);
  }

  nextNonce(signer: Uint8Array, backing: Backing): bigint {
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
