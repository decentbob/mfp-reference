// The transparent sequencer (§C2).
//
// A sequencer serves the backings whose E field names its operator key. It is
// the front door to the claim layer: clients submit signed operations, the
// sequencer drives the transparent ledger underneath, and returns an operator
// co-signed receipt bound to the operation's position in the committed log. At
// a declared interval it publishes a commitment over the state it serves.
//
// It never holds funds. Its added value in the transparent setting (where the
// ledger already prevents double-spends) is threefold:
//   - witnessed order: a receipt binds an operation to its committed position;
//   - idempotent replay (invariant 26): the same operation resubmitted returns
//     the identical prior receipt, and a different operation at an
//     already-spent nonce is declined by the ledger's NonceError — the
//     sequencer "refuses a second spend by declining to sign";
//   - commitments (invariants 22, 23): periodic signed roots over served
//     state, so a third party can verify state without trusting the
//     operator's live word.
//
// Boundaries, per the design rules: the sequencer owns routing (is this
// backing mine?) and raises SequencerError; the ledger owns the law and funds
// and raises LedgerError/NonceError; malformed fields raise EncodingError from
// the encoder. No layer re-checks or relabels another's verdict.
//
// NOTE (later slices, see DECISIONS.md): recovery / snapshot redemption /
// non-membership proofs (§C2b), silence and non-service grades, revocation,
// successor sequencers, dated instruments, multi-sequencer transfers, and
// presentation/dishonour (§C3) are all out of scope here.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { type Backing } from "./backing.js";
import { compareBytes } from "./bytes.js";
import { signCommitment, stateRoot, type BackingSnapshot, type Commitment } from "./commitment.js";
import { isValidPublicKey } from "./keys.js";
import { TransparentLedger } from "./ledger.js";
import {
  encodeBurn,
  encodeIssuance,
  encodeTransfer,
  type BurnOp,
  type IssuanceOp,
  type TransferOp,
} from "./messages.js";
import { signReceipt, type Receipt } from "./receipt.js";
import { Venue } from "./venue.js";

/** This operator declines to serve you. */
export class SequencerError extends Error {}

export class Sequencer {
  private readonly ledger = new TransparentLedger();
  // opHash (hex) -> the receipt returned when it was first accepted. Retained
  // to make replays idempotent (invariant 26); a later slice prunes entries an
  // eventual commitment has finalized.
  private readonly receipts = new Map<string, Receipt>();

  readonly operator: Uint8Array;

  constructor(private readonly operatorSecret: Uint8Array) {
    this.operator = ed25519.getPublicKey(operatorSecret);
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
    if (compareBytes(backing.evidence.operator, this.operator) !== 0) {
      throw new SequencerError("this sequencer does not serve that backing");
    }
    this.ledger.register(backing, backingSignature);
  }

  submitIssue(op: IssuanceOp, signature: Uint8Array): Receipt {
    return this.submit(op.backing, encodeIssuance(op), () => this.ledger.issue(op, signature));
  }

  submitTransfer(op: TransferOp, signature: Uint8Array): Receipt {
    return this.submit(op.backing, encodeTransfer(op), () => this.ledger.transfer(op, signature));
  }

  submitBurn(op: BurnOp, signature: Uint8Array): Receipt {
    return this.submit(op.backing, encodeBurn(op), () => this.ledger.burn(op, signature));
  }

  /**
   * Publish a commitment over the served state. The index comes from the
   * venue's record of this operator, so a failed publish does not burn one.
   */
  commit(venue: Venue): Commitment {
    const root = stateRoot(this.snapshot());
    const commitment = signCommitment(this.operatorSecret, venue.nextIndexFor(this.operator), root);
    venue.publish(commitment);
    return commitment;
  }

  /** The served state, as it would be published for a verifier (invariant 23). */
  snapshot(): BackingSnapshot[] {
    return this.ledger.registered().map((backing) => ({
      name: backing.name,
      issued: this.ledger.issued(backing),
      burned: this.ledger.burned(backing),
      balances: [...this.ledger.balancesOf(backing)].map(
        ([hex, units]) => [hexToBytes(hex), units] as const,
      ),
      opLog: this.ledger.opLog(backing),
    }));
  }

  outstanding(backing: Backing): bigint {
    return this.ledger.outstanding(backing);
  }

  balance(backing: Backing, holder: Uint8Array): bigint {
    return this.ledger.balance(backing, holder);
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
  private submit(backing: Backing, opMessage: Uint8Array, apply: () => OpLogEntryLike): Receipt {
    if (!this.ledger.has(backing)) {
      throw new SequencerError("backing not served by this sequencer");
    }
    const opHash = sha256(opMessage);
    const key = bytesToHex(opHash);
    const existing = this.receipts.get(key);
    if (existing !== undefined) return existing;

    const entry = apply();
    const receipt = signReceipt(this.operatorSecret, backing.name, opHash, BigInt(entry.position));
    this.receipts.set(key, receipt);
    return receipt;
  }
}

/** Just the field submit needs from the ledger's returned log entry. */
interface OpLogEntryLike {
  readonly position: number;
}
