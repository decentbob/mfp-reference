// The transparent sequencer (§C2).
//
// A sequencer serves the backings whose E field names its operator key. It is
// the front door to the claim layer: clients submit signed operations, the
// sequencer drives the transparent ledger underneath, assigns each accepted
// operation a witnessed index, and returns an operator co-signed receipt. At
// a declared interval it publishes a commitment over the state it serves.
//
// It never holds funds. Its added value in the transparent setting (where the
// ledger already prevents double-spends) is threefold:
//   - witnessed time: a monotonic index replacing the ledger's log-position
//     stand-in;
//   - idempotent replay (invariant 26): the same operation resubmitted
//     returns the identical prior receipt, and a different operation at an
//     already-spent nonce is declined (the ledger's nonce rejection);
//   - commitments (invariants 22, 23): periodic signed roots over state, so a
//     third party can verify state without trusting the operator's live word.
//
// NOTE (later slices, see DECISIONS.md): recovery / snapshot redemption /
// non-membership proofs (§C2b), silence and non-service grades, revocation,
// successor sequencers, dated instruments, multi-sequencer transfers, and
// presentation/dishonour (§C3) are all out of scope here.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { backingName, type Backing } from "./backing.js";
import { type BackingSnapshot, type Commitment, signCommitment, stateRoot } from "./commitment.js";
import { compareBytes } from "./bytes.js";
import { isValidPublicKey } from "./keys.js";
import {
  encodeBurn,
  encodeIssuance,
  encodeTransfer,
  type BurnOp,
  type IssuanceOp,
  type TransferOp,
} from "./messages.js";
import { TransparentLedger } from "./ledger.js";
import { signReceipt, type Receipt } from "./receipt.js";
import { Venue } from "./venue.js";

export class SequencerError extends Error {}

export class Sequencer {
  private readonly ledger = new TransparentLedger();
  private readonly served: Backing[] = [];
  /** opHash (hex) -> the receipt returned when it was first accepted. */
  private readonly receipts = new Map<string, Receipt>();
  private opIndex = 0n;
  private commitIndex = 0n;
  private lastCommitment: Commitment | undefined;

  readonly operator: Uint8Array;

  constructor(private readonly operatorSecret: Uint8Array) {
    this.operator = ed25519.getPublicKey(operatorSecret);
  }

  /**
   * Take on a backing whose E names this operator. Rejects a backing served
   * by a different operator, and (via the ledger) one without a valid obligor
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
    if (!this.served.some((b) => compareBytes(backingName(b), backingName(backing)) === 0)) {
      this.served.push(backing);
    }
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

  /** Publish a commitment over the served state at the next venue index. */
  commit(venue: Venue): Commitment {
    const root = stateRoot(this.snapshot());
    const commitment = signCommitment(this.operatorSecret, this.commitIndex, root);
    venue.publish(commitment);
    this.commitIndex += 1n;
    this.lastCommitment = commitment;
    return commitment;
  }

  /** The served state, as it would be published for a verifier (invariant 23). */
  snapshot(): BackingSnapshot[] {
    return this.served.map((backing) => ({
      name: backingName(backing),
      issued: this.ledger.issued(backing),
      burned: this.ledger.burned(backing),
      balances: [...this.ledger.balancesOf(backing)].map(
        ([hex, units]) => [hexToBytes(hex), units] as const,
      ),
      opLog: this.ledger.opLog(backing),
    }));
  }

  latestCommitment(): Commitment | undefined {
    return this.lastCommitment;
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
   * The shared submit path: idempotency first, then the ledger, then the
   * co-signed receipt. A replay of an accepted operation returns the identical
   * prior receipt without touching the ledger (invariant 26). A ledger
   * rejection (bad signature, insufficient balance, or a different operation
   * at an already-spent nonce) propagates as a LedgerError and records
   * nothing.
   */
  private submit(backing: Backing, opMessage: Uint8Array, apply: () => void): Receipt {
    const name = backingName(backing);
    if (!this.served.some((b) => compareBytes(backingName(b), name) === 0)) {
      throw new SequencerError("backing not served by this sequencer");
    }
    const opHash = sha256(opMessage);
    const key = bytesToHex(opHash);
    const existing = this.receipts.get(key);
    if (existing !== undefined) return existing;

    apply();
    const receipt = signReceipt(this.operatorSecret, name, opHash, this.opIndex);
    this.opIndex += 1n;
    this.receipts.set(key, receipt);
    return receipt;
  }
}
