// The transparent claim layer (§C1): a per-backing public ledger of
// key-controlled balances, transfer by holder signature.
//
// The law, enforced structurally:
//   - nothing you owe grows without your signature: only `issue`, verified
//     against the backing's obligor key, raises the outstanding count;
//   - nothing you hold leaves without your signature: `transfer` and `burn`
//     verify against the holding key itself. No other mutation path exists
//     (invariant 8) — there is deliberately no method that takes an
//     operator's or backer's authority over someone else's balance.
//
// Conservation (invariant 10): outstanding = issued − burned, per backing,
// after every operation, and the sum of balances equals outstanding.
// Redemption is not a ledger concept: presenting hands claims to the backer
// via an ordinary transfer, and only an explicit burn lowers the count.
//
// Every operation is atomic: it either fully applies or throws LedgerError
// with no state change. A signer's nonce is consumed only by a successful
// operation. NOTE (slice 3 seam): log positions are the ledger's own append
// indices, a stand-in for witnessed interval time (§C2); and a replayed
// message is an error here, where invariant 26 will want the identical prior
// response returned instead — that arrives with the sequencer.

import { bytesToHex } from "@noble/hashes/utils.js";
import { backingName, verifyBackingSignature, type Backing } from "./backing.js";
import { isValidPublicKey, verifySignatureStrict } from "./keys.js";
import {
  encodeBurn,
  encodeIssuance,
  encodeTransfer,
  type BurnOp,
  type IssuanceOp,
  type TransferOp,
} from "./messages.js";
import { isValidQuantity } from "./quantity.js";

export class LedgerError extends Error {}

export interface IssuanceLogEntry {
  /** Append index in this backing's log — the stand-in for witnessed time. */
  readonly position: number;
  readonly quantity: bigint;
  /** Transparent issuance names the first holder (§C1). */
  readonly recipient: Uint8Array;
  readonly nonce: bigint;
}

interface BackingState {
  readonly backing: Backing;
  issued: bigint;
  burned: bigint;
  readonly balances: Map<string, bigint>;
  readonly issuanceLog: IssuanceLogEntry[];
}

const MAX_NONCE = 0xffffffffffffffffn;

export class TransparentLedger {
  private readonly states = new Map<string, BackingState>();
  /** Next expected nonce per signer key, across all backings and op kinds. */
  private readonly nonces = new Map<string, bigint>();

  /**
   * A backing enters the ledger only with a valid signature by its obligor
   * over its own name (invariant 2). Re-registering the same backing is a
   * no-op: by invariant 1, same name means same terms.
   */
  register(backing: Backing, signature: Uint8Array): void {
    if (!verifyBackingSignature(backing, signature)) {
      throw new LedgerError("backing signature invalid");
    }
    const name = bytesToHex(backingName(backing));
    if (this.states.has(name)) return;
    this.states.set(name, {
      backing,
      issued: 0n,
      burned: 0n,
      balances: new Map(),
      issuanceLog: [],
    });
  }

  /** Issuance: backer-signed, raises issued and the recipient's balance. */
  issue(op: IssuanceOp, signature: Uint8Array): void {
    const state = this.stateOf(op.backing);
    if (!isValidPublicKey(op.recipient)) {
      throw new LedgerError("recipient key is not a valid Ed25519 point");
    }
    this.checkOp(op.backing.obligor, op.nonce, op.quantity);
    if (!verifySignatureStrict(signature, encodeIssuance(op), op.backing.obligor)) {
      throw new LedgerError("issuance signature invalid: only the obligor issues");
    }

    state.issued += op.quantity;
    this.credit(state, op.recipient, op.quantity);
    state.issuanceLog.push({
      position: state.issuanceLog.length,
      quantity: op.quantity,
      recipient: Uint8Array.prototype.slice.call(op.recipient),
      nonce: op.nonce,
    });
    this.consumeNonce(op.backing.obligor);
  }

  /** Transfer: holder-signed, moves units, touches no total. */
  transfer(op: TransferOp, signature: Uint8Array): void {
    const state = this.stateOf(op.backing);
    if (!isValidPublicKey(op.to)) {
      throw new LedgerError("to key is not a valid Ed25519 point");
    }
    this.checkOp(op.from, op.nonce, op.quantity);
    this.checkBalance(state, op.from, op.quantity);
    if (!verifySignatureStrict(signature, encodeTransfer(op), op.from)) {
      throw new LedgerError("transfer signature invalid: only the holder moves a holding");
    }

    this.debit(state, op.from, op.quantity);
    this.credit(state, op.to, op.quantity);
    this.consumeNonce(op.from);
  }

  /** Burn: holder-signed, the only operation that lowers outstanding. */
  burn(op: BurnOp, signature: Uint8Array): void {
    const state = this.stateOf(op.backing);
    this.checkOp(op.holder, op.nonce, op.quantity);
    this.checkBalance(state, op.holder, op.quantity);
    if (!verifySignatureStrict(signature, encodeBurn(op), op.holder)) {
      throw new LedgerError("burn signature invalid: only the holder burns a holding");
    }

    this.debit(state, op.holder, op.quantity);
    state.burned += op.quantity;
    this.consumeNonce(op.holder);
  }

  issued(backing: Backing): bigint {
    return this.stateOf(backing).issued;
  }

  burned(backing: Backing): bigint {
    return this.stateOf(backing).burned;
  }

  outstanding(backing: Backing): bigint {
    const state = this.stateOf(backing);
    return state.issued - state.burned;
  }

  balance(backing: Backing, holder: Uint8Array): bigint {
    return this.stateOf(backing).balances.get(bytesToHex(holder)) ?? 0n;
  }

  balancesOf(backing: Backing): ReadonlyMap<string, bigint> {
    return this.stateOf(backing).balances;
  }

  issuanceLog(backing: Backing): readonly IssuanceLogEntry[] {
    return this.stateOf(backing).issuanceLog;
  }

  /** The nonce the ledger expects in this signer's next operation. */
  nextNonce(signer: Uint8Array): bigint {
    return this.nonces.get(bytesToHex(signer)) ?? 0n;
  }

  /**
   * A holder's view of their own holdings, keyed by backing name — the shape
   * presentability (invariant 13) reads. Unknown backings hold zero.
   */
  holdingView(holder: Uint8Array): (name: Uint8Array) => bigint {
    const holderHex = bytesToHex(holder);
    return (name: Uint8Array) =>
      this.states.get(bytesToHex(name))?.balances.get(holderHex) ?? 0n;
  }

  private stateOf(backing: Backing): BackingState {
    const state = this.states.get(bytesToHex(backingName(backing)));
    if (!state) throw new LedgerError("backing not registered");
    return state;
  }

  private checkOp(signer: Uint8Array, nonce: bigint, quantity: bigint): void {
    if (!isValidQuantity(quantity)) throw new LedgerError("quantity out of range");
    if (nonce < 0n || nonce > MAX_NONCE) throw new LedgerError("nonce out of range");
    if (nonce !== this.nextNonce(signer)) {
      throw new LedgerError("nonce mismatch: stale or replayed message");
    }
  }

  private checkBalance(state: BackingState, holder: Uint8Array, quantity: bigint): void {
    const held = state.balances.get(bytesToHex(holder)) ?? 0n;
    if (held < quantity) throw new LedgerError("insufficient balance");
  }

  private credit(state: BackingState, holder: Uint8Array, quantity: bigint): void {
    const hex = bytesToHex(holder);
    state.balances.set(hex, (state.balances.get(hex) ?? 0n) + quantity);
  }

  private debit(state: BackingState, holder: Uint8Array, quantity: bigint): void {
    const hex = bytesToHex(holder);
    const held = state.balances.get(hex) ?? 0n;
    const remaining = held - quantity;
    if (remaining === 0n) state.balances.delete(hex);
    else state.balances.set(hex, remaining);
  }

  private consumeNonce(signer: Uint8Array): void {
    const hex = bytesToHex(signer);
    this.nonces.set(hex, (this.nonces.get(hex) ?? 0n) + 1n);
  }
}
