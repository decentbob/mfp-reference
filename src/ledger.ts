// The transparent claim layer (§C1): a per-backing public ledger of
// key-controlled balances, transfer by holder signature.
//
// The law, enforced structurally:
//   - nothing you owe grows without your signature: only `issue`, verified
//     against the registered backing's obligor key, raises the outstanding
//     count;
//   - nothing you hold leaves without your signature: `transfer` and `burn`
//     verify against the holding key itself. No other mutation path exists
//     (invariant 8) — there is deliberately no method that takes an
//     operator's or backer's authority over someone else's balance, and every
//     accessor returns a copy so a caller cannot reach in and mutate state.
//
// Conservation (invariant 10): outstanding = issued − burned, per backing,
// after every operation, and the sum of balances equals outstanding.
// Redemption is not a ledger concept: presenting hands claims to the backer
// via an ordinary transfer, and only an explicit burn lowers the count.
//
// Every operation is atomic: all checks run before any mutation, so it either
// fully applies or throws LedgerError with no state change. A signer's nonce
// is per (signer, backing) and consumed only by a successful operation.
//
// NOTE (slice 3 seams; see DECISIONS.md): op-log positions are the ledger's
// own per-backing append indices, a stand-in for witnessed interval time
// (§C2); balances are primary state rather than a fold over the log, and
// there are no commitments over ledger state yet; and a replayed message is
// an error here, where invariant 26 will want the identical prior response
// returned instead. All three arrive with the sequencer.

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
import { isValidQuantity, MAX_QUANTITY_EXCLUSIVE } from "./quantity.js";

export class LedgerError extends Error {}

export type OpKind = "issue" | "transfer" | "burn";

/** One entry in a backing's operation log. `position` is the append index. */
export type OpLogEntry =
  | { readonly position: number; readonly kind: "issue"; readonly recipient: Uint8Array; readonly quantity: bigint; readonly nonce: bigint }
  | { readonly position: number; readonly kind: "transfer"; readonly from: Uint8Array; readonly to: Uint8Array; readonly quantity: bigint; readonly nonce: bigint }
  | { readonly position: number; readonly kind: "burn"; readonly holder: Uint8Array; readonly quantity: bigint; readonly nonce: bigint };

/** The issuance-only projection of the op log (§C1: issuance names the first holder). */
export interface IssuanceLogEntry {
  readonly position: number;
  readonly quantity: bigint;
  readonly recipient: Uint8Array;
  readonly nonce: bigint;
}

interface BackingState {
  readonly backing: Backing;
  issued: bigint;
  burned: bigint;
  readonly balances: Map<string, bigint>;
  readonly opLog: OpLogEntry[];
}

function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.prototype.slice.call(bytes);
}

export class TransparentLedger {
  private readonly states = new Map<string, BackingState>();
  /** Next expected nonce per (signer key, backing name); see nonceKey. */
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
      opLog: [],
    });
  }

  /** Issuance: backer-signed, raises issued and the recipient's balance. */
  issue(op: IssuanceOp, signature: Uint8Array): void {
    const { state, nameHex } = this.resolve(op.backing);
    if (!isValidPublicKey(op.recipient)) {
      throw new LedgerError("recipient key is not a valid Ed25519 point");
    }
    // Authority comes from the terms the ledger accepted at registration, not
    // from the caller-supplied object, so it never rests on hash injectivity.
    const obligor = state.backing.obligor;
    this.checkOp(obligor, nameHex, op.nonce, op.quantity);
    if (state.issued + op.quantity >= MAX_QUANTITY_EXCLUSIVE) {
      throw new LedgerError("issuance would push outstanding beyond the quantity bound");
    }
    if (this.balanceIn(state, op.recipient) + op.quantity >= MAX_QUANTITY_EXCLUSIVE) {
      throw new LedgerError("issuance would push a balance beyond the quantity bound");
    }
    if (!verifySignatureStrict(signature, encodeIssuance(op), obligor)) {
      throw new LedgerError("issuance signature invalid: only the obligor issues");
    }

    state.issued += op.quantity;
    this.credit(state, op.recipient, op.quantity);
    state.opLog.push({
      position: state.opLog.length,
      kind: "issue",
      recipient: copyBytes(op.recipient),
      quantity: op.quantity,
      nonce: op.nonce,
    });
    this.consumeNonce(obligor, nameHex);
  }

  /** Transfer: holder-signed, moves units, touches no total. */
  transfer(op: TransferOp, signature: Uint8Array): void {
    const { state, nameHex } = this.resolve(op.backing);
    if (!isValidPublicKey(op.from)) {
      throw new LedgerError("from key is not a valid Ed25519 point");
    }
    if (!isValidPublicKey(op.to)) {
      throw new LedgerError("to key is not a valid Ed25519 point");
    }
    this.checkOp(op.from, nameHex, op.nonce, op.quantity);
    this.checkBalance(state, op.from, op.quantity);
    if (this.balanceIn(state, op.to) + op.quantity >= MAX_QUANTITY_EXCLUSIVE) {
      throw new LedgerError("transfer would push a balance beyond the quantity bound");
    }
    if (!verifySignatureStrict(signature, encodeTransfer(op), op.from)) {
      throw new LedgerError("transfer signature invalid: only the holder moves a holding");
    }

    this.debit(state, op.from, op.quantity);
    this.credit(state, op.to, op.quantity);
    state.opLog.push({
      position: state.opLog.length,
      kind: "transfer",
      from: copyBytes(op.from),
      to: copyBytes(op.to),
      quantity: op.quantity,
      nonce: op.nonce,
    });
    this.consumeNonce(op.from, nameHex);
  }

  /** Burn: holder-signed, the only operation that lowers outstanding. */
  burn(op: BurnOp, signature: Uint8Array): void {
    const { state, nameHex } = this.resolve(op.backing);
    if (!isValidPublicKey(op.holder)) {
      throw new LedgerError("holder key is not a valid Ed25519 point");
    }
    this.checkOp(op.holder, nameHex, op.nonce, op.quantity);
    this.checkBalance(state, op.holder, op.quantity);
    if (!verifySignatureStrict(signature, encodeBurn(op), op.holder)) {
      throw new LedgerError("burn signature invalid: only the holder burns a holding");
    }

    this.debit(state, op.holder, op.quantity);
    state.burned += op.quantity;
    state.opLog.push({
      position: state.opLog.length,
      kind: "burn",
      holder: copyBytes(op.holder),
      quantity: op.quantity,
      nonce: op.nonce,
    });
    this.consumeNonce(op.holder, nameHex);
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
    return this.balanceIn(this.stateOf(backing), holder);
  }

  /** A snapshot copy of current holders and their balances (spent-to-zero holders are absent). */
  balancesOf(backing: Backing): Map<string, bigint> {
    return new Map(this.stateOf(backing).balances);
  }

  /** A snapshot copy of the full operation log (issue, transfer, burn). */
  opLog(backing: Backing): OpLogEntry[] {
    return this.stateOf(backing).opLog.map(copyOpEntry);
  }

  /** A snapshot copy of the issuance-only projection of the op log. */
  issuanceLog(backing: Backing): IssuanceLogEntry[] {
    const log: IssuanceLogEntry[] = [];
    for (const entry of this.stateOf(backing).opLog) {
      if (entry.kind === "issue") {
        log.push({
          position: entry.position,
          quantity: entry.quantity,
          recipient: copyBytes(entry.recipient),
          nonce: entry.nonce,
        });
      }
    }
    return log;
  }

  /** The nonce the ledger expects in this signer's next operation on this backing. */
  nextNonce(signer: Uint8Array, backing: Backing): bigint {
    return this.nonces.get(this.nonceKey(signer, bytesToHex(backingName(backing)))) ?? 0n;
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

  /** Look up a backing's state and its name-hex in one hash. */
  private resolve(backing: Backing): { state: BackingState; nameHex: string } {
    const nameHex = bytesToHex(backingName(backing));
    const state = this.states.get(nameHex);
    if (!state) throw new LedgerError("backing not registered");
    return { state, nameHex };
  }

  private stateOf(backing: Backing): BackingState {
    return this.resolve(backing).state;
  }

  private nonceKey(signer: Uint8Array, nameHex: string): string {
    return bytesToHex(signer) + ":" + nameHex;
  }

  private checkOp(signer: Uint8Array, nameHex: string, nonce: bigint, quantity: bigint): void {
    if (!isValidQuantity(quantity)) throw new LedgerError("quantity out of range");
    // The equality check subsumes any range check: nextNonce starts at 0 and
    // rises by 1, so any out-of-range or negative nonce simply is not a match.
    if (nonce !== (this.nonces.get(this.nonceKey(signer, nameHex)) ?? 0n)) {
      throw new LedgerError("nonce mismatch: stale or replayed message");
    }
  }

  private checkBalance(state: BackingState, holder: Uint8Array, quantity: bigint): void {
    if (this.balanceIn(state, holder) < quantity) {
      throw new LedgerError("insufficient balance");
    }
  }

  private balanceIn(state: BackingState, holder: Uint8Array): bigint {
    return state.balances.get(bytesToHex(holder)) ?? 0n;
  }

  private credit(state: BackingState, holder: Uint8Array, quantity: bigint): void {
    const hex = bytesToHex(holder);
    state.balances.set(hex, (state.balances.get(hex) ?? 0n) + quantity);
  }

  private debit(state: BackingState, holder: Uint8Array, quantity: bigint): void {
    const hex = bytesToHex(holder);
    const held = state.balances.get(hex) ?? 0n;
    const remaining = held - quantity; // checkBalance ran first, so >= 0n
    // Drop the entry at zero so balancesOf enumerates current holders only.
    if (remaining === 0n) state.balances.delete(hex);
    else state.balances.set(hex, remaining);
  }

  private consumeNonce(signer: Uint8Array, nameHex: string): void {
    const key = this.nonceKey(signer, nameHex);
    this.nonces.set(key, (this.nonces.get(key) ?? 0n) + 1n);
  }
}

function copyOpEntry(entry: OpLogEntry): OpLogEntry {
  switch (entry.kind) {
    case "issue":
      return { ...entry, recipient: copyBytes(entry.recipient) };
    case "transfer":
      return { ...entry, from: copyBytes(entry.from), to: copyBytes(entry.to) };
    case "burn":
      return { ...entry, holder: copyBytes(entry.holder) };
  }
}
