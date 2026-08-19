// The transparent claim layer (§C1): a per-backing public ledger of
// key-controlled balances, transfer by holder signature.
//
// The law, enforced structurally:
//   - nothing you owe grows without your signature: only `issue`, verified
//     against the registered backing's obligor key, raises the outstanding
//     count;
//   - nothing you hold leaves without your signature: `transfer` and `burn`
//     verify against the holding key itself. No other mutation path exists
//     (invariant 8) — there is deliberately no method that takes an operator's
//     or backer's authority over someone else's balance, and every accessor
//     returns a copy so a caller cannot reach in and mutate state.
//
// Conservation (invariant 10): outstanding = issued − burned, per backing,
// after every operation, and the sum of balances equals outstanding.
// Redemption is not a ledger concept: presenting hands claims to the backer
// via an ordinary transfer, and only an explicit burn lowers the count.
//
// Every operation is atomic: all checks run before any mutation, so it either
// fully applies or throws with no state change. A signer's nonce is per
// (signer, backing) and consumed only by a successful operation.
//
// NOTE (later slices, see DECISIONS.md): op-log positions are the ledger's own
// per-backing append indices, a stand-in for witnessed interval time (§C2);
// balances are primary state rather than a fold over the log; and there are no
// commitments over ledger state here — the sequencer adds those.

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { makeBacking, verifyBackingSignature, type Backing } from "./backing.js";
import { copyBytes, isValidQuantity, MAX_QUANTITY_EXCLUSIVE } from "./bytes.js";
import { isValidPublicKey, verifySignatureStrict } from "./keys.js";
import {
  encodeBurn,
  encodeIssuance,
  encodeTransfer,
  type BurnOp,
  type IssuanceOp,
  type TransferOp,
} from "./messages.js";

/** The law refuses: bad signature, insufficient funds, unknown backing. */
export class LedgerError extends Error {}

/**
 * This nonce is not the signer's next. Distinguished so a caller can tell a
 * second spend at a used nonce from a funds or signature failure, without
 * re-deriving the expected nonce and re-checking it itself.
 */
export class NonceError extends LedgerError {}

/** One entry in a backing's operation log. `position` is the append index. */
export type OpLogEntry =
  | {
      readonly position: number;
      readonly kind: "issue";
      readonly recipient: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
    }
  | {
      readonly position: number;
      readonly kind: "transfer";
      readonly from: Uint8Array;
      readonly to: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
    }
  | {
      readonly position: number;
      readonly kind: "burn";
      readonly holder: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
    };

/**
 * One backing's state, serialized for a verifier. This is what a commitment
 * commits to (invariant 23) and what a verifier is handed to check against a
 * root. Every field is a copy.
 */
export interface BackingSnapshot {
  readonly name: Uint8Array;
  readonly issued: bigint;
  readonly burned: bigint;
  /** [holder key, units], canonicalized by key bytes when encoded. */
  readonly balances: readonly (readonly [Uint8Array, bigint])[];
  readonly opLog: readonly OpLogEntry[];
}

/** The issuance-only projection of the op log (§C1 names the first holder). */
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
    if (this.states.has(backing.nameHex)) return;
    // Store the ledger's OWN copy. Object.freeze does not freeze the bytes
    // inside a Uint8Array, and `issue` reads authority from the registered
    // obligor — so keeping the caller's object would leave a live write path
    // to the key that authorises issuance. makeBacking re-copies every field
    // and yields the same name (invariant 1).
    this.states.set(backing.nameHex, {
      backing: makeBacking(backing),
      issued: 0n,
      burned: 0n,
      balances: new Map(),
      opLog: [],
    });
  }

  /**
   * Every backing's state, serialized for a verifier (invariant 23). The
   * ledger owns its state, so it owns the serialization: no Backing object
   * leaves, so no caller can reach the obligor key that authorises issuance.
   */
  snapshotAll(): BackingSnapshot[] {
    return [...this.states.values()].map((state) => ({
      name: copyBytes(state.backing.name),
      issued: state.issued,
      burned: state.burned,
      balances: [...state.balances].map(([hex, units]) => [hexToBytes(hex), units] as const),
      opLog: state.opLog.map(copyOpEntry),
    }));
  }

  has(backing: Backing): boolean {
    return this.states.has(backing.nameHex);
  }

  /** Issuance: backer-signed, raises issued and the recipient's balance. */
  issue(op: IssuanceOp, signature: Uint8Array): OpLogEntry {
    const state = this.stateOf(op.backing);
    if (!isValidPublicKey(op.recipient)) {
      throw new LedgerError("recipient key is not a valid Ed25519 point");
    }
    // Authority comes from the terms the ledger accepted at registration, not
    // from the caller-supplied object, so it never rests on hash injectivity.
    const obligor = state.backing.obligor;
    this.checkOp(obligor, op.backing.nameHex, op.nonce, op.quantity);
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
    return this.append(state, obligor, op.backing.nameHex, {
      position: state.opLog.length,
      kind: "issue",
      recipient: copyBytes(op.recipient),
      quantity: op.quantity,
      nonce: op.nonce,
    });
  }

  /** Transfer: holder-signed, moves units, touches no total. */
  transfer(op: TransferOp, signature: Uint8Array): OpLogEntry {
    const state = this.stateOf(op.backing);
    if (!isValidPublicKey(op.from)) {
      throw new LedgerError("from key is not a valid Ed25519 point");
    }
    if (!isValidPublicKey(op.to)) {
      throw new LedgerError("to key is not a valid Ed25519 point");
    }
    this.checkOp(op.from, op.backing.nameHex, op.nonce, op.quantity);
    this.checkBalance(state, op.from, op.quantity);
    if (this.balanceIn(state, op.to) + op.quantity >= MAX_QUANTITY_EXCLUSIVE) {
      throw new LedgerError("transfer would push a balance beyond the quantity bound");
    }
    if (!verifySignatureStrict(signature, encodeTransfer(op), op.from)) {
      throw new LedgerError("transfer signature invalid: only the holder moves a holding");
    }

    this.debit(state, op.from, op.quantity);
    this.credit(state, op.to, op.quantity);
    return this.append(state, op.from, op.backing.nameHex, {
      position: state.opLog.length,
      kind: "transfer",
      from: copyBytes(op.from),
      to: copyBytes(op.to),
      quantity: op.quantity,
      nonce: op.nonce,
    });
  }

  /** Burn: holder-signed, the only operation that lowers outstanding. */
  burn(op: BurnOp, signature: Uint8Array): OpLogEntry {
    const state = this.stateOf(op.backing);
    if (!isValidPublicKey(op.holder)) {
      throw new LedgerError("holder key is not a valid Ed25519 point");
    }
    this.checkOp(op.holder, op.backing.nameHex, op.nonce, op.quantity);
    this.checkBalance(state, op.holder, op.quantity);
    if (!verifySignatureStrict(signature, encodeBurn(op), op.holder)) {
      throw new LedgerError("burn signature invalid: only the holder burns a holding");
    }

    this.debit(state, op.holder, op.quantity);
    state.burned += op.quantity;
    return this.append(state, op.holder, op.backing.nameHex, {
      position: state.opLog.length,
      kind: "burn",
      holder: copyBytes(op.holder),
      quantity: op.quantity,
      nonce: op.nonce,
    });
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

  /** A copy of current holders and balances (spent-to-zero holders are absent). */
  balancesOf(backing: Backing): Map<string, bigint> {
    return new Map(this.stateOf(backing).balances);
  }

  /** A copy of the full operation log (issue, transfer, burn). */
  opLog(backing: Backing): OpLogEntry[] {
    return this.stateOf(backing).opLog.map(copyOpEntry);
  }

  /** A copy of the issuance-only projection of the op log. */
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

  /** The nonce this signer's next operation on this backing must carry. */
  nextNonce(signer: Uint8Array, backing: Backing): bigint {
    return this.nonces.get(this.nonceKey(signer, backing.nameHex)) ?? 0n;
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

  /** Append the log entry and consume the nonce — the last step of every op. */
  private append(
    state: BackingState,
    signer: Uint8Array,
    nameHex: string,
    entry: OpLogEntry,
  ): OpLogEntry {
    state.opLog.push(entry);
    const key = this.nonceKey(signer, nameHex);
    this.nonces.set(key, (this.nonces.get(key) ?? 0n) + 1n);
    return copyOpEntry(entry);
  }

  private stateOf(backing: Backing): BackingState {
    const state = this.states.get(backing.nameHex);
    if (!state) throw new LedgerError("backing not registered");
    return state;
  }

  private nonceKey(signer: Uint8Array, nameHex: string): string {
    return bytesToHex(signer) + ":" + nameHex;
  }

  private checkOp(signer: Uint8Array, nameHex: string, nonce: bigint, quantity: bigint): void {
    if (!isValidQuantity(quantity)) throw new LedgerError("quantity out of range");
    // The equality check subsumes any range check: nextNonce starts at 0 and
    // rises by 1, so any out-of-range or negative nonce simply is not a match.
    const expected = this.nonces.get(this.nonceKey(signer, nameHex)) ?? 0n;
    if (nonce !== expected) {
      throw new NonceError(
        nonce < expected
          ? "nonce already spent on a different operation"
          : "nonce is ahead of the signer's next",
      );
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
}
