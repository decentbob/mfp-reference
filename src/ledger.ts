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
import { compareBytes, copyBytes, isValidQuantity, MAX_QUANTITY_EXCLUSIVE } from "./bytes.js";
import { isValidPublicKey, verifySignatureStrict } from "./keys.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
  encodeWithdrawal,
  type AcceptanceOp,
  type DemandOp,
  type ReleaseOp,
  type WithdrawalOp,
} from "./presentation.js";
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
  /** The standing demand record (invariant 23), by demand hash. */
  readonly demands: readonly DemandRecord[];
}

/**
 * A standing demand: claims committed against payment until settlement or
 * withdrawal (§C3). Invariant 23 makes the standing demand record part of what
 * a commitment commits to, so it travels in the snapshot beside the totals.
 */
export interface DemandRecord {
  /** The demand's identity: the hash of its canonical encoding. */
  readonly hash: Uint8Array;
  readonly holder: Uint8Array;
  readonly quantity: bigint;
  /** Witnessed index the payout is evaluated at (invariant 24). */
  readonly instant: bigint;
  /** Witnessed index past which non-payment is a public fact. */
  readonly deadline: bigint;
  /** The holder's nonce, so a verifier can recompute the demand's hash. */
  readonly nonce: bigint;
  /** The backer's answer, once given. Absent means unanswered. */
  readonly acceptedDeadline: bigint | undefined;
}

/**
 * Dishonour is not a separate mechanism (§C3): it is the branch where the
 * acceptance never arrives. Publicly checkable against the committed record
 * and a witnessed index, with nobody reporting anything.
 */
export function isDishonoured(record: DemandRecord, atWitnessedIndex: bigint): boolean {
  return record.acceptedDeadline === undefined && atWitnessedIndex > record.deadline;
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
  /** Open demands only — settlement and withdrawal remove them. */
  readonly demands: Map<string, DemandRecord>;
}

function copyDemand(record: DemandRecord): DemandRecord {
  return { ...record, hash: copyBytes(record.hash), holder: copyBytes(record.holder) };
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
      demands: new Map(),
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
      demands: [...state.demands.values()].map(copyDemand),
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

  /**
   * Present claims for payment (C3). The demand commits the quantity: it can
   * no longer be transferred or burned, but it is not surrendered - settlement
   * needs the backer's acceptance and the holder's own release.
   */
  demand(op: DemandOp, signature: Uint8Array): DemandRecord {
    const state = this.stateOf(op.backing);
    if (!isValidPublicKey(op.holder)) {
      throw new LedgerError("holder key is not a valid Ed25519 point");
    }
    this.checkOp(op.holder, op.backing.nameHex, op.nonce, op.quantity);
    // Only unlocked units may be committed, or one holding could answer two
    // demands.
    this.checkBalance(state, op.holder, op.quantity);
    if (!verifySignatureStrict(signature, encodeDemand(op), op.holder)) {
      throw new LedgerError("demand signature invalid: only the holder presents a holding");
    }
    // No duplicate check: the demand hash binds the holder's nonce, which
    // checkOp has already pinned to a value that is consumed on success, so
    // two standing demands cannot share a hash.
    const hash = demandHash(op);
    const record: DemandRecord = {
      hash,
      holder: copyBytes(op.holder),
      quantity: op.quantity,
      instant: op.instant,
      deadline: op.deadline,
      nonce: op.nonce,
      acceptedDeadline: undefined,
    };
    state.demands.set(bytesToHex(hash), record);
    this.consumeNonce(op.holder, op.backing.nameHex);
    return copyDemand(record);
  }

  /**
   * Answer a demand (C3). Backer-signed, and it must agree the demand's own
   * evaluation instant - two signatures over one value (invariant 24). It
   * carries its own deadline, or the backer would hold a free option: accept,
   * keep the claims committed, and wait for the payout to move.
   */
  accept(op: AcceptanceOp, signature: Uint8Array, atWitnessedIndex: bigint): DemandRecord {
    const state = this.stateOf(op.backing);
    const obligor = state.backing.obligor;
    this.checkOpNoQuantity(obligor, op.backing.nameHex, op.nonce);
    const record = this.standingDemand(state, op.demandHash);
    if (record.acceptedDeadline !== undefined) {
      throw new LedgerError("demand already accepted");
    }
    // A demand already past its deadline is publicly dishonoured, and the
    // holder has earned the right to walk away. Answering it now would let the
    // backer convert its own failure into a lock on the holder's claims.
    if (atWitnessedIndex > record.deadline) {
      throw new LedgerError("demand is past its deadline and cannot be answered");
    }
    if (op.instant !== record.instant) {
      throw new LedgerError("acceptance does not agree the demand's instant");
    }
    if (!verifySignatureStrict(signature, encodeAcceptance(op), obligor)) {
      throw new LedgerError("acceptance signature invalid: only the obligor answers");
    }

    const answered: DemandRecord = { ...record, acceptedDeadline: op.deadline };
    state.demands.set(bytesToHex(record.hash), answered);
    this.consumeNonce(obligor, op.backing.nameHex);
    return copyDemand(answered);
  }

  /**
   * Settle an accepted demand (invariant 27). Takes two signatures: the
   * backer's acceptance, already recorded, and the holder's release here. A
   * backer must never void unilaterally, or non-payment would be recorded as
   * settlement. The exact quantity offered moves to the backer - presentation
   * destroys nothing (invariant 10), so this is a transfer, not a burn.
   */
  release(op: ReleaseOp, signature: Uint8Array, atWitnessedIndex: bigint): OpLogEntry {
    const state = this.stateOf(op.backing);
    const record = this.standingDemand(state, op.demandHash);
    this.checkOpNoQuantity(record.holder, op.backing.nameHex, op.nonce);
    if (record.acceptedDeadline === undefined) {
      throw new LedgerError("demand has not been accepted");
    }
    // Past the acceptance's own deadline the answer is stale: the holder's
    // exit is withdrawal, not settlement on terms that have moved.
    if (atWitnessedIndex > record.acceptedDeadline) {
      throw new LedgerError("acceptance has expired");
    }
    if (!verifySignatureStrict(signature, encodeRelease(op), record.holder)) {
      throw new LedgerError("release signature invalid: only the holder releases");
    }
    const backer = state.backing.obligor;
    if (this.balanceIn(state, backer) + record.quantity >= MAX_QUANTITY_EXCLUSIVE) {
      throw new LedgerError("settlement would push a balance beyond the quantity bound");
    }

    // Drop the demand first so the settling transfer is not blocked by its own
    // lock, then move exactly the quantity offered.
    state.demands.delete(bytesToHex(record.hash));
    this.debit(state, record.holder, record.quantity);
    this.credit(state, backer, record.quantity);
    return this.append(state, record.holder, op.backing.nameHex, {
      position: state.opLog.length,
      kind: "transfer",
      from: copyBytes(record.holder),
      to: copyBytes(backer),
      quantity: record.quantity,
      nonce: op.nonce,
    });
  }

  /**
   * End an unanswered demand (C3). Unilateral and holder-signed: the
   * protection against a backer that stalls, which it cannot wait out. An
   * accepted demand cannot be withdrawn - the holder has an answer to release
   * against or to let expire.
   */
  withdraw(op: WithdrawalOp, signature: Uint8Array, atWitnessedIndex: bigint): void {
    const state = this.stateOf(op.backing);
    const record = this.standingDemand(state, op.demandHash);
    this.checkOpNoQuantity(record.holder, op.backing.nameHex, op.nonce);
    // A live acceptance holds the claims: the holder has an answer to release
    // against. Once it expires the claims are the holder's again, or a single
    // free signature from the backer would sterilise them forever.
    if (record.acceptedDeadline !== undefined && atWitnessedIndex <= record.acceptedDeadline) {
      throw new LedgerError("a live acceptance stands: release it or wait for it to expire");
    }
    if (!verifySignatureStrict(signature, encodeWithdrawal(op), record.holder)) {
      throw new LedgerError("withdrawal signature invalid: only the holder withdraws");
    }
    state.demands.delete(bytesToHex(record.hash));
    this.consumeNonce(record.holder, op.backing.nameHex);
  }

  /** The standing demand record (invariant 23), as copies. */
  openDemands(backing: Backing): DemandRecord[] {
    return [...this.stateOf(backing).demands.values()].map(copyDemand);
  }

  /** Units this holder can still spend: held minus committed by open demands. */
  availableBalance(backing: Backing, holder: Uint8Array): bigint {
    const state = this.stateOf(backing);
    return this.balanceIn(state, holder) - this.lockedIn(state, holder);
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
    this.consumeNonce(signer, nameHex);
    return copyOpEntry(entry);
  }

  private consumeNonce(signer: Uint8Array, nameHex: string): void {
    const key = this.nonceKey(signer, nameHex);
    this.nonces.set(key, (this.nonces.get(key) ?? 0n) + 1n);
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
    this.checkOpNoQuantity(signer, nameHex, nonce);
  }

  /**
   * Units an open demand has committed against payment. Derived from the
   * standing record rather than tracked in parallel, so there is one source of
   * truth and no counter that can desync from the demands themselves.
   */
  private lockedIn(state: BackingState, holder: Uint8Array): bigint {
    let locked = 0n;
    for (const record of state.demands.values()) {
      if (compareBytes(record.holder, holder) === 0) locked += record.quantity;
    }
    return locked;
  }

  /** The nonce half of checkOp, for operations that carry no quantity. */
  private checkOpNoQuantity(signer: Uint8Array, nameHex: string, nonce: bigint): void {
    const expected = this.nonces.get(this.nonceKey(signer, nameHex)) ?? 0n;
    if (nonce !== expected) {
      throw new NonceError(
        nonce < expected
          ? "nonce already spent on a different operation"
          : "nonce is ahead of the signer's next",
      );
    }
  }

  private standingDemand(state: BackingState, hash: Uint8Array): DemandRecord {
    const record = state.demands.get(bytesToHex(hash));
    if (!record) throw new LedgerError("no such standing demand");
    return record;
  }

  /**
   * Spendable units: held minus committed. §C3's commitment is enforced here —
   * claims under an open demand cannot leave by any ordinary path, so the
   * holder cannot present the same units and also spend them.
   */
  private checkBalance(state: BackingState, holder: Uint8Array, quantity: bigint): void {
    if (this.balanceIn(state, holder) - this.lockedIn(state, holder) < quantity) {
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
    const remaining = held - quantity;
    // Every caller checks first, but a mint-capable line must not rest on a
    // cross-method argument: refuse rather than persist a negative balance.
    if (remaining < 0n) throw new LedgerError("debit exceeds the holding");
    // Drop the entry at zero so balancesOf enumerates current holders only.
    if (remaining === 0n) state.balances.delete(hex);
    else state.balances.set(hex, remaining);
  }
}
