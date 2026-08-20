// Operator co-signed receipts (§C2).
//
// A sequencer co-signs each accepted operation: the operator signs
// (backing name, operation hash, position). The position is the operation's
// index in that backing's operation log — the same log the commitment commits
// to (invariant 23) — so a receipt is verifiable against a committed state:
// reconstruct the operation at that position from the committed log entry,
// hash it, and check it equals the receipt's op hash. On a replay the
// sequencer returns the identical prior receipt (invariant 26).
//
// This holds for all seven operation kinds, presentation included: a demand, an
// acceptance, a release and a withdrawal each take a position and get a receipt,
// so an operator cannot deny having accepted one even though none of them moves
// value.

import { ed25519 } from "@noble/curves/ed25519.js";
import type { Backing } from "./backing.js";
import { ByteWriter, compareBytes, copyBytes } from "./bytes.js";
import { committedLogFor, type ServedState } from "./commitment.js";
import { isAnOperator } from "./replacement.js";
import type { Venue } from "./venue.js";
import { RECEIPT_CONTEXT } from "./contexts.js";
import { verifySignatureStrict } from "./keys.js";
import type { BackingSnapshot } from "./ledger.js";
import { opHashOfEntry, type OpLogEntry, type PublishedOp } from "./oplog.js";

export interface Receipt {
  readonly backingName: Uint8Array;
  readonly opHash: Uint8Array;
  /** The operation's position in the backing's operation log. */
  readonly position: bigint;
  readonly operator: Uint8Array;
  readonly signature: Uint8Array;
}

/**
 * A snapshot of a receipt's bytes. `readonly` is erased at runtime, so anything
 * that stores or serves a receipt copies it (CLAUDE.md: copy on the way in, copy
 * on the way out). Without it whoever holds a receipt can mutate the one the
 * sequencer kept, and invariant 26's "identical prior response" stops being
 * something the operator controls.
 */
export function copyReceipt(receipt: Receipt): Receipt {
  return {
    backingName: copyBytes(receipt.backingName),
    opHash: copyBytes(receipt.opHash),
    position: receipt.position,
    operator: copyBytes(receipt.operator),
    signature: copyBytes(receipt.signature),
  };
}

/** Both 32-byte fields are asserted, so one signature covers one receipt. */
function receiptMessage(backingName: Uint8Array, opHash: Uint8Array, position: bigint): Uint8Array {
  const w = new ByteWriter();
  w.context(RECEIPT_CONTEXT);
  w.key32(backingName, "backing name");
  w.key32(opHash, "op hash");
  w.u64(position);
  return w.finish();
}

export function signReceipt(
  operatorSecret: Uint8Array,
  backingName: Uint8Array,
  opHash: Uint8Array,
  position: bigint,
): Receipt {
  const operator = ed25519.getPublicKey(operatorSecret);
  const signature = ed25519.sign(receiptMessage(backingName, opHash, position), operatorSecret);
  // The receipt owns its bytes: it is handed a backing name and an op hash the
  // caller still holds, and what the operator co-signed must not be rewritable.
  return {
    backingName: copyBytes(backingName),
    opHash: copyBytes(opHash),
    position,
    operator,
    signature,
  };
}

/** Valid iff the operator signed exactly (backing name, op hash, position). */
export function verifyReceipt(receipt: Receipt): boolean {
  try {
    const message = receiptMessage(receipt.backingName, receipt.opHash, receipt.position);
    return verifySignatureStrict(receipt.signature, message, receipt.operator);
  } catch {
    return false;
  }
}

/**
 * Whether this receipt is the operator's co-signature over exactly this
 * operation. The pairing is what a holder exhibits when there is no committed
 * state to check against — during a §C2b gap the operator's log is unpublished,
 * and its receipt is the only evidence outside it that the operation was
 * accepted at all.
 *
 * It proves acceptance, and **not a holding**: a payee who was paid and then
 * paid onward still holds the receipt for what they received. Reading it as a
 * holding is how a redemption pays a party that has already spent.
 *
 * A verifier: the receipt and the operation both come from whoever exhibits
 * them, so anything malformed is a pairing that does not hold.
 */
export function receiptCovers(
  backingName: Uint8Array,
  op: PublishedOp,
  receipt: Receipt,
): boolean {
  try {
    if (!verifyReceipt(receipt)) return false;
    // The backing is the caller's to name, not the receipt's to assert. An
    // operation carries no backing name — the name comes from whoever encodes
    // it — so taking it from the receipt would let a receipt issued on ANOTHER
    // backing cover this operation perfectly, and one operator commonly serves
    // many (§C2). It is a parameter for the same reason it is one on
    // opMessageOfEntry: the binding is structural rather than remembered.
    if (compareBytes(receipt.backingName, backingName) !== 0) return false;
    return compareBytes(opHashOfEntry(backingName, op), receipt.opHash) === 0;
  } catch {
    return false;
  }
}

/**
 * Whether a served state contains the operation a receipt attests to: same
 * backing, a log entry at the receipt's position, and that entry reconstructs
 * to the receipt's op hash. Combined with stateProvesCommitment this proves
 * the operation is in committed state. Never throws — the snapshot may come
 * from an untrusted operator, so any malformed field is a failed proof. Does
 * not check the operator signature; call verifyReceipt for that.
 */
export function receiptProvenBy(receipt: Receipt, snapshot: BackingSnapshot): boolean {
  try {
    if (compareBytes(snapshot.name, receipt.backingName) !== 0) return false;
    const entry = entryAt(snapshot.opLog, receipt.position);
    if (entry === undefined) return false;
    return compareBytes(opHashOfEntry(snapshot.name, entry), receipt.opHash) === 0;
  } catch {
    return false;
  }
}

/**
 * The entry a receipt's position names, or undefined if the log does not reach
 * it. The position is pinned to the index by the commitment encoder, and checked
 * again here because a served log comes from whoever serves it.
 */
function entryAt(
  opLog: readonly OpLogEntry[],
  position: bigint,
): OpLogEntry | undefined {
  if (position < 0n || position > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  const entry = opLog[Number(position)];
  if (entry === undefined) return undefined;
  if (!Number.isSafeInteger(entry.position) || BigInt(entry.position) !== position) {
    return undefined;
  }
  return entry;
}

/**
 * Whether this receipt is a valid co-signature by a key that has **served this
 * backing**, over this backing.
 *
 * Both halves matter and neither is enough. Without the backing name, a receipt
 * the operator issued perfectly correctly on another backing covers an operation
 * here, since an operation carries no name of its own. Without the operator key,
 * a stranger signs both halves of somebody's real equivocation and it reads as a
 * fault by the operator of this backing — which is what a caller takes these
 * predicates to mean, and under §C2's backer-run default names the party that
 * owes the money.
 *
 * **Any key in the chain, not only the key E names.** A receipt records an
 * operation and a position and never when it was signed, so "was this key in
 * force then" is not a question it can answer — but a retired operator's
 * co-signature over an operation its own log really held is still evidence of
 * what it accepted while it served, and a successor's receipts have to count at
 * all. What stops a retired key mattering is that the state of record is the
 * operator in force now, and a receipt is read against that log.
 */
export function isOperatorReceipt(backing: Backing, venue: Venue, receipt: Receipt): boolean {
  try {
    return (
      compareBytes(receipt.backingName, backing.name) === 0 &&
      isAnOperator(backing, venue, receipt.operator) &&
      verifyReceipt(receipt)
    );
  } catch {
    return false;
  }
}

/**
 * What a committed state says about a receipt — the question behind CLAUDE.md's
 * rule that **a payment is final when witnessed, not when co-signed** (§C2:
 * "Finality means witnessed rather than co-signed").
 *
 *   - `witnessed`    the committed log holds this operation at this position.
 *   - `pending`      the log is shorter than the position. Not yet.
 *   - `contradicted` the log is long enough and holds something else, so one of
 *                    the operator's two signatures is a lie about its own log.
 *   - `unrelated`    not this backing's operator's receipt, or not its state.
 *
 * **`witnessed` does not need the latest commitment.** Positions are pinned and
 * the log is append-only, so once witnessed, always witnessed — unlike
 * provesHolding, where "last" is load-bearing because a holding can be spent
 * afterwards and an accepted operation cannot un-happen.
 *
 * **`unrelated` exists so that a proof never accuses the wrong party**, which is
 * the finding slice 9 made twice. Reading a stranger's receipt as contradicted
 * would name this backing's operator — the party that owes the money under the
 * backer-run default — for something it did not do.
 *
 * The log is not replayed. Whether the operator committed a lawful history is a
 * different question (stateIsAuthentic); what is asked here is only what the
 * operator put its own signature to, twice.
 *
 * A verifier: everything here comes from whoever exhibits it.
 */
export type ReceiptStatus = "witnessed" | "pending" | "contradicted" | "unrelated";

export function receiptStatus(
  backing: Backing,
  venue: Venue,
  receipt: Receipt,
  served: ServedState,
): ReceiptStatus {
  try {
    if (!isOperatorReceipt(backing, venue, receipt)) return "unrelated";
    const committed = committedLogFor(backing, venue, served);
    if (committed === undefined) return "unrelated";
    if (receipt.position < 0n || receipt.position >= BigInt(committed.opLog.length)) {
      return "pending";
    }
    // Not reachable through committedLogFor, which recomputes the root and so
    // rejects a log whose positions are not pinned to their indices. Answered
    // "unrelated" rather than "contradicted" anyway: a state this malformed is
    // not this operator's committed state, and a proof must not accuse on it.
    const entry = entryAt(committed.opLog, receipt.position);
    if (entry === undefined) return "unrelated";
    return compareBytes(opHashOfEntry(backing.name, entry), receipt.opHash) === 0
      ? "witnessed"
      : "contradicted";
  } catch {
    return "unrelated";
  }
}
