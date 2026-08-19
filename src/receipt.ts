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
import { ByteWriter, compareBytes } from "./bytes.js";
import { RECEIPT_CONTEXT } from "./contexts.js";
import { verifySignatureStrict } from "./keys.js";
import type { BackingSnapshot } from "./ledger.js";
import { opHashOfEntry } from "./oplog.js";

export interface Receipt {
  readonly backingName: Uint8Array;
  readonly opHash: Uint8Array;
  /** The operation's position in the backing's operation log. */
  readonly position: bigint;
  readonly operator: Uint8Array;
  readonly signature: Uint8Array;
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
  return { backingName, opHash, position, operator, signature };
}

/** Valid iff the operator signed exactly (backing name, op hash, position). */
export function verifyReceipt(receipt: Receipt): boolean {
  let message: Uint8Array;
  try {
    message = receiptMessage(receipt.backingName, receipt.opHash, receipt.position);
  } catch {
    return false;
  }
  return verifySignatureStrict(receipt.signature, message, receipt.operator);
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
    if (receipt.position < 0n || receipt.position > BigInt(Number.MAX_SAFE_INTEGER)) return false;
    const entry = snapshot.opLog[Number(receipt.position)];
    if (entry === undefined) return false;
    if (!Number.isSafeInteger(entry.position) || BigInt(entry.position) !== receipt.position) {
      return false;
    }
    return compareBytes(opHashOfEntry(snapshot.name, entry), receipt.opHash) === 0;
  } catch {
    return false;
  }
}
