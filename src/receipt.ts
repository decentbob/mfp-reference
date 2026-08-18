// Operator co-signed receipts (§C2).
//
// A sequencer co-signs each accepted operation: the operator signs
// (backing name, operation hash, position). The position is the operation's
// index in that backing's operation log — the same log the commitment commits
// to (invariant 23) — so a receipt is verifiable *against a committed state*:
// reconstruct the op at that position from the committed log entry, hash it,
// and check it equals the receipt's op hash. On a replay the sequencer returns
// the identical prior receipt (invariant 26).

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ByteWriter, compareBytes } from "./bytes.js";
import type { BackingSnapshot } from "./commitment.js";
import { verifySignatureStrict } from "./keys.js";
import type { OpLogEntry } from "./ledger.js";
import { encodeBurnMessage, encodeIssuanceMessage, encodeTransferMessage } from "./messages.js";

const textEncoder = new TextEncoder();
const RECEIPT_CONTEXT = textEncoder.encode("mfp/receipt/v1");

export interface Receipt {
  readonly backingName: Uint8Array;
  readonly opHash: Uint8Array;
  /** The operation's position in the backing's operation log. */
  readonly position: bigint;
  readonly operator: Uint8Array;
  readonly signature: Uint8Array;
}

function receiptMessage(backingName: Uint8Array, opHash: Uint8Array, position: bigint): Uint8Array {
  const w = new ByteWriter();
  w.raw(RECEIPT_CONTEXT);
  w.raw(backingName);
  w.raw(opHash);
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

/** A receipt is valid iff the operator signed exactly (backing name, op hash, position). */
export function verifyReceipt(receipt: Receipt): boolean {
  return verifySignatureStrict(
    receipt.signature,
    receiptMessage(receipt.backingName, receipt.opHash, receipt.position),
    receipt.operator,
  );
}

/** Reconstruct the canonical signed message of a logged operation, then hash it. */
export function opHashOfEntry(backingName: Uint8Array, entry: OpLogEntry): Uint8Array {
  switch (entry.kind) {
    case "issue":
      return sha256(encodeIssuanceMessage(backingName, entry.recipient, entry.quantity, entry.nonce));
    case "transfer":
      return sha256(
        encodeTransferMessage(backingName, entry.from, entry.to, entry.quantity, entry.nonce),
      );
    case "burn":
      return sha256(encodeBurnMessage(backingName, entry.holder, entry.quantity, entry.nonce));
  }
}

/**
 * Whether a receipt is proven by a served state: the snapshot is for the same
 * backing, has a log entry at the receipt's position, and that entry
 * reconstructs to the receipt's op hash. Combined with a check that the
 * snapshot matches a commitment root (invariant 22), this proves the operation
 * is in the committed state. Does not itself check the operator signature —
 * call verifyReceipt for that.
 */
export function receiptProvenBy(receipt: Receipt, snapshot: BackingSnapshot): boolean {
  if (compareBytes(snapshot.name, receipt.backingName) !== 0) return false;
  const index = Number(receipt.position);
  const entry = snapshot.opLog[index];
  if (entry === undefined || BigInt(entry.position) !== receipt.position) return false;
  // The snapshot may come from an untrusted operator, so a malformed entry
  // (out-of-range quantity, wrong-length key) is a failed proof, never a throw.
  let hash: Uint8Array;
  try {
    hash = opHashOfEntry(snapshot.name, entry);
  } catch {
    return false;
  }
  return compareBytes(hash, receipt.opHash) === 0;
}
