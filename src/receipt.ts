// Operator co-signed receipts (§C2).
//
// A sequencer co-signs each accepted operation: the operator signs
// (backing name, operation hash, witnessed index). The operation hash is the
// SHA-256 of the operation's canonical signed message (messages.ts), so a
// receipt binds one exact operation to the index at which the sequencer
// witnessed it. On a replay the sequencer returns the identical prior receipt
// (invariant 26).

import { ed25519 } from "@noble/curves/ed25519.js";
import { ByteWriter } from "./bytes.js";
import { verifySignatureStrict } from "./keys.js";

const textEncoder = new TextEncoder();
const RECEIPT_CONTEXT = textEncoder.encode("mfp/receipt/v1");

export interface Receipt {
  readonly backingName: Uint8Array;
  readonly opHash: Uint8Array;
  /** The witnessed index at which the sequencer accepted the operation. */
  readonly index: bigint;
  readonly operator: Uint8Array;
  readonly signature: Uint8Array;
}

function receiptMessage(backingName: Uint8Array, opHash: Uint8Array, index: bigint): Uint8Array {
  const w = new ByteWriter();
  w.raw(RECEIPT_CONTEXT);
  w.raw(backingName);
  w.raw(opHash);
  w.u64(index);
  return w.finish();
}

export function signReceipt(
  operatorSecret: Uint8Array,
  backingName: Uint8Array,
  opHash: Uint8Array,
  index: bigint,
): Receipt {
  const operator = ed25519.getPublicKey(operatorSecret);
  const signature = ed25519.sign(receiptMessage(backingName, opHash, index), operatorSecret);
  return { backingName, opHash, index, operator, signature };
}

/** A receipt is valid iff the operator signed exactly (backing name, op hash, index). */
export function verifyReceipt(receipt: Receipt): boolean {
  return verifySignatureStrict(
    receipt.signature,
    receiptMessage(receipt.backingName, receipt.opHash, receipt.index),
    receipt.operator,
  );
}
