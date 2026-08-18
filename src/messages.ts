// Canonical encodings of the signed claim-layer operations.
//
// Each operation type carries its own domain-separation context so a
// signature over one kind of message can never be replayed as another kind.
// The signed bytes are: context || fixed-layout fields. Replay of the same
// kind is prevented by the signer's nonce, which is inside the signed bytes.
//
//   issuance  "mfp/issuance/v1" || backing name (32) || recipient key (32)
//             || u32 length || quantity (minimal BE) || u64 nonce
//   transfer  "mfp/transfer/v1" || backing name (32) || from key (32)
//             || to key (32) || u32 length || quantity || u64 nonce
//   burn      "mfp/burn/v1"     || backing name (32) || holder key (32)
//             || u32 length || quantity || u64 nonce

import { backingName, type Backing } from "./backing.js";
import { bigintToMinimalBytes, ByteWriter, EncodingError } from "./bytes.js";
import { KEY_LENGTH } from "./keys.js";
import { validateQuantity } from "./quantity.js";

const textEncoder = new TextEncoder();
const ISSUANCE_CONTEXT = textEncoder.encode("mfp/issuance/v1");
const TRANSFER_CONTEXT = textEncoder.encode("mfp/transfer/v1");
const BURN_CONTEXT = textEncoder.encode("mfp/burn/v1");

export interface IssuanceOp {
  readonly backing: Backing;
  readonly recipient: Uint8Array;
  readonly quantity: bigint;
  /** The backer's next nonce; signed, so the message cannot be replayed. */
  readonly nonce: bigint;
}

export interface TransferOp {
  readonly backing: Backing;
  readonly from: Uint8Array;
  readonly to: Uint8Array;
  readonly quantity: bigint;
  /** The holder's (from key's) next nonce. */
  readonly nonce: bigint;
}

export interface BurnOp {
  readonly backing: Backing;
  readonly holder: Uint8Array;
  readonly quantity: bigint;
  /** The holder's next nonce. */
  readonly nonce: bigint;
}

function key(bytes: Uint8Array, what: string): Uint8Array {
  if (bytes.length !== KEY_LENGTH) {
    throw new EncodingError(`${what} must be ${KEY_LENGTH} bytes`);
  }
  return bytes;
}

export function encodeIssuance(op: IssuanceOp): Uint8Array {
  validateQuantity(op.quantity, "issuance quantity");
  const w = new ByteWriter();
  w.raw(ISSUANCE_CONTEXT);
  w.raw(backingName(op.backing));
  w.raw(key(op.recipient, "recipient key"));
  w.lengthPrefixed(bigintToMinimalBytes(op.quantity));
  w.u64(op.nonce);
  return w.finish();
}

export function encodeTransfer(op: TransferOp): Uint8Array {
  validateQuantity(op.quantity, "transfer quantity");
  const w = new ByteWriter();
  w.raw(TRANSFER_CONTEXT);
  w.raw(backingName(op.backing));
  w.raw(key(op.from, "from key"));
  w.raw(key(op.to, "to key"));
  w.lengthPrefixed(bigintToMinimalBytes(op.quantity));
  w.u64(op.nonce);
  return w.finish();
}

export function encodeBurn(op: BurnOp): Uint8Array {
  validateQuantity(op.quantity, "burn quantity");
  const w = new ByteWriter();
  w.raw(BURN_CONTEXT);
  w.raw(backingName(op.backing));
  w.raw(key(op.holder, "holder key"));
  w.lengthPrefixed(bigintToMinimalBytes(op.quantity));
  w.u64(op.nonce);
  return w.finish();
}
