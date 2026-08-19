// Canonical encodings of the signed claim-layer operations.
//
// Each operation type carries its own domain-separation context (contexts.ts)
// so a signature over one kind of message can never be replayed as another.
// Replay of the same kind is prevented by the signer's nonce, which is inside
// the signed bytes. Every field is fixed-width-and-asserted or length-prefixed
// (the framing rule), so no two operations share an encoding and the operation
// hash is a sound identity.
//
//   issuance  context || backing name (32) || recipient key (32)
//             || u32 length || quantity (minimal BE) || u64 nonce
//   transfer  context || backing name (32) || from key (32) || to key (32)
//             || u32 length || quantity || u64 nonce
//   burn      context || backing name (32) || holder key (32)
//             || u32 length || quantity || u64 nonce
//
// The field-level encoders take the backing NAME rather than the Backing
// object, so a verifier holding only a committed operation-log entry can
// reconstruct the exact signed message and hence its hash (see receipt.ts).
// The op-shaped wrappers below feed them backing.name.

import { type Backing } from "./backing.js";
import { bigintToMinimalBytes, ByteWriter, validateQuantity } from "./bytes.js";
import { BURN_CONTEXT, ISSUANCE_CONTEXT, TRANSFER_CONTEXT } from "./contexts.js";

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

/** Context, then the backing name — the head every operation message shares. */
function head(context: Uint8Array, backingName: Uint8Array): ByteWriter {
  const w = new ByteWriter();
  w.context(context);
  w.key32(backingName, "backing name");
  return w;
}

/** Quantity then nonce — the tail every operation message shares. */
function tail(w: ByteWriter, quantity: bigint, nonce: bigint): Uint8Array {
  validateQuantity(quantity, "quantity");
  w.lengthPrefixed(bigintToMinimalBytes(quantity));
  w.u64(nonce);
  return w.finish();
}

export function encodeIssuanceMessage(
  backingName: Uint8Array,
  recipient: Uint8Array,
  quantity: bigint,
  nonce: bigint,
): Uint8Array {
  const w = head(ISSUANCE_CONTEXT, backingName);
  w.key32(recipient, "recipient key");
  return tail(w, quantity, nonce);
}

export function encodeTransferMessage(
  backingName: Uint8Array,
  from: Uint8Array,
  to: Uint8Array,
  quantity: bigint,
  nonce: bigint,
): Uint8Array {
  const w = head(TRANSFER_CONTEXT, backingName);
  w.key32(from, "from key");
  w.key32(to, "to key");
  return tail(w, quantity, nonce);
}

export function encodeBurnMessage(
  backingName: Uint8Array,
  holder: Uint8Array,
  quantity: bigint,
  nonce: bigint,
): Uint8Array {
  const w = head(BURN_CONTEXT, backingName);
  w.key32(holder, "holder key");
  return tail(w, quantity, nonce);
}

export function encodeIssuance(op: IssuanceOp): Uint8Array {
  return encodeIssuanceMessage(op.backing.name, op.recipient, op.quantity, op.nonce);
}

export function encodeTransfer(op: TransferOp): Uint8Array {
  return encodeTransferMessage(op.backing.name, op.from, op.to, op.quantity, op.nonce);
}

export function encodeBurn(op: BurnOp): Uint8Array {
  return encodeBurnMessage(op.backing.name, op.holder, op.quantity, op.nonce);
}
