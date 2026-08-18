// Quantity rules shared by the backing object and the claim layer.
//
// A quantity is a whole positive number of units, bounded so its minimal
// big-endian encoding fits MAX_QUANTITY_BYTES (invariant 15 makes all
// presentation arithmetic integer arithmetic over these).

import { EncodingError } from "./bytes.js";

export const MAX_QUANTITY_BYTES = 32; // quantities are < 2^256
export const MAX_QUANTITY_EXCLUSIVE = 1n << (8n * BigInt(MAX_QUANTITY_BYTES));

export function isValidQuantity(n: bigint): boolean {
  return n >= 1n && n < MAX_QUANTITY_EXCLUSIVE;
}

export function validateQuantity(n: bigint, what: string): void {
  if (n < 1n) throw new EncodingError(`${what} must be at least 1`);
  if (n >= MAX_QUANTITY_EXCLUSIVE) throw new EncodingError(`${what} too large`);
}
