// Key and signature rules shared by every layer.
//
// Every verification key that carries authority (an obligor, a holder, an
// operator) must be a valid, non-small-order Ed25519 point: a small-order key
// accepts a forged signature over any message under permissive verification,
// and even under strict verification a balance under an invalid point is
// unspendable garbage. Verification is strict (non-ZIP215); see DECISIONS.md.

import { ed25519 } from "@noble/curves/ed25519.js";

export const KEY_LENGTH = 32;
export const SIGNATURE_LENGTH = 64;

export function isValidPublicKey(key: Uint8Array): boolean {
  if (key.length !== KEY_LENGTH) return false;
  try {
    return !ed25519.Point.fromHex(key).isSmallOrder();
  } catch {
    return false;
  }
}

/**
 * Strict Ed25519 verification, and the only verification path in the system.
 * Returns false — never throws — for a wrong-length signature OR a malformed
 * key: noble length-checks the public key outside its own try/catch, so an
 * unchecked key turns every verifier into a crash on hostile input.
 */
export function verifySignatureStrict(
  signature: Uint8Array,
  message: Uint8Array,
  key: Uint8Array,
): boolean {
  if (signature.length !== SIGNATURE_LENGTH) return false;
  // Length only: noble length-checks the key OUTSIDE its own try/catch, so an
  // unchecked key turns every verifier into a crash. The small-order rejection
  // that isValidPublicKey also does is already performed inside the strict
  // (non-ZIP215) verify path, so repeating it here would be a second
  // point decompression per verification for no added safety.
  if (key.length !== KEY_LENGTH) return false;
  return ed25519.verify(signature, message, key, { zip215: false });
}
