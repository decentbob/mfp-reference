// Every domain-separation tag in the system, on one screen.
//
// A tag prefixes the bytes signed for one message type, so a signature made
// for one purpose can never verify for another. A collision here is a
// signature-forgery class, which is why the complete list lives in one file
// rather than beside each use: no tag may be a prefix of another, and that is
// checkable only by reading them together.
//
//   mfp/backing-signature/v1   the obligor's signature over a backing's name
//   mfp/issuance/v1            a backer authorising issuance
//   mfp/transfer/v1            a holder moving units
//   mfp/burn/v1                a holder destroying units
//   mfp/receipt/v1             an operator co-signing an accepted operation
//   mfp/commitment/v1          an operator committing to served state

const encoder = new TextEncoder();
const tag = (s: string): Uint8Array => encoder.encode(s);

export const BACKING_SIGNATURE_CONTEXT = tag("mfp/backing-signature/v1");
export const ISSUANCE_CONTEXT = tag("mfp/issuance/v1");
export const TRANSFER_CONTEXT = tag("mfp/transfer/v1");
export const BURN_CONTEXT = tag("mfp/burn/v1");
export const RECEIPT_CONTEXT = tag("mfp/receipt/v1");
export const COMMITMENT_CONTEXT = tag("mfp/commitment/v1");

/** Shared UTF-8 codecs. The decoder is strict and BOM-preserving so that
 *  decode(encode(s)) === s for every well-formed string. */
export const utf8Encoder = encoder;
export const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
