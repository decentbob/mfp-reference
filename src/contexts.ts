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
//   mfp/demand/v1              a holder presenting claims for payment
//   mfp/acceptance/v1          a backer answering a demand
//   mfp/release/v1             a holder settling an accepted demand
//   mfp/withdrawal/v1          a holder ending an unanswered demand
//   mfp/replacement/v1         E's rule naming a successor operator
//   mfp/revocation/v1          K withdrawing its own authority to issue

const encoder = new TextEncoder();
const tag = (s: string): Uint8Array => encoder.encode(s);

export const BACKING_SIGNATURE_CONTEXT = tag("mfp/backing-signature/v1");
export const ISSUANCE_CONTEXT = tag("mfp/issuance/v1");
export const TRANSFER_CONTEXT = tag("mfp/transfer/v1");
export const BURN_CONTEXT = tag("mfp/burn/v1");
export const RECEIPT_CONTEXT = tag("mfp/receipt/v1");
export const COMMITMENT_CONTEXT = tag("mfp/commitment/v1");
export const DEMAND_CONTEXT = tag("mfp/demand/v1");
export const ACCEPTANCE_CONTEXT = tag("mfp/acceptance/v1");
export const RELEASE_CONTEXT = tag("mfp/release/v1");
export const WITHDRAWAL_CONTEXT = tag("mfp/withdrawal/v1");
export const REPLACEMENT_CONTEXT = tag("mfp/replacement/v1");
export const REVOCATION_CONTEXT = tag("mfp/revocation/v1");

/** Shared UTF-8 codecs. The decoder is strict and BOM-preserving so that
 *  decode(encode(s)) === s for every well-formed string. */
export const utf8Encoder = encoder;
export const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * The property the whole scheme rests on: no tag is a prefix of another, so
 * writing a tag unframed as a message's first field can never let one message
 * type be read as another. Asserted at load rather than assumed, because a tag
 * added later is exactly when this would silently stop holding.
 */
const ALL_CONTEXTS = [
  BACKING_SIGNATURE_CONTEXT,
  ISSUANCE_CONTEXT,
  TRANSFER_CONTEXT,
  BURN_CONTEXT,
  RECEIPT_CONTEXT,
  COMMITMENT_CONTEXT,
  DEMAND_CONTEXT,
  ACCEPTANCE_CONTEXT,
  RELEASE_CONTEXT,
  WITHDRAWAL_CONTEXT,
  REPLACEMENT_CONTEXT,
  REVOCATION_CONTEXT,
];

export function contextsArePrefixFree(tags: readonly Uint8Array[] = ALL_CONTEXTS): boolean {
  for (let i = 0; i < tags.length; i++) {
    for (let j = 0; j < tags.length; j++) {
      if (i === j) continue;
      const a = tags[i] as Uint8Array;
      const b = tags[j] as Uint8Array;
      if (a.length <= b.length && a.every((byte, k) => byte === b[k])) return false;
    }
  }
  return true;
}

if (!contextsArePrefixFree()) {
  throw new Error("domain-separation tags are not prefix-free");
}
