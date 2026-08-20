// §C2b's first failure branch: the backer's key is stolen.
//
// "If a backer's key is stolen, the damage is unbounded and permanent, since K
// alone authorises issuance and nothing expires. So K may publish a revocation:
// witnessed, and prospective, so existing claims keep their terms and no further
// issuance is valid."
//
// **A stop-loss, not a remedy.** A thief issues fast and a backer notices
// slowly, so by the time a revocation is witnessed the fraudulent supply is
// already committed and stands — "the damage is unbounded and permanent", and "a
// thief's purpose is to issue, so it revokes only on the way out". What actually
// prevents the loss is a threshold K, which §C2b calls "the strongest argument"
// for one, and which is invisible here: t-of-n aggregated to a single Ed25519
// key leaves the name, E and strict verification untouched. That is the same
// shape as CLAUDE.md's one-writer rule for the operator, one role along.
//
// **It revokes a KEY, not a backing**, which makes it the one venue record that
// does not name a backing. §C2b: "published by K to every venue its backings
// name" — one K obligates many backings, and revoking it revokes all of them at
// once. Slice 15's rule that every record names its own backing was written for
// records about a backing; this is a record about a key, so it names the key.
//
// **And it carries nothing else.** No sequence, because "revocation is the one
// act no later signature can repair" and there is no second one to order. No
// venue, because the paper wants it relayed everywhere and a copy at another
// venue is a copy anyone may make. No expiry, because "de-revocation would carry
// the same K". Two revocations by one key are byte-identical, which is what
// makes republishing harmless.

import { ed25519 } from "@noble/curves/ed25519.js";
import type { Backing } from "./backing.js";
import { ByteReader, ByteWriter, compareBytes, copyBytes } from "./bytes.js";
import { REVOCATION_CONTEXT } from "./contexts.js";
import { verifySignatureStrict } from "./keys.js";
import type { Venue } from "./venue.js";

/** K's own signature that K issues no more. */
export interface Revocation {
  /** The obligor key being revoked. */
  readonly obligor: Uint8Array;
  /** That key's signature over the message below. */
  readonly signature: Uint8Array;
}

/** A revocation together with the venue's word on when it witnessed it. */
export interface WitnessedRevocation {
  readonly revocation: Revocation;
  readonly at: bigint;
}

/**
 * The bytes K signs: the tag and K itself, and nothing more.
 *
 * Signing over its own key is what makes the act self-contained — a record that
 * named anything else would need that thing to be checked too, and there is
 * nothing here to check against. Throws on a malformed key.
 */
export function revocationMessage(obligor: Uint8Array): Uint8Array {
  const w = new ByteWriter();
  w.context(REVOCATION_CONTEXT);
  w.key32(obligor, "obligor key");
  return w.finish();
}

/** Revoke this key. Idempotent by construction: the bytes are always the same. */
export function signRevocation(obligorSecret: Uint8Array): Revocation {
  const obligor = ed25519.getPublicKey(obligorSecret);
  return {
    obligor,
    signature: ed25519.sign(revocationMessage(obligor), obligorSecret),
  };
}

/**
 * A revocation as a **record**: the key, then the signature. Fixed width
 * throughout, so there is one spelling and no length to disagree with.
 */
export function encodeRevocation(revocation: Revocation): Uint8Array {
  const w = new ByteWriter();
  w.key32(revocation.obligor, "obligor key");
  w.fixed(revocation.signature, 64, "signature");
  return w.finish();
}

/** Strict inverse of encodeRevocation. Throws EncodingError on anything else. */
export function decodeRevocation(bytes: Uint8Array): Revocation {
  const r = new ByteReader(bytes);
  const obligor = r.raw(32);
  const signature = r.raw(64);
  r.expectEnd();
  return { obligor, signature };
}

/**
 * Whether this really is K's signature over K. A verifier: the record comes from
 * whoever published it, so anything malformed is a revocation that is not
 * proven rather than a throw.
 *
 * There is no second party to check against — a revocation is one key's word
 * about itself — which is exactly why it is safe for anyone at all to relay one.
 */
export function isSignedRevocation(revocation: Revocation): boolean {
  try {
    return verifySignatureStrict(
      revocation.signature,
      revocationMessage(revocation.obligor),
      revocation.obligor,
    );
  } catch {
    return false;
  }
}

/**
 * The witnessed index this backing's obligor was revoked at, or undefined if it
 * was not — on this venue, which must be the one the backing declares.
 *
 * **Earliest wins**, where two replacements at one predecessor also take the
 * earliest (§C2, witnessing pins order) but for a different reason: there is no
 * choice being made here and no later act can repair it, so a second publication
 * is a copy of the first rather than a competing claim. Taking the latest would
 * let a thief holding K push its own boundary forward by republishing.
 *
 * **Read on the declared venue**, because §C2b makes a revocation "effective for
 * each backing at its witnessed index on that backing's declared venue" — the
 * same sentence the grades are read under, so the same guard. A backing that
 * declares no venue is answered by whichever record its reader holds, which is
 * the setting its backer chose.
 */
export function revokedAt(venue: Venue, backing: Backing): bigint | undefined {
  try {
    const declared = backing.evidence.witnessing?.venue;
    if (declared !== undefined && compareBytes(venue.id, declared) !== 0) return undefined;
    let earliest: bigint | undefined;
    for (const witnessed of venue.revocationsFor(backing.obligor)) {
      if (earliest === undefined || witnessed.at < earliest) earliest = witnessed.at;
    }
    return earliest;
  } catch {
    return undefined;
  }
}

/** A copy, for the same reason every other record hands out copies. */
export function copyRevocation(revocation: Revocation): Revocation {
  return {
    obligor: copyBytes(revocation.obligor),
    signature: copyBytes(revocation.signature),
  };
}
