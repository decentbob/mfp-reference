// The witnessing venue (§C2).
//
// The spec publishes commitments to "a widely-witnessed venue, typically a
// public chain", named in E together with a finality rule. A reference
// implementation has no chain, so this is an in-memory append-only log of
// commitments with an immediate finality rule — the honest stand-in, with a
// clean seam where a real venue (and its depth/gadget finality) plugs in
// later. See DECISIONS.md.
//
// **The venue owns the clock.** Its witnessed index is the one every deadline in
// the system is read against, and it advances whether or not any particular
// operator publishes — `advance` stands in for block production, which nobody
// inside the system controls. That independence is the point: read the clock off
// an operator's own commitments instead and a sequencer that simply stops
// publishing freezes every deadline in its book, so no dishonour is ever reached
// and a holder locked by a live acceptance can never withdraw. §C2b names that
// party: "A stalling backer-run sequencer publishes on time, and the stall shows
// only as a spent set that stops growing."
//
// So a commitment's `sequence` — the operator's own count of its commitments,
// which equivocation is keyed on — is a different number from the venue's
// witnessed index, and the two are named differently here so they cannot be
// read as one. The venue records both: what was published, and the index it was
// witnessed at, which is the only trustworthy source for the latter. Both are
// stored as the venue's own copies and handed out as copies — the publisher keeps
// a reference to what it published, and `readonly` does not stop it rewriting
// those bytes.
//
// **A venue has an identity, and E names it.** §C2b makes a grade effective
// "for each backing at its witnessed index on that backing's declared venue",
// so a reader asking whether an operator has gone silent has to be asking the
// right record. recovery.ts refuses to answer for a backing that names a
// different venue; a backing that names none is answered by whichever record
// its reader holds, which is the setting its backer chose.
//
// Anyone may publish, so every query is per operator: a stranger's commitments
// must not be mistaken for the operator you are checking. The venue does not
// judge equivocation; it records what was published, and isEquivocation
// (commitment.ts) is what proves a fault against the record.
//
// **The venue records two kinds of thing.** Commitments, which operators
// publish, and operations, which anyone may. §C2b sends the second here when a
// sequencer goes dark: "a signed spend record published at the venue, checked
// against the last committed balance state, stands in for the nullifier", and
// the transfer request a challenger exhibits is published "where demands are".
// The venue judges neither. It records what was published and the index it was
// witnessed at, exactly as it does for a commitment — whether an operation had
// any force is the law's question, answered by whoever reads (recovery.ts).
// Refusing bytes that do not encode is the one thing it does judge, because an
// entry with no canonical message is not a record of anything.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { compareBytes, copyBytes } from "./bytes.js";
import {
  decodeCommitment,
  encodeCommitment,
  verifyCommitment,
  type Commitment,
} from "./commitment.js";
import { utf8Encoder } from "./contexts.js";
import type { Backing } from "./backing.js";
import { decodePublishedOp, encodePublishedOp, type PublishedOp } from "./oplog.js";
import {
  decodeReplacement,
  encodeReplacement,
  type Replacement,
  type WitnessedReplacement,
} from "./replacement.js";
import {
  decodeRevocation,
  encodeRevocation,
  isSignedRevocation,
  type Revocation,
  type WitnessedRevocation,
} from "./revocation.js";

export class VenueError extends Error {}

/**
 * Run a verifier's body, keeping the one distinction every catch in this system
 * has to make: **a venue declining to answer is not malformed input.**
 *
 * The verifiers here catch broadly on purpose, because everything they read —
 * served states, receipts, commitments, published operations — comes from
 * whoever exhibits it, so a wrong length or a missing field has to be a failed
 * check rather than a crash (CLAUDE.md: verifiers never throw). A `VenueError`
 * is the one thing reaching those catches that is not that. It means the caller
 * holds a partial view and asked it something it was not synced for, and turning
 * it into `false`, `undefined` or `"unrelated"` states a fact about a party
 * built out of not having looked: an honest operator reads as inauthentic, a
 * punctual successor reads as silent, a stolen key reads as live.
 *
 * That rule was written by hand three times and forgotten four, each time one
 * layer above the last, so it lives here once and every catch that can see a
 * venue goes through it. `venue-refusal.test.ts` holds the whole surface to it.
 */
export function answering<T>(body: () => T, onMalformed: T): T {
  try {
    return body();
  } catch (cause) {
    if (cause instanceof VenueError) throw cause;
    return onMalformed;
  }
}

/**
 * Whether this venue is the one the backing declares (§C2b: a grade is effective
 * "at its witnessed index on that backing's declared venue", and a revocation is
 * "effective for each backing at its witnessed index on that backing's declared
 * venue").
 *
 * **A backing that declares no venue answers true**, and that is the setting
 * rather than a hole: E tags 0x01 and 0x02 name no venue, so their grade is read
 * against whichever record the reader holds, exactly as it was before a venue
 * could be declared at all. A backer who wants the grade pinned declares one.
 *
 * Every predicate that reads a venue's record on a backing's behalf goes through
 * this, so there is one definition of "the right record" rather than one per
 * caller. It lives here rather than beside the grades because the revocation
 * reads it too, and a second copy over there would be one definition drifting
 * from another. quietFor deliberately does not use it: it takes an operator
 * rather than a backing, and has no terms to consult.
 */
export function venueIsDeclared(venue: Venue, backing: Backing): boolean {
  const declared = backing.evidence.witnessing?.venue;
  if (declared === undefined) return true;
  return compareBytes(venue.id, declared) === 0;
}

/**
 * The identity of a venue nobody named. A backing that declares no venue (E
 * tags 0x01 and 0x02) is graded against whichever record its reader holds, and
 * a Venue built without an identity is that record — one venue, not a wildcard,
 * so a backing may declare this id and mean it.
 */
export const UNNAMED_VENUE = sha256(utf8Encoder.encode("mfp/venue/unnamed/v1"));

/**
 * One record, as a venue holds it: the canonical bytes, and the venue's own word
 * on when it witnessed them.
 *
 * **Bytes, not objects.** Any venue that is not a variable in this process
 * stores bytes — a chain stores bytes — so holding them here is the honest model
 * rather than a concession. It also makes the copy rule structural instead of
 * remembered: encoding produces fresh bytes on the way in and decoding produces
 * a fresh object on the way out, so a publisher cannot rewrite what it
 * published and a reader cannot poison the record for the next one. Three
 * explicit copy functions stopped being needed the moment this changed.
 */
interface Witnessed {
  readonly bytes: Uint8Array;
  readonly at: bigint;
}

/**
 * An operation published at the venue, and the index the venue witnessed it at.
 * That index is the clock the operation is judged against — the venue's word,
 * never the publisher's, which is the whole reason it is worth publishing here.
 */
export interface WitnessedOp {
  readonly op: PublishedOp;
  readonly at: bigint;
}

/**
 * What the rest of the system needs from a venue, and nothing else.
 *
 * An interface rather than a class, because there will be more than one: this
 * process holds `LocalVenue`, and a real one is a chain. Every method here is
 * something a chain can answer — a height, records filed by key, records in the
 * order they were witnessed. `advance` is deliberately NOT here: block
 * production is not a venue's to offer, it is the thing no participant controls,
 * and only the local stand-in can pretend otherwise.
 */
export interface Venue {
  /** This venue's identity, as a copy — the value E declares to name it. */
  readonly id: Uint8Array;
  witnessedIndex(): bigint;
  publish(commitment: Commitment): void;
  publishOp(backingName: Uint8Array, op: PublishedOp): void;
  publishReplacement(backingName: Uint8Array, replacement: Replacement): void;
  /**
   * Filed under the key it revokes, not under a backing: §C2b's revocation is
   * "published by K to every venue its backings name", and one K obligates many
   * backings. The record names its own subject, so nothing is passed beside it.
   */
  publishRevocation(revocation: Revocation): void;
  publishedOpsFor(backingName: Uint8Array): WitnessedOp[];
  replacementsFor(backingName: Uint8Array): WitnessedReplacement[];
  revocationsFor(obligor: Uint8Array): WitnessedRevocation[];
  latestFor(operator: Uint8Array, asOf?: bigint): Commitment | undefined;
  witnessedAtFor(operator: Uint8Array, asOf?: bigint): bigint | undefined;
  firstCommitmentFor(operator: Uint8Array, notBefore?: bigint): bigint | undefined;
  nextSequenceFor(operator: Uint8Array): bigint;
}

export class LocalVenue implements Venue {
  /** The venue's own clock: the latest witnessed index (immediate finality). */
  private height = 0n;
  /** This venue's own identity, the value E declares to name it. */
  private readonly venueId: Uint8Array;
  /** Operator hex -> that operator's commitment records, in published order. */
  private readonly byOperator = new Map<string, Witnessed[]>();
  /** Backing name hex -> operation records, in published order. */
  private readonly opsByBacking = new Map<string, Witnessed[]>();
  /** Backing name hex -> replacement records, in published order. */
  private readonly replacementsByBacking = new Map<string, Witnessed[]>();
  /** Obligor key hex -> revocation records, in published order. */
  private readonly revocationsByObligor = new Map<string, Witnessed[]>();

  /**
   * A venue carries an identity, because §C2b reads a grade "at its witnessed
   * index on that backing's declared venue". Without one, whether an operator
   * has gone silent is a fact about which record you happened to be handed
   * rather than one a stranger checks — and the grade pays money.
   *
   * Its own copy, handed out as a copy: a venue that could be re-identified
   * after publication could be made to answer for a backing it never served.
   */
  constructor(id: Uint8Array = UNNAMED_VENUE) {
    if (!(id instanceof Uint8Array) || id.length !== 32) {
      throw new VenueError("a venue id must be 32 bytes");
    }
    this.venueId = copyBytes(id);
  }

  /** This venue's identity, as a copy — the value E declares to name it. */
  get id(): Uint8Array {
    return copyBytes(this.venueId);
  }

  /**
   * The latest witnessed index at this venue — the clock instants, deadlines and
   * every other asserted time are read against (§C0b, invariant 21).
   */
  witnessedIndex(): bigint {
    return this.height;
  }

  /**
   * Advance the clock. Stands in for block production: no participant controls
   * it, which is exactly why a stalling operator cannot stop it.
   */
  advance(by = 1n): bigint {
    if (by < 1n) throw new VenueError("the venue's clock only moves forward");
    this.height += by;
    return this.height;
  }

  /**
   * Record a commitment. Rejects an invalid signature, and a sequence number
   * that does not strictly extend that operator's own history — so latestFor
   * means the most recent state and an operator cannot silently rewrite its past.
   */
  publish(commitment: Commitment): void {
    if (!verifyCommitment(commitment)) {
      throw new VenueError("commitment signature invalid");
    }
    const key = bytesToHex(commitment.operator);
    // Encoded on the way in, which is what makes the record the venue's own: the
    // publisher keeps a reference to the object it handed over, and mutating it
    // afterwards must not rewrite a published past.
    const witnessed: Witnessed = { bytes: encodeCommitment(commitment), at: this.height };
    const log = this.byOperator.get(key);
    if (log === undefined) {
      this.byOperator.set(key, [witnessed]);
      return;
    }
    const highest = decodeCommitment((log[log.length - 1] as Witnessed).bytes).sequence;
    if (commitment.sequence <= highest) {
      throw new VenueError("commitment sequence does not extend the operator's history");
    }
    log.push(witnessed);
  }

  /**
   * Record an operation published against a backing. Anyone may publish, and
   * the venue takes no view: a publication is not an accepted operation, and
   * §C2b gives it force only where it was witnessed inside a gap in its
   * operator's commitments — which recovery.ts decides, from this record.
   *
   * The one refusal is bytes that do not encode. An entry with no canonical
   * message names no operation, so recording it would be recording nothing,
   * and every reader would have to handle the throw instead.
   */
  publishOp(backingName: Uint8Array, op: PublishedOp): void {
    // Both halves of "can this be recorded at all" are inside one guard.
    // Encoding proves the operation names something; copying it proves every
    // field is really there — including the signature, which the canonical
    // message deliberately does not contain and so cannot vouch for. Left
    // outside, the half the message cannot see escaped as a TypeError naming no
    // boundary. The copy is the venue's own, for the reason commitments are
    // copied: the publisher keeps a reference to what it handed over.
    let bytes: Uint8Array;
    try {
      bytes = encodePublishedOp(backingName, op);
    } catch (cause) {
      throw new VenueError(`published operation does not encode: ${String(cause)}`);
    }
    const key = bytesToHex(backingName);
    const log = this.opsByBacking.get(key);
    if (log === undefined) this.opsByBacking.set(key, [{ bytes, at: this.height }]);
    else log.push({ bytes, at: this.height });
  }

  /**
   * Everything published against this backing, in the order the venue witnessed
   * it, as copies. Order is the venue's contribution: "witnessing pins order"
   * (§C2), which is what settles two conflicting requests at one nonce.
   */
  publishedOpsFor(backingName: Uint8Array): WitnessedOp[] {
    const log = this.opsByBacking.get(bytesToHex(backingName)) ?? [];
    // Decoded on the way out, so every reader gets its own object and the record
    // itself is unreachable. Nothing published here can fail to decode: publishOp
    // refused anything that did not encode.
    return log.map((witnessed) => ({
      op: decodePublishedOp(witnessed.bytes).op,
      at: witnessed.at,
    }));
  }

  /**
   * Record a replacement published against a backing (§C2: "a replacement is
   * itself a witnessed object"). Anyone may publish, and the venue takes no
   * view: whether it is signed by the key E's rule names, and whether it has
   * taken force, is replacement.ts's question, answered from this record.
   *
   * The one refusal is bytes that do not encode, for the reason an operation
   * with no canonical message is a record of nothing.
   */
  publishReplacement(backingName: Uint8Array, replacement: Replacement): void {
    let bytes: Uint8Array;
    try {
      bytes = encodeReplacement(backingName, replacement);
    } catch (cause) {
      throw new VenueError(`published replacement does not encode: ${String(cause)}`);
    }
    const key = bytesToHex(backingName);
    const log = this.replacementsByBacking.get(key);
    if (log === undefined) this.replacementsByBacking.set(key, [{ bytes, at: this.height }]);
    else log.push({ bytes, at: this.height });
  }

  /** Every replacement published against this backing, as copies, in order. */
  replacementsFor(backingName: Uint8Array): WitnessedReplacement[] {
    const log = this.replacementsByBacking.get(bytesToHex(backingName)) ?? [];
    return log.map((w) => ({ replacement: decodeReplacement(w.bytes).replacement, at: w.at }));
  }

  /**
   * Record K's revocation of itself, filed under K.
   *
   * **This one is checked, where a published operation is not**, and the
   * difference is what a bad record could do. Anyone may publish an operation
   * and the venue takes no view, because a publication is not an accepted
   * operation and recovery.ts decides what force it has. A revocation has its
   * whole effect the moment it is recorded — it stops issuance and moves the
   * boundary every holder reads — so an unsigned one would let any stranger
   * freeze any backer's issuance for the cost of a publication. It is one
   * signature by the key named in the record, which is the whole of what a
   * revocation is, so the venue can check it without taking a view on anything.
   */
  publishRevocation(revocation: Revocation): void {
    if (!isSignedRevocation(revocation)) {
      throw new VenueError("revocation is not signed by the key it revokes");
    }
    let bytes: Uint8Array;
    try {
      bytes = encodeRevocation(revocation);
    } catch (cause) {
      throw new VenueError(`published revocation does not encode: ${String(cause)}`);
    }
    const key = bytesToHex(revocation.obligor);
    const log = this.revocationsByObligor.get(key);
    if (log === undefined) this.revocationsByObligor.set(key, [{ bytes, at: this.height }]);
    else log.push({ bytes, at: this.height });
  }

  /** Every revocation published against this key, as copies, in order. */
  revocationsFor(obligor: Uint8Array): WitnessedRevocation[] {
    const log = this.revocationsByObligor.get(bytesToHex(obligor)) ?? [];
    return log.map((w) => ({ revocation: decodeRevocation(w.bytes), at: w.at }));
  }

  /**
   * The index at which this key first published a commitment here at or after
   * `notBefore`, or undefined if it never has. §C2 gives a successor force only
   * "from the first index at which it has published its own commitment", so this
   * is the second half of the two-stage handover.
   *
   * The bound matters: asked from genesis, a successor that already operates
   * some other backing answers with a commitment it made long before anyone
   * named it, and the second stage means nothing. Asked from the index the
   * handover was witnessed at, the commitment is at least one it could have made
   * for this handover.
   */
  firstCommitmentFor(operator: Uint8Array, notBefore = 0n): bigint | undefined {
    const log = this.byOperator.get(bytesToHex(operator)) ?? [];
    for (const witnessed of log) if (witnessed.at >= notBefore) return witnessed.at;
    return undefined;
  }

  /**
   * This operator's most recent commitment **as of** `asOf` (the present by
   * default), as a copy, or undefined if it had none by then. A copy because one
   * reader must not be able to poison the record for the next.
   *
   * The `asOf` form is what makes "the last witnessed snapshot" a stable fact:
   * asked about the present, the answer changes the moment the operator
   * publishes again, and an operator that would rather a redemption were not
   * resolvable could make it so by publishing.
   */
  latestFor(operator: Uint8Array, asOf?: bigint): Commitment | undefined {
    const witnessed = this.latestWitnessedFor(operator, asOf);
    return witnessed === undefined ? undefined : decodeCommitment(witnessed.bytes);
  }

  /**
   * The witnessed index of this operator's latest commitment **at or before**
   * `asOf` (the present by default), or undefined if it had none by then.
   * "Witnessed at index i" is the spec's own notion — §C2b makes a revocation
   * "effective for each backing at its witnessed index on that backing's
   * declared venue" — and the height is the venue's word, not the operator's,
   * which is the party that would want to misstate it. Subtract it from an index
   * and you have how long this operator had been quiet at that index, which is
   * what §C2b's silence clause is measured on — now, for the grade, and at a
   * past index, for whether a publication landed inside a gap.
   */
  witnessedAtFor(operator: Uint8Array, asOf?: bigint): bigint | undefined {
    return this.latestWitnessedFor(operator, asOf)?.at;
  }

  private latestWitnessedFor(operator: Uint8Array, asOf?: bigint): Witnessed | undefined {
    const log = this.byOperator.get(bytesToHex(operator));
    if (log === undefined) return undefined;
    if (asOf === undefined) return log[log.length - 1];
    // Published in witnessed order, so the last one at or before asOf is the
    // latest. A linear walk from the end: the commitments a gap question reaches
    // back over are the recent ones.
    for (let i = log.length - 1; i >= 0; i--) {
      const witnessed = log[i] as Witnessed;
      if (witnessed.at <= asOf) return witnessed;
    }
    return undefined;
  }

  /**
   * The sequence number this operator's next commitment must carry. Derived from
   * the record rather than from sequencer memory, so a failed publish does not
   * burn one (which would let the operator sign two roots at one sequence and
   * frame itself for equivocation) and a restart resumes where it left off.
   */
  nextSequenceFor(operator: Uint8Array): bigint {
    const latest = this.latestWitnessedFor(operator);
    return latest === undefined ? 0n : decodeCommitment(latest.bytes).sequence + 1n;
  }
}
