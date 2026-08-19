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

import { bytesToHex } from "@noble/hashes/utils.js";
import { copyCommitment, verifyCommitment, type Commitment } from "./commitment.js";
import { copyOp, opMessageOfEntry, type PublishedOp } from "./oplog.js";

export class VenueError extends Error {}

/** A commitment together with the venue's own word on when it was witnessed. */
interface Witnessed {
  readonly commitment: Commitment;
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

export class Venue {
  /** The venue's own clock: the latest witnessed index (immediate finality). */
  private height = 0n;
  /** Operator hex -> that operator's commitments, in published order. */
  private readonly byOperator = new Map<string, Witnessed[]>();
  /** Backing name hex -> operations published against it, in published order. */
  private readonly opsByBacking = new Map<string, WitnessedOp[]>();

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
    // The venue's own copy. The publisher keeps a reference to what it handed
    // over, and mutating those bytes afterwards would let it rewrite its
    // published past — the one thing this class exists to prevent.
    const witnessed: Witnessed = { commitment: copyCommitment(commitment), at: this.height };
    const log = this.byOperator.get(key);
    if (log === undefined) {
      this.byOperator.set(key, [witnessed]);
      return;
    }
    const highest = (log[log.length - 1] as Witnessed).commitment.sequence;
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
    try {
      opMessageOfEntry(backingName, op);
    } catch (cause) {
      throw new VenueError(`published operation does not encode: ${String(cause)}`);
    }
    const key = bytesToHex(backingName);
    // The venue's own copy, for the reason commitments are copied: the
    // publisher keeps a reference to what it handed over.
    const witnessed: WitnessedOp = { op: copyOp(op), at: this.height };
    const log = this.opsByBacking.get(key);
    if (log === undefined) this.opsByBacking.set(key, [witnessed]);
    else log.push(witnessed);
  }

  /**
   * Everything published against this backing, in the order the venue witnessed
   * it, as copies. Order is the venue's contribution: "witnessing pins order"
   * (§C2), which is what settles two conflicting requests at one nonce.
   */
  publishedOpsFor(backingName: Uint8Array): WitnessedOp[] {
    const log = this.opsByBacking.get(bytesToHex(backingName)) ?? [];
    return log.map((witnessed) => ({ op: copyOp(witnessed.op), at: witnessed.at }));
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
    return witnessed === undefined ? undefined : copyCommitment(witnessed.commitment);
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
    return latest === undefined ? 0n : latest.commitment.sequence + 1n;
  }
}
