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
// read as one.
//
// Anyone may publish, so every query is per operator: a stranger's commitments
// must not be mistaken for the operator you are checking. The venue does not
// judge equivocation; it records what was published, and isEquivocation
// (commitment.ts) is what proves a fault against the record.

import { bytesToHex } from "@noble/hashes/utils.js";
import { verifyCommitment, type Commitment } from "./commitment.js";

export class VenueError extends Error {}

export class Venue {
  /** The venue's own clock: the latest witnessed index (immediate finality). */
  private height = 0n;
  /** Operator hex -> that operator's commitments, in published order. */
  private readonly byOperator = new Map<string, Commitment[]>();

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
    const log = this.byOperator.get(key);
    if (log === undefined) {
      this.byOperator.set(key, [commitment]);
      return;
    }
    const highest = (log[log.length - 1] as Commitment).sequence;
    if (commitment.sequence <= highest) {
      throw new VenueError("commitment sequence does not extend the operator's history");
    }
    log.push(commitment);
  }

  /** This operator's most recent commitment, or undefined if it has none. */
  latestFor(operator: Uint8Array): Commitment | undefined {
    const log = this.byOperator.get(bytesToHex(operator));
    return log?.[log.length - 1];
  }

  /**
   * The sequence number this operator's next commitment must carry. Derived from
   * the record rather than from sequencer memory, so a failed publish does not
   * burn one (which would let the operator sign two roots at one sequence and
   * frame itself for equivocation) and a restart resumes where it left off.
   */
  nextSequenceFor(operator: Uint8Array): bigint {
    const latest = this.latestFor(operator);
    return latest === undefined ? 0n : latest.sequence + 1n;
  }
}
