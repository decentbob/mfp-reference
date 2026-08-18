// The witnessing venue (§C2).
//
// The spec publishes commitments to "a widely-witnessed venue, typically a
// public chain", named in E together with a finality rule. A reference
// implementation has no chain, so this is an in-memory append-only log of
// commitments with an immediate finality rule — the honest stand-in, with a
// clean seam where a real venue (and its depth/gadget finality) plugs in
// later. See DECISIONS.md.
//
// The venue does not judge equivocation; it records what was published, and
// isEquivocation (commitment.ts) is what proves a fault against the record.

import { verifyCommitment, type Commitment } from "./commitment.js";

export class VenueError extends Error {}

export class Venue {
  private readonly log: Commitment[] = [];

  /** Record a commitment. Rejects one whose operator signature is invalid. */
  publish(commitment: Commitment): void {
    if (!verifyCommitment(commitment)) {
      throw new VenueError("commitment signature invalid");
    }
    this.log.push(commitment);
  }

  /** The most recently published commitment, or undefined if none. */
  latest(): Commitment | undefined {
    return this.log[this.log.length - 1];
  }

  /** Every commitment published, in order (a copy). */
  all(): readonly Commitment[] {
    return [...this.log];
  }
}
