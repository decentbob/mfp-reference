// The witnessing venue (§C2).
//
// The spec publishes commitments to "a widely-witnessed venue, typically a
// public chain", named in E together with a finality rule. A reference
// implementation has no chain, so this is an in-memory append-only log of
// commitments with an immediate finality rule — the honest stand-in, with a
// clean seam where a real venue (and its depth/gadget finality) plugs in
// later. See DECISIONS.md.
//
// Anyone may publish, so every query is per operator: a stranger's commitments
// must not be mistaken for the operator you are checking. The venue does not
// judge equivocation; it records what was published, and isEquivocation
// (commitment.ts) is what proves a fault against the record.

import { bytesToHex } from "@noble/hashes/utils.js";
import { verifyCommitment, type Commitment } from "./commitment.js";

export class VenueError extends Error {}

export class Venue {
  /** Operator hex -> that operator's commitments, in published order. */
  private readonly byOperator = new Map<string, Commitment[]>();

  /**
   * Record a commitment. Rejects an invalid signature, and an index that does
   * not strictly extend that operator's own history — so latestFor means the
   * most recent state and an operator cannot silently rewrite its past.
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
    const highest = (log[log.length - 1] as Commitment).index;
    if (commitment.index <= highest) {
      throw new VenueError("commitment index does not extend the operator's history");
    }
    log.push(commitment);
  }

  /** This operator's most recent commitment, or undefined if it has none. */
  latestFor(operator: Uint8Array): Commitment | undefined {
    const log = this.byOperator.get(bytesToHex(operator));
    return log?.[log.length - 1];
  }

  /**
   * The index this operator's next commitment must carry. Derived from the
   * record rather than from sequencer memory, so a failed publish does not
   * burn an index (which would let the operator sign two roots at one index
   * and frame itself for equivocation) and a restart resumes where it left off.
   */
  nextIndexFor(operator: Uint8Array): bigint {
    const latest = this.latestFor(operator);
    return latest === undefined ? 0n : latest.index + 1n;
  }
}
