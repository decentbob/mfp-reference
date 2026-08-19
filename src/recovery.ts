// §C2b: failure, silence, and recovery — the two facts that open snapshot
// redemption.
//
// "When sequencers go dark, claims go illiquid rather than dead. Value discounts
// until they return, and after the declared silence, redemption against the last
// witnessed snapshot opens without co-signature, with the holder proving the
// claim unspent as of that snapshot."
//
// Two things have to be true, and both are checkable by a stranger against the
// published record — which is what makes the grade something a backer concedes
// rather than argues:
//
//   1. **the grade.** "No commitment past a second declared duration, in any
//      setting: the aggravated grade. It opens snapshot redemption and runs from
//      the first missed commitment until commitments resume." Measured on the
//      venue's clock, never the silent party's own publications, and against the
//      duration the backing itself declares in E.
//   2. **the unspentness proof.** Invariant 23: "The spent set must support
//      non-membership proofs, since §C2b's recovery path proves a claim *not*
//      spent as of the last commitment, which a bare Merkle root cannot do."
//      §C2b names the transparent form: "a signed spend record published at the
//      venue, checked against the last committed balance state, stands in for
//      the nullifier."
//
// Under transparent the whole served state is rehashed against the root, which
// is already how a receipt proves, so **serving everything IS the
// non-membership proof** — the Merkle machinery is what a construction needs
// when it cannot serve everything, and belongs with the shielded ones. See
// DECISIONS.md.
//
// The payment path — the claim, acceptance and release legs, the challenge
// window, and a returning sequencer adopting what was witnessed during the gap —
// is the next slice. These predicates are its precondition, and are already what
// a holder needs in order to know where they stand.
//
// Everything here is a verifier: it answers questions about state an untrusted
// operator served, so it returns false on any malformed input and never throws.

import { type Backing } from "./backing.js";
import { compareBytes, isValidQuantity } from "./bytes.js";
import { replayLog, type LogReplay } from "./oplog.js";
import {
  stateProvesCommitment,
  type BackingSnapshot,
  type Commitment,
} from "./commitment.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Venue } from "./venue.js";

/** A served state and the commitment it must prove against — what a holder is handed. */
export interface ServedState {
  readonly snapshots: readonly BackingSnapshot[];
  readonly commitment: Commitment;
}

/**
 * How many witnessed indices this operator has been quiet. Measured from its
 * latest commitment, or from the venue's genesis where it has never published —
 * otherwise never publishing at all would be the way to escape the grade.
 */
export function quietFor(venue: Venue, operator: Uint8Array): bigint {
  return venue.witnessedIndex() - (venue.witnessedAtFor(operator) ?? 0n);
}

/**
 * §C2b's aggravated grade for this backing: its operator has published no
 * commitment for longer than the duration the backing declares. A backing whose
 * E declares no silence clause is never silent — snapshot redemption never opens
 * for it and its claims can go illiquid forever, which is a setting the backer
 * chose and the holder read before accepting.
 */
export function isSilent(venue: Venue, backing: Backing): boolean {
  const clause = backing.evidence.silence;
  if (clause === undefined) return false;
  return quietFor(venue, backing.evidence.operator) > clause.noCommitmentDuration;
}

/**
 * The one check on served state, and what everything else here rests on: it is
 * the state this backing's operator committed to, and its operation log replays
 * under the law.
 *
 * Two properties, because a committed log is the whole of what is served: what
 * the operator asserts, and whether it could have happened. Balances, totals and
 * standing demands are not compared against anything, because they are not
 * asserted separately — they are what the replay returns.
 *
 * A verifier: the state comes from an operator with a motive, so any malformed
 * field is a failed check rather than a crash.
 */
export function stateIsAuthentic(backing: Backing, served: ServedState): boolean {
  return replayServedState(backing, served) !== undefined;
}

/**
 * The state a served snapshot replays to, or undefined if it is not this
 * backing's committed state or not a history that could have happened. The
 * shared body behind stateIsAuthentic and provesHolding, so a caller that needs
 * the numbers does not verify twice.
 */
function replayServedState(backing: Backing, served: ServedState): LogReplay | undefined {
  try {
    const operator = backing.evidence.operator;
    // Signed by the operator E names — anyone can sign a valid commitment over
    // any state they like, and a stranger's says nothing about this backing.
    if (compareBytes(served.commitment.operator, operator) !== 0) return undefined;
    if (!stateProvesCommitment(served.snapshots, served.commitment)) return undefined;
    const snapshot = served.snapshots.find((s) => compareBytes(s.name, backing.name) === 0);
    if (snapshot === undefined) return undefined;
    return replayLog(backing, snapshot.opLog);
  } catch {
    return undefined;
  }
}

/**
 * Whether the served state proves this holder held at least `quantity` of this
 * backing as of the operator's LAST witnessed commitment.
 *
 * "Last" is load-bearing rather than decorative: against an older commitment a
 * holder who has since spent the units would still prove the state that shows
 * them.
 *
 * It answers the holding, not the policy: whether a standing demand on the same
 * units blocks redemption is a question for the redemption legs, where the
 * double-payment it would risk actually arises. See DECISIONS.md.
 */
export function provesHolding(
  venue: Venue,
  backing: Backing,
  served: ServedState,
  holder: Uint8Array,
  quantity: bigint,
): boolean {
  try {
    if (!isValidQuantity(quantity)) return false;
    const latest = venue.latestFor(backing.evidence.operator);
    if (latest === undefined) return false;
    if (latest.sequence !== served.commitment.sequence) return false;
    if (compareBytes(latest.root, served.commitment.root) !== 0) return false;

    const replay = replayServedState(backing, served);
    if (replay === undefined) return false;
    return (replay.balances.get(bytesToHex(holder)) ?? 0n) >= quantity;
  } catch {
    return false;
  }
}

/**
 * Whether snapshot redemption is open to this holder for this quantity: the
 * operator is silent past the declared duration, and the last witnessed snapshot
 * proves the holding. Both, or neither — silence without a proved holding
 * redeems nothing, and a proved holding while the operator is answering belongs
 * at the sequencer, where §C3's presentation already handles it.
 */
export function redemptionIsOpen(
  venue: Venue,
  backing: Backing,
  served: ServedState,
  holder: Uint8Array,
  quantity: bigint,
): boolean {
  return isSilent(venue, backing) && provesHolding(venue, backing, served, holder, quantity);
}
