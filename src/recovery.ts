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
import type { DemandRecord } from "./ledger.js";
import { compareBytes, isValidQuantity } from "./bytes.js";
import { replayLog } from "./oplog.js";
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

/** Two demand records agree on every field the law fixes. */
function sameDemand(a: DemandRecord, b: DemandRecord): boolean {
  return (
    compareBytes(a.holder, b.holder) === 0 &&
    a.quantity === b.quantity &&
    a.instant === b.instant &&
    a.deadline === b.deadline &&
    a.nonce === b.nonce &&
    a.acceptedDeadline === b.acceptedDeadline
  );
}

/**
 * The one check on served state, and what everything else here rests on: it is
 * the state this backing's operator committed to, and it is a state that could
 * have happened — its operation log replays under the law, and the balances and
 * standing demands it publishes are exactly what that replay leaves behind.
 *
 * Three properties because an operator can lie in three places, and closing any
 * two leaves the third open. Committed-but-inconsistent is the sweep: reassign
 * the balances and conservation still passes, because nothing was destroyed.
 * Consistent-but-unauthorised is the fabricated append: add the transfers you
 * want, and the arithmetic agrees with them. Authorised-but-impossible is the
 * refused release: replay a settlement of a demand the holder had withdrawn, on
 * a signature the holder really made. All three were demonstrated before they
 * were closed.
 *
 * A verifier: the state comes from an operator with a motive, so any malformed
 * field is a failed check rather than a crash.
 */
export function stateIsAuthentic(backing: Backing, served: ServedState): boolean {
  try {
    const operator = backing.evidence.operator;
    // Signed by the operator E names — anyone can sign a valid commitment over
    // any state they like, and a stranger's says nothing about this backing.
    if (compareBytes(served.commitment.operator, operator) !== 0) return false;
    if (!stateProvesCommitment(served.snapshots, served.commitment)) return false;

    const snapshot = served.snapshots.find((s) => compareBytes(s.name, backing.name) === 0);
    if (snapshot === undefined) return false;
    const replay = replayLog(backing, snapshot.opLog);
    if (replay === undefined) return false;

    if (replay.balances.size !== snapshot.balances.length) return false;
    for (const [key, units] of snapshot.balances) {
      if (replay.balances.get(bytesToHex(key)) !== units) return false;
    }

    if (replay.demands.length !== snapshot.demands.length) return false;
    const replayed = new Map(replay.demands.map((d) => [bytesToHex(d.hash), d]));
    for (const record of snapshot.demands) {
      const expected = replayed.get(bytesToHex(record.hash));
      if (expected === undefined || !sameDemand(record, expected)) return false;
    }
    return true;
  } catch {
    return false;
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
    if (!stateIsAuthentic(backing, served)) return false;
    const latest = venue.latestFor(backing.evidence.operator);
    if (latest === undefined) return false;
    if (latest.sequence !== served.commitment.sequence) return false;
    if (compareBytes(latest.root, served.commitment.root) !== 0) return false;

    const snapshot = served.snapshots.find((s) => compareBytes(s.name, backing.name) === 0);
    if (snapshot === undefined) return false;
    const held = snapshot.balances.find(([key]) => compareBytes(key, holder) === 0);
    return held !== undefined && held[1] >= quantity;
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
