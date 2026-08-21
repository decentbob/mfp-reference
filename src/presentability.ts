// Presentability (invariant 13): a holding is presentable at b for q iff it
// contains q units of b and q·cᵢ units of each (bᵢ, cᵢ) in R(b).
//
// Units, never claims, so the answer cannot depend on packing. One level, no
// traversal: a reliance target's own reliance is that target's presentation
// problem (invariant 17 keeps the unaccompanied claim inert, never invalid).
//
// **presentableFor is the condition on a HOLDING**, and nothing in src calls it:
// the sequencer enforces the same thing per leg when a demand is filed (slice
// 22), and pre-checking it there would re-check what the locks check anyway.
// accompanimentOf below is the other question — whether a demand already filed
// really has its legs reserved — which is read out of a committed state rather
// than out of a holding. See DECISIONS.md.

import { bytesToHex } from "@noble/hashes/utils.js";
import { paysInClaims, backingName, type Backing } from "./backing.js";
import { compareBytes } from "./bytes.js";
import { type Terms } from "./closure.js";
import { type ServedState } from "./commitment.js";
import { replayServedState } from "./recovery.js";
import { answering, type Venue } from "./venue.js";

/** Units held against a backing name. Unknown names hold zero. */
export type HoldingView = (name: Uint8Array) => bigint;

export function presentableFor(view: HoldingView, backing: Backing, quantity: bigint): boolean {
  if (quantity < 1n) return false;
  if (view(backingName(backing)) < quantity) return false;
  for (const entry of backing.reliance) {
    if (view(entry.target) < quantity * entry.count) return false;
  }
  return true;
}

/**
 * Whether a standing demand's reliance legs are actually reserved for it
 * (invariant 13), read out of a committed state.
 *
 *   - `accompanied`  every leg holds a lock for this demand, for q·cᵢ units,
 *                    committing the demanding holder and paying the demanded
 *                    backing's obligor.
 *   - `unaccompanied` one does not. Invariant 13's condition is not met, so a
 *                    backer answering this demand would take in a set it cannot
 *                    unwind.
 *   - `unreadable`   this reader cannot establish either: the state is not this
 *                    backing's operator's, the demand is not standing in it, or
 *                    the legs' own terms are not to hand.
 *
 * **Why it exists.** The law is per backing: `applyEntry` sees one state, and a
 * leg's q·cᵢ units live in another, so a log carrying an unaccompanied demand
 * replays perfectly well and `stateIsAuthentic` — which folds one backing — says
 * yes. Slice 22 enforces the set at the sequencer, where it is filed; this is the
 * same condition read afterwards, by somebody who did not have to trust the
 * operator.
 *
 * **The backer is who asks.** §C3 makes the acceptance the backer's own
 * signature, and it is the party that loses by an unaccompanied demand, so it is
 * the one with both the motive and the moment to check.
 *
 * **The terms come from a resolver**, because R names its targets by hash, and
 * every answer is checked against the name asked for — the same rule closure.ts
 * follows, and for the same reason: what a store hands back is never taken on
 * its word.
 *
 * A verifier: the served state comes from an operator with a motive, so anything
 * malformed is a question that cannot be answered rather than a throw. A venue
 * declining to answer still propagates (venue.ts).
 */
export type Accompaniment = "accompanied" | "unaccompanied" | "unreadable";

export function accompanimentOf(
  backing: Backing,
  venue: Venue,
  terms: Terms,
  served: ServedState,
  demandHash: Uint8Array,
): Accompaniment {
  return answering(() => {
    const head = replayServedState(backing, venue, served);
    if (head === undefined) return "unreadable";
    const demand = head.demands.get(bytesToHex(demandHash));
    if (demand === undefined) return "unreadable";

    for (const entry of backing.reliance) {
      const leg = terms(entry.target);
      if (leg === undefined) return "unreadable";
      if (compareBytes(backingName(leg), entry.target) !== 0) return "unreadable";
      const legState = replayServedState(leg, venue, served);
      if (legState === undefined) return "unreadable";

      const lock = legState.locks.get(bytesToHex(demandHash));
      if (lock === undefined) return "unaccompanied";
      // Invariant 13's arithmetic, checked rather than assumed: q units of the
      // claim need q·cᵢ of this leg.
      if (lock.quantity !== demand.quantity * entry.count) return "unaccompanied";
      // The demanding holder's own units, and going where the set goes.
      if (compareBytes(lock.holder, demand.holder) !== 0) return "unaccompanied";
      if (compareBytes(lock.beneficiary, backing.obligor) !== 0) return "unaccompanied";
    }
    return "accompanied";
  }, "unreadable");
}

/**
 * Whether a standing demand's payout is reserved inside the claim layer: the
 * backer's lock on the backing P names, q times per-unit units, to the demand
 * holder, convertible by the holder alone. The holder asks before it releases,
 * as the backer asks `accompanimentOf` before it accepts — the two sides of
 * §C3's "neither party can write the other's outcome".
 *
 *   - `reserved`     the paying lock stands with the set's terms.
 *   - `unreserved`   the demand stands and the payout does not.
 *   - `outside`      P pays outside the claim layer; nothing here to reserve.
 *   - `unreadable`   the served state does not let the question be answered.
 */
export type PayoutStanding = "reserved" | "unreserved" | "outside" | "unreadable";

export function payoutOf(
  backing: Backing,
  venue: Venue,
  terms: Terms,
  served: ServedState,
  demandHash: Uint8Array,
): PayoutStanding {
  return answering(() => {
    if (!paysInClaims(backing.payout)) return "outside";
    const head = replayServedState(backing, venue, served);
    if (head === undefined) return "unreadable";
    const demand = head.demands.get(bytesToHex(demandHash));
    if (demand === undefined) return "unreadable";
    const paying = terms(backing.payout.backing);
    if (paying === undefined) return "unreadable";
    if (compareBytes(backingName(paying), backing.payout.backing) !== 0) return "unreadable";
    const payingState = replayServedState(paying, venue, served);
    if (payingState === undefined) return "unreadable";
    const lock = payingState.locks.get(bytesToHex(demandHash));
    if (lock === undefined) return "unreserved";
    if (lock.quantity !== demand.quantity * backing.payout.perUnit) return "unreserved";
    if (compareBytes(lock.holder, backing.obligor) !== 0) return "unreserved";
    if (compareBytes(lock.beneficiary, demand.holder) !== 0) return "unreserved";
    if (lock.parties.length !== 1 || compareBytes(lock.parties[0] as Uint8Array, demand.holder) !== 0) {
      return "unreserved";
    }
    return "reserved";
  }, "unreadable");
}
