import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { signBacking } from "../src/backing.js";
import { isEquivocation, signCommitment } from "../src/commitment.js";
import { isDishonoured } from "../src/ledger.js";
import { encodeIssuance } from "../src/messages.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
  encodeWithdrawal,
} from "../src/presentation.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// Invariant 21 and §C2: the witnessed clock belongs to the venue, not to any
// operator. "A venue is named together with its finality rule, the depth or
// gadget under which an index counts as witnessed there" — a widely witnessed
// venue, typically a public chain, whose indices advance whether or not any
// particular operator publishes.
//
// Two different indices, deliberately named differently in the code so they
// cannot be conflated again:
//   - a commitment's `sequence` is the operator's own count of its commitments.
//     Equivocation is two different roots signed at one sequence number.
//   - the venue's witnessed index is the clock every deadline is read against.
//
// Read as one, an operator that simply stops publishing freezes every deadline
// in its book: no dishonour is ever reached, and a holder locked by a live
// acceptance can never withdraw. §C2b names that party — "A stalling backer-run
// sequencer publishes on time, and the stall shows only as a spent set that
// stops growing" — and §C2 the reason it matters: "a stall is deniable where a
// dishonour is recorded." Presentation already refuses that trap when it comes
// as a signature; these tests refuse it when it comes as silence.

/** A backer-run sequencer (§C2's cold-start default) holding Alice's 100 units. */
function setup() {
  const venue = new Venue();
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { venue, sequencer, backing };
}

/** Alice presents everything, deadline 10; the backer answers to 10, pays nothing. */
function lockedByAnAcceptance(f: ReturnType<typeof setup>) {
  const { sequencer, backing } = f;
  const demand = {
    backing,
    holder: KEYS.alice,
    quantity: 100n,
    instant: 5n,
    deadline: 10n,
    nonce: sequencer.nextNonce(KEYS.alice, backing),
  };
  sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
  const hash = demandHash(demand);
  const answer = {
    backing,
    demandHash: hash,
    instant: 5n,
    deadline: 10n,
    nonce: sequencer.nextNonce(KEYS.backer, backing),
  };
  sequencer.submitAcceptance(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer));
  return hash;
}

function tryWithdraw(f: ReturnType<typeof setup>, hash: Uint8Array): boolean {
  const op = {
    backing: f.backing,
    demandHash: hash,
    nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
  };
  try {
    f.sequencer.submitWithdrawal(op, ed25519.sign(encodeWithdrawal(op), SECRETS.alice));
    return true;
  } catch {
    return false;
  }
}

describe("invariant 21: the witnessed clock is the venue's, not the operator's", () => {
  it("advances with nobody publishing anything", () => {
    const venue = new Venue();
    expect(venue.witnessedIndex()).toBe(0n);
    venue.advance();
    expect(venue.witnessedIndex()).toBe(1n);
    venue.advance(9n);
    expect(venue.witnessedIndex()).toBe(10n);
  });

  it("a sequencer reads the venue's clock, not its own publications", () => {
    const f = setup();
    expect(f.sequencer.witnessedIndex()).toBe(0n);
    f.venue.advance(7n);
    // Seven indices have been witnessed and the operator has published nothing.
    expect(f.sequencer.witnessedIndex()).toBe(7n);
    expect(f.venue.latestFor(f.sequencer.operator)).toBeUndefined();
  });

  it("an operation is servable before the operator's first commitment", () => {
    // Time exists whether or not this operator has committed, so there is no
    // reason to refuse: the first interval simply has not elapsed yet.
    const f = setup();
    f.venue.advance(5n);
    const demand = {
      backing: f.backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: 0n,
    };
    expect(
      f.sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice)).position,
    ).toBe(1n);
  });

  it("a dark operator cannot freeze a deadline", () => {
    const f = setup();
    f.venue.advance(5n);
    const hash = lockedByAnAcceptance(f);
    f.sequencer.commit();
    const answered = f.sequencer.openDemands(f.backing)[0]!;
    expect(isDishonoured(answered, f.sequencer.witnessedIndex())).toBe(false);

    // The operator now publishes nothing, ever again. The clock does not care.
    f.venue.advance(6n);
    expect(f.sequencer.witnessedIndex()).toBe(11n);
    expect(isDishonoured(f.sequencer.openDemands(f.backing)[0]!, 11n)).toBe(true);
  });

  it("a dark operator cannot hold a holder's claims", () => {
    const f = setup();
    f.venue.advance(5n);
    const hash = lockedByAnAcceptance(f);
    expect(f.sequencer.availableBalance(f.backing, KEYS.alice)).toBe(0n);
    // While the acceptance is live the claims are held, as they should be.
    expect(tryWithdraw(f, hash)).toBe(false);

    // Past it, they are Alice's again — without the operator lifting a finger,
    // because it is not the operator's clock.
    f.venue.advance(6n);
    expect(tryWithdraw(f, hash)).toBe(true);
    expect(f.sequencer.availableBalance(f.backing, KEYS.alice)).toBe(100n);
  });

  it("a dark operator cannot hold a settlement open either", () => {
    // The complement: past the acceptance's own deadline the answer is stale,
    // and the venue's clock is what makes it stale.
    const f = setup();
    f.venue.advance(5n);
    const hash = lockedByAnAcceptance(f);
    f.venue.advance(6n);
    const op = {
      backing: f.backing,
      demandHash: hash,
      nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
    };
    expect(() =>
      f.sequencer.submitRelease(op, ed25519.sign(encodeRelease(op), SECRETS.alice)),
    ).toThrow(/no live acceptance/);
  });
});

describe("§C2: a commitment's sequence is the operator's own count", () => {
  it("is independent of the venue's witnessed index", () => {
    const f = setup();
    f.venue.advance(100n);
    // First commitment ever: sequence 0, at witnessed index 100.
    expect(f.sequencer.commit().sequence).toBe(0n);
    f.venue.advance(50n);
    expect(f.sequencer.commit().sequence).toBe(1n);
    expect(f.sequencer.witnessedIndex()).toBe(150n);
  });

  it("equivocation is still two roots at one sequence, whatever the clock says", () => {
    const f = setup();
    f.venue.advance(20n);
    const honest = f.sequencer.commit();
    const conflicting = signCommitment(
      SECRETS.operator,
      honest.sequence,
      new Uint8Array(32).fill(0xab),
    );
    expect(isEquivocation(honest, conflicting)).toBe(true);
    f.venue.advance(5n);
    // A later commitment at the next sequence is not equivocation, even though
    // the venue has moved on in between.
    expect(isEquivocation(honest, f.sequencer.commit())).toBe(false);
  });

  it("the venue still refuses a sequence that does not extend the operator's history", () => {
    const f = setup();
    const first = f.sequencer.commit();
    f.venue.advance(3n);
    expect(() => f.venue.publish(first)).toThrow(/does not extend/);
  });
});
