import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import {
  encodeCommit,
  encodeLock,
  encodeWithdrawal,
  signCommit,
  type LockOp,
} from "../src/presentation.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// §C3's prepare-decide-commit, generalised to any multi-sequencer transfer.
//
// §C2 poses it and gives two answers: "Extend §C3's prepare-decide-commit to any
// multi-sequencer transfer, at a round trip per payment. Or let payees accept
// partial-and-retry and price it, as card networks do."
//
// **Both are built, and which one is used is the parties' choice per trade.**
// The cheap one is what already existed: independent transfers, each final when
// its own sequencer co-signs, with the receipt as the payer's proof and
// isOverdue as the payee's read on how long finality will take. That covers
// every trade where the two sides have recourse — a grocer will refund, or take
// the rest by other means.
//
// This file is the other branch, for the trade where nobody will make anyone
// whole: **the bundle moves entire or not at all.**
//
// The shape, and why each piece is what it is:
//
//   - **Prepare.** The holder locks at each sequencer. A lock is a reservation,
//     not a transfer, and that is the whole point: invariant 8 makes a transfer
//     irreversible, so handing units over before the outcome is known would
//     destroy §11's "a refusal burns nothing" — the branch §15 prices a holding
//     on. A lock can be taken back; a transfer cannot.
//   - **Commit.** ONE object, signed by the holder over the attempt id, published
//     at a decision venue. §C3: "effective on witnessing rather than delivery, so
//     every sequencer evaluates one predicate against the same object." Delivery
//     is a fact about a message and differs per recipient; witnessing is a fact
//     about the record and is the same for everyone. That is what stops half the
//     bundle committing while the other half aborts.
//   - **No sequencer reads another's backing.** It matches one published object
//     against its own lock. That is why the commit names an attempt rather than
//     a set: knowing who else is in the bundle is the holder's business.
//   - **Abort.** Past the lock's timeout the commit can no longer settle it, and
//     the holder frees it alone.

const TIMEOUT = 50n;

/** Two backings, two operators, one venue they both publish at. */
function setup() {
  const venue = new LocalVenue();
  const mk = (thing: string, operator: Uint8Array) =>
    makeBacking({
      obligor: KEYS.backer,
      payout: { thing, quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator,
        witnessing: { venue: venue.id, interval: 5n },
      },
    });
  const eur = mk("EUR", KEYS.operator);
  const gold = mk("GOLD", KEYS.carol);
  const one = new Sequencer(SECRETS.operator, venue);
  const two = new Sequencer(SECRETS.carol, venue);
  one.register(eur, signBacking(SECRETS.backer, eur));
  two.register(gold, signBacking(SECRETS.backer, gold));
  for (const [sequencer, backing] of [
    [one, eur],
    [two, gold],
  ] as const) {
    const nonce = sequencer.nextNonce(KEYS.backer, backing);
    sequencer.submitIssue(
      { backing, recipient: KEYS.alice, quantity: 200n, nonce },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 200n, nonce), SECRETS.backer),
    );
  }
  return { venue, one, two, eur, gold };
}

const ATTEMPT = new Uint8Array(32).fill(0xa7);

function lockFor(
  sequencer: Sequencer,
  backing: Backing,
  venue: LocalVenue,
  quantity: bigint,
  attempt = ATTEMPT,
  timeout = TIMEOUT,
): LockOp {
  return {
    backing,
    attemptId: attempt,
    holder: KEYS.alice,
    beneficiary: KEYS.bob,
    quantity,
    timeout,
    decisionVenue: venue.id,
    nonce: sequencer.nextNonce(KEYS.alice, backing),
  };
}

/** Alice reserves both halves of the bundle for Bob. */
function prepare(venue: LocalVenue, one: Sequencer, two: Sequencer, eur: Backing, gold: Backing) {
  const eurLock = lockFor(one, eur, venue, 40n);
  const goldLock = lockFor(two, gold, venue, 90n);
  one.submitLock(eurLock, ed25519.sign(encodeLock(eurLock), SECRETS.alice));
  two.submitLock(goldLock, ed25519.sign(encodeLock(goldLock), SECRETS.alice));
  return { eurLock, goldLock };
}

describe("§C3: prepare reserves without moving", () => {
  it("locks at each sequencer, and neither has moved anything", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    expect(one.balance(eur, KEYS.alice)).toBe(200n);
    expect(two.balance(gold, KEYS.alice)).toBe(200n);
    expect(one.availableBalance(eur, KEYS.alice)).toBe(160n);
    expect(two.availableBalance(gold, KEYS.alice)).toBe(110n);
    expect(one.balance(eur, KEYS.bob)).toBe(0n);
  });

  it("a sequencer refuses to prepare against a venue it does not watch", () => {
    // §C3: "A sequencer unwilling to watch it refuses to prepare, which is an
    // abort rather than a fork." Refusing is the safe answer — a fork would be
    // reading the timeout on a clock nobody else reads.
    const { venue, one, eur } = setup();
    const elsewhere = new LocalVenue(new Uint8Array(32).fill(9));
    const lock = lockFor(one, eur, elsewhere, 40n);
    expect(() => one.submitLock(lock, ed25519.sign(encodeLock(lock), SECRETS.alice))).toThrow(
      SequencerError,
    );
  });
});

describe("§C3: one witnessed object commits the whole bundle", () => {
  it("each sequencer settles its own half against the same object", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);

    // ONE signature, published once. Neither sequencer hears from the other.
    venue.advance(3n);
    venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));

    one.settle(eur, ATTEMPT);
    two.settle(gold, ATTEMPT);

    expect(one.balance(eur, KEYS.bob)).toBe(40n);
    expect(two.balance(gold, KEYS.bob)).toBe(90n);
    expect(one.balance(eur, KEYS.alice)).toBe(160n);
    expect(two.balance(gold, KEYS.alice)).toBe(110n);
  });

  it("and the object is the same bytes for every backing in the bundle", () => {
    // Deliberately not naming a backing: the same signed object has to be valid
    // in every log in the set, which is what makes it one object rather than n.
    const commit = signCommit(SECRETS.alice, ATTEMPT);
    expect(encodeCommit(commit)).toEqual(encodeCommit(signCommit(SECRETS.alice, ATTEMPT)));
    expect(encodeCommit(commit)).toHaveLength(32 + 64);
  });

  it("refuses to settle before the commit is witnessed", () => {
    // "Publication is not optional, since a release nobody witnessed did not
    // happen." A commit held privately settles nothing.
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    expect(() => one.settle(eur, ATTEMPT)).toThrow(SequencerError);
    expect(one.balance(eur, KEYS.bob)).toBe(0n);
  });

  it("refuses a commit signed by anyone but the holder who locked", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    venue.advance(3n);
    venue.publishCommit(signCommit(SECRETS.mallory, ATTEMPT));
    expect(() => one.settle(eur, ATTEMPT)).toThrow();
    expect(one.balance(eur, KEYS.bob)).toBe(0n);
  });

  it("refuses to settle a commit witnessed past the timeout", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    venue.advance(TIMEOUT + 1n);
    venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    expect(() => one.settle(eur, ATTEMPT)).toThrow();
    expect(one.balance(eur, KEYS.bob)).toBe(0n);
  });

  it("the earliest witnessing is the one that counts", () => {
    // Published twice, once in time and once late: the attempt committed when
    // the record first showed it, and a later copy cannot un-commit it.
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    venue.advance(3n);
    venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    venue.advance(TIMEOUT + 10n);
    venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    one.settle(eur, ATTEMPT);
    expect(one.balance(eur, KEYS.bob)).toBe(40n);
  });
});

describe("§C3: abort, and what each side can do alone", () => {
  it("past the timeout the holder frees its own reservation", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    venue.advance(TIMEOUT + 1n);
    const abort = { backing: eur, demandHash: ATTEMPT, nonce: one.nextNonce(KEYS.alice, eur) };
    one.submitWithdrawal(abort, ed25519.sign(encodeWithdrawal(abort), SECRETS.alice));
    expect(one.availableBalance(eur, KEYS.alice)).toBe(200n);
    expect(one.balance(eur, KEYS.bob)).toBe(0n);
  });

  it("and a freed half cannot be settled afterwards", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    venue.advance(TIMEOUT + 1n);
    const abort = { backing: eur, demandHash: ATTEMPT, nonce: one.nextNonce(KEYS.alice, eur) };
    one.submitWithdrawal(abort, ed25519.sign(encodeWithdrawal(abort), SECRETS.alice));
    venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    expect(() => one.settle(eur, ATTEMPT)).toThrow();
  });

  it("the reserved units cannot be spent while the attempt stands", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    const nonce = one.nextNonce(KEYS.alice, eur);
    expect(() =>
      one.submitTransfer(
        { backing: eur, from: KEYS.alice, to: KEYS.carol, quantity: 170n, nonce },
        ed25519.sign(
          encodeTransferMessage(eur.name, KEYS.alice, KEYS.carol, 170n, nonce),
          SECRETS.alice,
        ),
      ),
    ).toThrow(/insufficient/);
  });

  it("but everything outside the bundle keeps moving", () => {
    // The cheap path is untouched by any of this: a transfer of units no lock
    // reaches is one sequencer co-signing, as it always was.
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    const nonce = one.nextNonce(KEYS.alice, eur);
    one.submitTransfer(
      { backing: eur, from: KEYS.alice, to: KEYS.carol, quantity: 160n, nonce },
      ed25519.sign(
        encodeTransferMessage(eur.name, KEYS.alice, KEYS.carol, 160n, nonce),
        SECRETS.alice,
      ),
    );
    expect(one.balance(eur, KEYS.carol)).toBe(160n);
  });
});

describe("§C3: half a bundle is still not a bundle", () => {
  it("one half committing does not move the other", () => {
    // The failure the whole mechanism exists to prevent, from the other side:
    // settling at one sequencer tells the other nothing, so nothing there moves
    // until it reads the same object for itself.
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    venue.advance(3n);
    venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    one.settle(eur, ATTEMPT);
    expect(one.balance(eur, KEYS.bob)).toBe(40n);
    expect(two.balance(gold, KEYS.bob)).toBe(0n);
    // And the second half is still there to be settled, on the same object.
    two.settle(gold, ATTEMPT);
    expect(two.balance(gold, KEYS.bob)).toBe(90n);
  });

  it("settling twice is idempotent, not a second payment", () => {
    const { venue, one, two, eur, gold } = setup();
    prepare(venue, one, two, eur, gold);
    venue.advance(3n);
    venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    const first = one.settle(eur, ATTEMPT);
    const again = one.settle(eur, ATTEMPT);
    expect(again.opHash).toEqual(first.opHash);
    expect(one.balance(eur, KEYS.bob)).toBe(40n);
  });
});
