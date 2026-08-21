import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { replayLog } from "../src/ledger.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeLock,
  encodeRelease,
  encodeWithdrawal,
  type DemandOp,
  type LockOp,
  NO_DECISION_VENUE,
} from "../src/presentation.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// Invariant 13's other half, and the first presentation that moves a leg.
//
//   "A holding is presentable at *b* for *q* if and only if it contains *q*
//   units of *b* and *q·cᵢ* units of each *(bᵢ, cᵢ)* in R(b)."
//
// §C3 licenses doing it in one act here: "Single-phase wherever every lock in
// the set can be taken in one atomically signed decision: R empty and the payout
// settling outside the claim layer, **or the whole set and the paying leg inside
// one operator**." So this operator takes the demand and every lock together, or
// refuses the lot. Two-phase — a decision venue and a lock timeout — is what a
// set spanning operators needs, and is not built.
//
// **A leg is reserved in the leg's own log**, signed by the holder whose units
// it commits, because those units are that backing's and every backing has to
// stay replayable on its own — which provesHolding, the redemption walk and
// committedOutstanding all rest on. Deriving the leg locks from the demand plus
// R(b) instead would mean no backing could be checked alone.
//
// **The beneficiary is the DEMANDED backing's obligor**, not the leg's: the
// backer of *b* takes in the whole set and may then present at *bᵢ* itself,
// which is what reliance is for. Signed into the lock rather than supplied at
// release, or the operator would choose where the accompaniment goes.

const DEADLINE = 100n;
const LOCK_TIMEOUT = 90n;

function setup() {
  const venue = new LocalVenue();
  const mk = (thing: string, reliance: { target: Uint8Array; count: bigint }[] = []) =>
    makeBacking({
      obligor: KEYS.backer,
      payout: { thing, quantumExponent: -2, perUnit: 100n },
      reliance,
      evidence: { setting: "transparent", operator: KEYS.operator },
    });
  const gold = mk("GOLD");
  const eur = mk("EUR", [{ target: gold.name, count: 2n }]);
  const sequencer = new Sequencer(SECRETS.operator, venue);
  for (const backing of [gold, eur]) {
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
  }
  const issue = (backing: Backing, quantity: bigint) => {
    const nonce = sequencer.nextNonce(KEYS.backer, backing);
    sequencer.submitIssue(
      { backing, recipient: KEYS.alice, quantity, nonce },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, quantity, nonce), SECRETS.backer),
    );
  };
  issue(eur, 100n);
  issue(gold, 200n);
  return { venue, sequencer, eur, gold };
}

/** Alice's demand for `quantity` of eur, and the lock its one leg needs. */
function present(
  sequencer: Sequencer,
  venue: LocalVenue,
  eur: Backing,
  gold: Backing,
  quantity: bigint,
) {
  const demand: DemandOp = {
    backing: eur,
    holder: KEYS.alice,
    quantity,
    instant: 0n,
    deadline: DEADLINE,
    nonce: sequencer.nextNonce(KEYS.alice, eur),
  };
  const hash = demandHash(demand);
  const lock: LockOp = {
    backing: gold,
    attemptId: hash,
    holder: KEYS.alice,
    beneficiary: KEYS.backer,
    quantity: quantity * 2n,
    timeout: LOCK_TIMEOUT,
    decisionVenue: NO_DECISION_VENUE,
    parties: [KEYS.alice],
    nonce: sequencer.nextNonce(KEYS.alice, gold),
  };
  return {
    demand,
    hash,
    lock,
    signature: ed25519.sign(encodeDemand(demand), SECRETS.alice),
    legSignature: ed25519.sign(encodeLock(lock), SECRETS.alice),
  };
}

/** File it, legs and all. */
function file(
  sequencer: Sequencer,
  venue: LocalVenue,
  eur: Backing,
  gold: Backing,
  quantity: bigint,
) {
  const p = present(sequencer, venue, eur, gold, quantity);
  const receipt = sequencer.submitDemand(p.demand, p.signature, [
    { op: p.lock, signature: p.legSignature },
  ]);
  return { ...p, receipt };
}

/** The backer answers, so a release has something to settle against. */
function accept(sequencer: Sequencer, eur: Backing, hash: Uint8Array, deadline = 50n) {
  const op = {
    backing: eur,
    demandHash: hash,
    instant: 0n,
    deadline,
    nonce: sequencer.nextNonce(KEYS.backer, eur),
  };
  return sequencer.submitAcceptance(op, ed25519.sign(encodeAcceptance(op), SECRETS.backer));
}

/** The holder's release, on the demand and on its one leg. */
function release(sequencer: Sequencer, eur: Backing, gold: Backing, hash: Uint8Array) {
  const head = { backing: eur, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, eur) };
  const leg = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
  return sequencer.submitRelease(head, ed25519.sign(encodeRelease(head), SECRETS.alice), [
    { op: leg, signature: ed25519.sign(encodeRelease(leg), SECRETS.alice) },
  ]);
}

describe("invariant 13: a demand reserves q·cᵢ of every leg", () => {
  it("locks the leg in the leg's own ledger", () => {
    const { venue, sequencer, eur, gold } = setup();
    file(sequencer, venue, eur, gold, 40n);
    // 40 EUR demanded, c = 2, so 80 GOLD are spoken for. Held, not moved:
    // presentation destroys nothing and the set has not settled.
    expect(sequencer.balance(gold, KEYS.alice)).toBe(200n);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(120n);
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(60n);
  });

  it("and the lock is an entry in that leg's log, so the leg replays alone", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    const log = sequencer.opLog(gold);
    const lock = log[log.length - 1];
    expect(lock?.kind).toBe("lock");
    expect(replayLog(gold, log)).toBeDefined();
    if (lock?.kind === "lock") {
      expect(lock.attemptId).toEqual(hash);
      expect(lock.quantity).toBe(80n);
      expect(lock.beneficiary).toEqual(KEYS.backer);
    }
  });

  it("the locked units cannot be spent while the demand stands", () => {
    const { venue, sequencer, eur, gold } = setup();
    file(sequencer, venue, eur, gold, 40n);
    const nonce = sequencer.nextNonce(KEYS.alice, gold);
    const move = { backing: gold, from: KEYS.alice, to: KEYS.bob, quantity: 130n, nonce };
    expect(() =>
      sequencer.submitTransfer(
        move,
        ed25519.sign(
          encodeTransferMessage(gold.name, KEYS.alice, KEYS.bob, 130n, nonce),
          SECRETS.alice,
        ),
      ),
    ).toThrow(/insufficient/);
  });

  it("but the units the lock does not reach still move", () => {
    const { venue, sequencer, eur, gold } = setup();
    file(sequencer, venue, eur, gold, 40n);
    const nonce = sequencer.nextNonce(KEYS.alice, gold);
    const move = { backing: gold, from: KEYS.alice, to: KEYS.bob, quantity: 120n, nonce };
    sequencer.submitTransfer(
      move,
      ed25519.sign(
        encodeTransferMessage(gold.name, KEYS.alice, KEYS.bob, 120n, nonce),
        SECRETS.alice,
      ),
    );
    expect(sequencer.balance(gold, KEYS.bob)).toBe(120n);
  });
});

describe("§C3: the set settles together, or ends together", () => {
  it("release moves the claims and the accompaniment to the same obligor", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    accept(sequencer, eur, hash);
    release(sequencer, eur, gold, hash);

    // The backer of EUR took in the set: 40 EUR and the 80 GOLD that must
    // accompany them. Presentation destroys nothing (invariant 10).
    expect(sequencer.balance(eur, KEYS.backer)).toBe(40n);
    expect(sequencer.balance(gold, KEYS.backer)).toBe(80n);
    expect(sequencer.balance(eur, KEYS.alice)).toBe(60n);
    expect(sequencer.balance(gold, KEYS.alice)).toBe(120n);
    expect(sequencer.outstanding(eur)).toBe(100n);
    expect(sequencer.outstanding(gold)).toBe(200n);
  });

  it("withdrawal frees the accompaniment and moves nothing", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    // Since 24c a lock is withdrawable only past its timeout (c3-lock-timeout):
    // before it, the reservation is the holder's own declared commitment.
    venue.advance(LOCK_TIMEOUT + 1n);
    const head = { backing: eur, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, eur) };
    const leg = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
    sequencer.submitWithdrawal(head, ed25519.sign(encodeWithdrawal(head), SECRETS.alice), [
      { op: leg, signature: ed25519.sign(encodeWithdrawal(leg), SECRETS.alice) },
    ]);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(200n);
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(100n);
    expect(sequencer.balance(gold, KEYS.backer)).toBe(0n);
  });

  it("two demands lock cumulatively, and each frees its own", () => {
    const { venue, sequencer, eur, gold } = setup();
    const first = file(sequencer, venue, eur, gold, 30n);
    const second = file(sequencer, venue, eur, gold, 20n);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(200n - 60n - 40n);

    // Since 24c a lock is withdrawable only past its timeout (c3-lock-timeout):
    // before it, the reservation is the holder's own declared commitment.
    venue.advance(LOCK_TIMEOUT + 1n);
    const head = {
      backing: eur,
      demandHash: first.hash,
      nonce: sequencer.nextNonce(KEYS.alice, eur),
    };
    const leg = {
      backing: gold,
      demandHash: first.hash,
      nonce: sequencer.nextNonce(KEYS.alice, gold),
    };
    sequencer.submitWithdrawal(head, ed25519.sign(encodeWithdrawal(head), SECRETS.alice), [
      { op: leg, signature: ed25519.sign(encodeWithdrawal(leg), SECRETS.alice) },
    ]);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(200n - 40n);
    expect(second.hash).not.toEqual(first.hash);
  });
});

describe("§C3: one atomically signed decision, or none of it", () => {
  it("a holder short on the leg files nothing at all", () => {
    // The whole point of taking the set together. A demand standing without its
    // accompaniment committed would hand a backer a claim it cannot unwind.
    const { venue, sequencer, eur, gold } = setup();
    // Move the gold away first, so 40 EUR cannot be accompanied.
    const nonce = sequencer.nextNonce(KEYS.alice, gold);
    sequencer.submitTransfer(
      { backing: gold, from: KEYS.alice, to: KEYS.bob, quantity: 150n, nonce },
      ed25519.sign(
        encodeTransferMessage(gold.name, KEYS.alice, KEYS.bob, 150n, nonce),
        SECRETS.alice,
      ),
    );
    const p = present(sequencer, venue, eur, gold, 40n);
    expect(() =>
      sequencer.submitDemand(p.demand, p.signature, [{ op: p.lock, signature: p.legSignature }]),
    ).toThrow(/insufficient/);
    expect(sequencer.openDemands(eur)).toHaveLength(0);
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(100n);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(50n);
  });

  it("refuses a demand whose legs are not supplied", () => {
    const { venue, sequencer, eur, gold } = setup();
    const p = present(sequencer, venue, eur, gold, 40n);
    expect(() => sequencer.submitDemand(p.demand, p.signature)).toThrow(SequencerError);
    expect(sequencer.openDemands(eur)).toHaveLength(0);
  });

  it("refuses a lock that does not cover q·c units", () => {
    const { venue, sequencer, eur, gold } = setup();
    const p = present(sequencer, venue, eur, gold, 40n);
    const short: LockOp = { ...p.lock, quantity: 79n };
    expect(() =>
      sequencer.submitDemand(p.demand, p.signature, [
        { op: short, signature: ed25519.sign(encodeLock(short), SECRETS.alice) },
      ]),
    ).toThrow(/quantity the set needs/);
  });

  it("refuses a lock that pays anyone but the demanded backing's obligor", () => {
    // Otherwise the accompaniment goes somewhere the backer of EUR cannot
    // present it, and the set is worthless to the party taking it in.
    const { venue, sequencer, eur, gold } = setup();
    const p = present(sequencer, venue, eur, gold, 40n);
    const elsewhere: LockOp = { ...p.lock, beneficiary: KEYS.mallory };
    expect(() =>
      sequencer.submitDemand(p.demand, p.signature, [
        { op: elsewhere, signature: ed25519.sign(encodeLock(elsewhere), SECRETS.alice) },
      ]),
    ).toThrow(/party the set names/);
  });

  it("refuses a lock naming another demand", () => {
    const { venue, sequencer, eur, gold } = setup();
    const p = present(sequencer, venue, eur, gold, 40n);
    const other: LockOp = { ...p.lock, attemptId: new Uint8Array(32).fill(9) };
    expect(() =>
      sequencer.submitDemand(p.demand, p.signature, [
        { op: other, signature: ed25519.sign(encodeLock(other), SECRETS.alice) },
      ]),
    ).toThrow(/name the demand/);
  });

  it("refuses a lock committing somebody else's units", () => {
    const { venue, sequencer, eur, gold } = setup();
    const p = present(sequencer, venue, eur, gold, 40n);
    const bobs: LockOp = { ...p.lock, holder: KEYS.bob };
    expect(() =>
      sequencer.submitDemand(p.demand, p.signature, [
        { op: bobs, signature: ed25519.sign(encodeLock(bobs), SECRETS.bob) },
      ]),
    ).toThrow(/party the set names as its holder/);
  });

  it("refuses a lock on a backing that is not a leg", () => {
    const { venue, sequencer, eur, gold } = setup();
    const p = present(sequencer, venue, eur, gold, 40n);
    const wrong: LockOp = { ...p.lock, backing: eur };
    expect(() =>
      sequencer.submitDemand(p.demand, p.signature, [
        { op: wrong, signature: ed25519.sign(encodeLock(wrong), SECRETS.alice) },
      ]),
    ).toThrow(SequencerError);
  });

  it("a backing with no reliance still takes a demand with no legs", () => {
    const { venue, sequencer, gold } = setup();
    const op: DemandOp = {
      backing: gold,
      holder: KEYS.alice,
      quantity: 10n,
      instant: 0n,
      deadline: DEADLINE,
      nonce: sequencer.nextNonce(KEYS.alice, gold),
    };
    sequencer.submitDemand(op, ed25519.sign(encodeDemand(op), SECRETS.alice));
    expect(sequencer.openDemands(gold)).toHaveLength(1);
  });
});

describe("what the law alone does not settle", () => {
  it("a served state can carry a demand whose legs were never locked", () => {
    // This was an OPEN test: the law is per backing, so a log carrying an
    // unaccompanied demand replays and stateIsAuthentic — which folds one
    // backing — says yes. It still does, and that is correct: whether the legs
    // are reserved is a fact about the SET, spread over several backings.
    //
    // What closed is that nobody could read it. accompanimentOf
    // (invariant-13.accompaniment) answers it across the served state, where
    // every backing this operator serves already is, and the backer asks it
    // before signing an acceptance — the party that loses by an unaccompanied
    // demand, at the moment it can still refuse.
    const { venue, sequencer, eur } = setup();
    const op: DemandOp = {
      backing: eur,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 0n,
      deadline: DEADLINE,
      nonce: sequencer.nextNonce(KEYS.alice, eur),
    };
    const entry = {
      ...op,
      kind: "demand" as const,
      position: sequencer.opLog(eur).length,
      signature: ed25519.sign(encodeDemand(op), SECRETS.alice),
    };
    expect(replayLog(eur, [...sequencer.opLog(eur), entry])).toBeDefined();
    expect(() => sequencer.submitDemand(op, entry.signature)).toThrow(SequencerError);
  });
});

describe("§C3: the set's shape is read where it settles, not only where it is filed", () => {
  // Found reviewing 24c. Since 24b a lock can be created by submitLock with any
  // terms under any attempt id — a standing demand's hash included. A head
  // release used to check only that each leg HELD a lock, so a holder could
  // withdraw a leg past its timeout, relock one unit to a friend under the same
  // hash, and settle the head against the backer's still-live acceptance: 40 EUR
  // to the backer with none of the 80 GOLD that must accompany them.
  it("a head release checks that each leg's lock carries the set's terms", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    accept(sequencer, eur, hash, DEADLINE);
    venue.advance(LOCK_TIMEOUT + 1n);
    const legOut = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
    sequencer.submitWithdrawal(legOut, ed25519.sign(encodeWithdrawal(legOut), SECRETS.alice));
    const junk: LockOp = {
      backing: gold,
      attemptId: hash,
      holder: KEYS.alice,
      beneficiary: KEYS.mallory,
      quantity: 1n,
      timeout: 200n,
      decisionVenue: venue.id,
      parties: [KEYS.alice],
      nonce: sequencer.nextNonce(KEYS.alice, gold),
    };
    // Since the review of slice 26 the relock itself is refused at the gate: a demand's
    // hash is its set's, and a lock naming a venue under it is a squat. The release
    // then has no leg to settle and the set is refused whole.
    expect(() => sequencer.submitLock(junk, ed25519.sign(encodeLock(junk), SECRETS.alice))).toThrow(/standing demand/);
    expect(() => release(sequencer, eur, gold, hash)).toThrow();
    expect(sequencer.balance(eur, KEYS.backer)).toBe(0n);
    expect(sequencer.balance(gold, KEYS.mallory)).toBe(0n);
  });

  it("a head whose leg was withdrawn alone can still be withdrawn", () => {
    // A withdrawal takes the legs that still stand; demanding one per entry in
    // R(b) left this head with no exit short of relocking. Same shape for a
    // bundle lock on a backing that itself has reliance, below.
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    venue.advance(LOCK_TIMEOUT + 1n);
    const legOut = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
    sequencer.submitWithdrawal(legOut, ed25519.sign(encodeWithdrawal(legOut), SECRETS.alice));
    const head = { backing: eur, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, eur) };
    sequencer.submitWithdrawal(head, ed25519.sign(encodeWithdrawal(head), SECRETS.alice));
    expect(sequencer.openDemands(eur)).toHaveLength(0);
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(100n);
  });

  it("a bundle lock on a backing with reliance of its own is withdrawable past its timeout", () => {
    const { venue, sequencer, eur } = setup();
    const X = new Uint8Array(32).fill(0x11);
    const lock: LockOp = {
      backing: eur,
      attemptId: X,
      holder: KEYS.alice,
      beneficiary: KEYS.bob,
      quantity: 40n,
      timeout: 10n,
      decisionVenue: venue.id,
      parties: [KEYS.alice],
      nonce: sequencer.nextNonce(KEYS.alice, eur),
    };
    sequencer.submitLock(lock, ed25519.sign(encodeLock(lock), SECRETS.alice));
    venue.advance(11n);
    const out = { backing: eur, demandHash: X, nonce: sequencer.nextNonce(KEYS.alice, eur) };
    sequencer.submitWithdrawal(out, ed25519.sign(encodeWithdrawal(out), SECRETS.alice));
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(100n);
  });
});

describe("§C3: a stranger's lock under a demand's hash is a squat, not a leg", () => {
  // Found reviewing 24c, twice. Locks are keyed by attempt id alone, and the law
  // resolved a release or withdrawal lock-first, so one unit locked under a
  // standing demand's hash by anyone could hijack the head's own exits.
  it("on the demanded backing the law refuses it: a lock and a demand never share a hash", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    const mallory = sequencer.nextNonce(KEYS.backer, eur);
    sequencer.submitIssue(
      { backing: eur, recipient: KEYS.mallory, quantity: 5n, nonce: mallory },
      ed25519.sign(encodeIssuanceMessage(eur.name, KEYS.mallory, 5n, mallory), SECRETS.backer),
    );
    const squat: LockOp = {
      backing: eur,
      attemptId: hash,
      holder: KEYS.mallory,
      beneficiary: KEYS.mallory,
      quantity: 1n,
      timeout: 10_000n,
      decisionVenue: venue.id,
      parties: [KEYS.mallory],
      nonce: sequencer.nextNonce(KEYS.mallory, eur),
    };
    expect(() => sequencer.submitLock(squat, ed25519.sign(encodeLock(squat), SECRETS.mallory))).toThrow(
      /standing demand/,
    );
    // And the head's exits are its own: the set still withdraws.
    venue.advance(LOCK_TIMEOUT + 1n);
    const head = { backing: eur, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, eur) };
    const leg = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
    sequencer.submitWithdrawal(head, ed25519.sign(encodeWithdrawal(head), SECRETS.alice), [
      { op: leg, signature: ed25519.sign(encodeWithdrawal(leg), SECRETS.alice) },
    ]);
    expect(sequencer.openDemands(eur)).toHaveLength(0);
  });

  it("on a leg's backing it does not count as a leg: the head still withdraws alone", () => {
    // After the holder withdrew her expired leg, a stranger locks one unit under
    // the hash there. Standing legs are the DEMAND HOLDER'S, so the head's
    // withdrawal names none; the squat stays the stranger's own reservation.
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    venue.advance(LOCK_TIMEOUT + 1n);
    const legOut = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
    sequencer.submitWithdrawal(legOut, ed25519.sign(encodeWithdrawal(legOut), SECRETS.alice));
    const mallory = sequencer.nextNonce(KEYS.backer, gold);
    sequencer.submitIssue(
      { backing: gold, recipient: KEYS.mallory, quantity: 5n, nonce: mallory },
      ed25519.sign(encodeIssuanceMessage(gold.name, KEYS.mallory, 5n, mallory), SECRETS.backer),
    );
    const squat: LockOp = {
      backing: gold,
      attemptId: hash,
      holder: KEYS.mallory,
      beneficiary: KEYS.mallory,
      quantity: 1n,
      timeout: 10_000n,
      decisionVenue: venue.id,
      parties: [KEYS.mallory],
      nonce: sequencer.nextNonce(KEYS.mallory, gold),
    };
    // Refused at the gate since the review of slice 26 (a demand's hash is its set's);
    // and had it stood, standing legs are the demand holder's own, so the head
    // withdraws alone either way.
    expect(() => sequencer.submitLock(squat, ed25519.sign(encodeLock(squat), SECRETS.mallory))).toThrow(/standing demand/);
    const head = { backing: eur, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, eur) };
    sequencer.submitWithdrawal(head, ed25519.sign(encodeWithdrawal(head), SECRETS.alice));
    expect(sequencer.openDemands(eur)).toHaveLength(0);
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(100n);
    expect(sequencer.availableBalance(gold, KEYS.mallory)).toBe(5n);
  });
});

describe("§C3: a leg is prepared at the same gate as any lock", () => {
  it("a leg naming another decision venue is refused, as a bare lock would be", () => {
    // "A cross-operator prepare names a decision venue... A sequencer unwilling
    // to watch it refuses to prepare." The check lived on submitLock alone and
    // legSet copied the field through (found regression-reviewing 24c); every
    // lock item now passes one gate in submit.
    const { venue, sequencer, eur, gold } = setup();
    const p = present(sequencer, venue, eur, gold, 40n);
    const elsewhere: LockOp = { ...p.lock, decisionVenue: new Uint8Array(32).fill(9) };
    expect(() =>
      sequencer.submitDemand(p.demand, p.signature, [
        { op: elsewhere, signature: ed25519.sign(encodeLock(elsewhere), SECRETS.alice) },
      ]),
    ).toThrow(/decision venue/);
    expect(sequencer.openDemands(eur)).toHaveLength(0);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(200n);
  });
});
