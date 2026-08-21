import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { replayLog } from "../src/ledger.js";
import { snapshotRedemptions } from "../src/recovery.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeLock,
  encodeRelease,
  encodeWithdrawal,
  signCommit,
  type DemandOp,
  type LockOp,
} from "../src/presentation.js";
import { Sequencer } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { advanceWitnessedIndex, KEYS, SECRETS } from "./support.js";

// §C3's fourth step, and the only one slice 22 left out.
//
//   "**Abort.** The **lock timeout** the holder declared in the prepare, itself a
//   witnessed index, unlocks everywhere, and expired locks unlock unilaterally.
//   It is not the demand's deadline: the timeout ends the atomic attempt, the
//   deadline governs evidence, and a demand outlives its locks."
//
// **The timeout gates the release, and never the balances.** That is not a
// softening — it is what keeps a replay exact. Every TIME rule in this ledger
// refuses an action and none moves units, because `applyEntry`'s clock is
// undefined on replay: if an expiring lock silently freed its units, an operator
// that correctly accepted a transfer after the timeout would have a log that no
// verifier could replay, and stateIsAuthentic would call an honest history
// unlawful. The existing demand deadline works the same way — a demand past its
// deadline still holds its units until a withdrawal ends it.
//
// So "unlocks unilaterally" is read as: past the timeout the set can no longer
// settle, so the holder's exit needs nobody's cooperation. Withdrawal is that
// exit -- and since 24c it opens ONLY past the timeout. Before it the lock is
// the holder's own declared commitment, and an exit open there let a holder
// take back one half of a bundle the record had already committed (the last
// block below, and c3-atomic-bundle).

const TIMEOUT = 40n;

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
    const nonce = sequencer.nextNonce(KEYS.backer, backing);
    sequencer.submitIssue(
      { backing, recipient: KEYS.alice, quantity: 200n, nonce },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 200n, nonce), SECRETS.backer),
    );
  }
  return { venue, sequencer, eur, gold };
}

function file(
  sequencer: Sequencer,
  venue: LocalVenue,
  eur: Backing,
  gold: Backing,
  quantity: bigint,
  timeout = TIMEOUT,
) {
  const demand: DemandOp = {
    backing: eur,
    holder: KEYS.alice,
    quantity,
    instant: 0n,
    deadline: 100n,
    nonce: sequencer.nextNonce(KEYS.alice, eur),
  };
  const hash = demandHash(demand);
  const lock: LockOp = {
    backing: gold,
    attemptId: hash,
    holder: KEYS.alice,
    beneficiary: KEYS.backer,
    quantity: quantity * 2n,
    timeout,
    decisionVenue: venue.id,
    parties: [KEYS.alice],
    nonce: sequencer.nextNonce(KEYS.alice, gold),
  };
  sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice), [
    { op: lock, signature: ed25519.sign(encodeLock(lock), SECRETS.alice) },
  ]);
  return { hash, lock };
}

function accept(sequencer: Sequencer, eur: Backing, hash: Uint8Array, deadline = 90n) {
  const op = {
    backing: eur,
    demandHash: hash,
    instant: 0n,
    deadline,
    nonce: sequencer.nextNonce(KEYS.backer, eur),
  };
  sequencer.submitAcceptance(op, ed25519.sign(encodeAcceptance(op), SECRETS.backer));
}

function releaseSet(sequencer: Sequencer, eur: Backing, gold: Backing, hash: Uint8Array) {
  const head = { backing: eur, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, eur) };
  const leg = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
  return sequencer.submitRelease(head, ed25519.sign(encodeRelease(head), SECRETS.alice), [
    { op: leg, signature: ed25519.sign(encodeRelease(leg), SECRETS.alice) },
  ]);
}

function withdrawSet(sequencer: Sequencer, eur: Backing, gold: Backing, hash: Uint8Array) {
  const head = { backing: eur, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, eur) };
  const leg = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
  return sequencer.submitWithdrawal(head, ed25519.sign(encodeWithdrawal(head), SECRETS.alice), [
    { op: leg, signature: ed25519.sign(encodeWithdrawal(leg), SECRETS.alice) },
  ]);
}

describe("§C3: the lock timeout ends the atomic attempt", () => {
  it("settles inside the timeout", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    accept(sequencer, eur, hash);
    venue.advance(TIMEOUT);
    releaseSet(sequencer, eur, gold, hash);
    expect(sequencer.balance(gold, KEYS.backer)).toBe(80n);
  });

  it("and refuses to settle one index past it", () => {
    // "was a valid release witnessed at or before the lock timeout?" — at is
    // inside, one past is not.
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    accept(sequencer, eur, hash);
    venue.advance(TIMEOUT + 1n);
    expect(() => releaseSet(sequencer, eur, gold, hash)).toThrow(/timeout/);
    expect(sequencer.balance(gold, KEYS.backer)).toBe(0n);
  });

  it("refuses a lock whose timeout has already passed", () => {
    const { venue, sequencer, eur, gold } = setup();
    venue.advance(50n);
    expect(() => file(sequencer, venue, eur, gold, 40n, 40n)).toThrow(/timeout/);
    // And one whose timeout IS the current index: strictly ahead, or the attempt
    // has no index to run in (the boundary 24c's review caught moving).
    expect(() => file(sequencer, venue, eur, gold, 40n, 50n)).toThrow(/timeout/);
  });

  it("the demand outlives its locks, and can be relocked", () => {
    // §C3: "the timeout ends the atomic attempt, the deadline governs evidence,
    // and a demand outlives its locks." So an expired attempt is a retry, not a
    // lost demand — the whole point of the timeout being separate.
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    accept(sequencer, eur, hash);
    venue.advance(TIMEOUT + 1n);
    expect(() => releaseSet(sequencer, eur, gold, hash)).toThrow(/timeout/);

    // The demand still stands, and its units are still committed to it.
    expect(sequencer.openDemands(eur)).toHaveLength(1);
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(160n);
  });
});

describe("§C3: an expired lock unlocks unilaterally", () => {
  it("withdrawal frees it with nobody else's cooperation", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    venue.advance(TIMEOUT + 5n);
    withdrawSet(sequencer, eur, gold, hash);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(200n);
    expect(sequencer.balance(gold, KEYS.backer)).toBe(0n);
  });

  it("but the units stay committed until it is withdrawn", () => {
    // The rule that keeps a replay exact: no clock moves a balance. An expiring
    // lock that silently freed its units would make an operator's correct
    // history unreplayable, since applyEntry has no clock on a replay.
    const { venue, sequencer, eur, gold } = setup();
    file(sequencer, venue, eur, gold, 40n);
    venue.advance(TIMEOUT + 5n);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(120n);
    const nonce = sequencer.nextNonce(KEYS.alice, gold);
    expect(() =>
      sequencer.submitTransfer(
        { backing: gold, from: KEYS.alice, to: KEYS.bob, quantity: 130n, nonce },
        ed25519.sign(
          encodeTransferMessage(gold.name, KEYS.alice, KEYS.bob, 130n, nonce),
          SECRETS.alice,
        ),
      ),
    ).toThrow(/insufficient/);
  });

  it("and the whole history still replays after the timeout passes", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    venue.advance(TIMEOUT + 5n);
    withdrawSet(sequencer, eur, gold, hash);
    const nonce = sequencer.nextNonce(KEYS.alice, gold);
    sequencer.submitTransfer(
      { backing: gold, from: KEYS.alice, to: KEYS.bob, quantity: 200n, nonce },
      ed25519.sign(
        encodeTransferMessage(gold.name, KEYS.alice, KEYS.bob, 200n, nonce),
        SECRETS.alice,
      ),
    );
    // The verifier has no clock, and does not need one: every balance here was
    // moved by an operation rather than by time passing.
    expect(replayLog(gold, sequencer.opLog(gold))).toBeDefined();
    expect(replayLog(eur, sequencer.opLog(eur))).toBeDefined();
  });
});

describe("§C2b: the gap path cannot open a reliant presentation", () => {
  it("refuses to adopt a demand on a backing with reliance", () => {
    // Found regression-reviewing this slice, and it reaches back into slice 22.
    // That slice removed applyEntry's refusal of a reliant demand — correctly,
    // since the legs live in other states — and made the sequencer enforce the
    // set. But `adopt` applies gap publications straight to the ledger, so the
    // gap path inherited the relaxed law with nothing in its place: a holder
    // published demand, acceptance and release at the venue while the operator
    // was dark, and settled 40 units to the backer with none of the 80 that must
    // accompany them, keeping the lot. Invariant 13, through the back door.
    //
    // Refused, and refusing is §C2b's own posture: claims "go illiquid rather
    // than dead" while the operator is away. A lock is not a gap leg either
    // (recovery.ts), so there is nothing that could have accompanied it.
    const venue = new LocalVenue();
    const silence = { noCommitmentDuration: 10n, challengeWindow: 5n };
    const mk = (thing: string, reliance: { target: Uint8Array; count: bigint }[] = []) =>
      makeBacking({
        obligor: KEYS.backer,
        payout: { thing, quantumExponent: -2, perUnit: 100n },
        reliance,
        evidence: {
          setting: "transparent",
          operator: KEYS.operator,
          silence,
          witnessing: { venue: venue.id, interval: 5n },
        },
      });
    const gold = mk("GOLD");
    const eur = mk("EUR", [{ target: gold.name, count: 2n }]);
    const sequencer = new Sequencer(SECRETS.operator, venue);
    for (const backing of [gold, eur]) {
      sequencer.register(backing, signBacking(SECRETS.backer, backing));
      const nonce = sequencer.nextNonce(KEYS.backer, backing);
      sequencer.submitIssue(
        { backing, recipient: KEYS.alice, quantity: 200n, nonce },
        ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 200n, nonce), SECRETS.backer),
      );
    }
    sequencer.commit();
    venue.advance(30n);

    const demand: DemandOp = {
      backing: eur,
      holder: KEYS.alice,
      quantity: 40n,
      instant: venue.witnessedIndex(),
      deadline: 200n,
      nonce: 0n,
    };
    const hash = demandHash(demand);
    venue.publishOp(eur.name, {
      kind: "demand",
      holder: demand.holder,
      quantity: demand.quantity,
      instant: demand.instant,
      deadline: demand.deadline,
      nonce: demand.nonce,
      signature: ed25519.sign(encodeDemand(demand), SECRETS.alice),
    });
    venue.advance(1n);
    const answer = {
      backing: eur,
      demandHash: hash,
      instant: demand.instant,
      deadline: 150n,
      nonce: sequencer.nextNonce(KEYS.backer, eur),
    };
    venue.publishOp(eur.name, {
      kind: "acceptance",
      demandHash: hash,
      instant: answer.instant,
      deadline: answer.deadline,
      nonce: answer.nonce,
      signature: ed25519.sign(encodeAcceptance(answer), SECRETS.backer),
    });
    venue.advance(1n);
    const settle = { backing: eur, demandHash: hash, nonce: demand.nonce + 1n };
    venue.publishOp(eur.name, {
      kind: "release",
      demandHash: hash,
      nonce: settle.nonce,
      signature: ed25519.sign(encodeRelease(settle), SECRETS.alice),
    });

    venue.advance(1n);
    sequencer.commit();

    expect(sequencer.balance(eur, KEYS.backer)).toBe(0n);
    expect(sequencer.balance(eur, KEYS.alice)).toBe(200n);
    expect(sequencer.openDemands(eur)).toHaveLength(0);
  });

  it("but a backing with no reliance settles through the gap as before", () => {
    // The guard must be exactly as wide as the reason for it.
    const venue = new LocalVenue();
    const gold = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "GOLD", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
        witnessing: { venue: venue.id, interval: 5n },
      },
    });
    const sequencer = new Sequencer(SECRETS.operator, venue);
    sequencer.register(gold, signBacking(SECRETS.backer, gold));
    const nonce = sequencer.nextNonce(KEYS.backer, gold);
    sequencer.submitIssue(
      { backing: gold, recipient: KEYS.alice, quantity: 200n, nonce },
      ed25519.sign(encodeIssuanceMessage(gold.name, KEYS.alice, 200n, nonce), SECRETS.backer),
    );
    sequencer.commit();
    venue.advance(30n);

    const demand: DemandOp = {
      backing: gold,
      holder: KEYS.alice,
      quantity: 40n,
      instant: venue.witnessedIndex(),
      deadline: 200n,
      nonce: 0n,
    };
    const hash = demandHash(demand);
    venue.publishOp(gold.name, {
      kind: "demand",
      holder: demand.holder,
      quantity: demand.quantity,
      instant: demand.instant,
      deadline: demand.deadline,
      nonce: demand.nonce,
      signature: ed25519.sign(encodeDemand(demand), SECRETS.alice),
    });
    venue.advance(1n);
    const answer = {
      backing: gold,
      demandHash: hash,
      instant: demand.instant,
      deadline: 150n,
      nonce: sequencer.nextNonce(KEYS.backer, gold),
    };
    venue.publishOp(gold.name, {
      kind: "acceptance",
      demandHash: hash,
      instant: answer.instant,
      deadline: answer.deadline,
      nonce: answer.nonce,
      signature: ed25519.sign(encodeAcceptance(answer), SECRETS.backer),
    });
    venue.advance(1n);
    const settle = { backing: gold, demandHash: hash, nonce: 1n };
    venue.publishOp(gold.name, {
      kind: "release",
      demandHash: hash,
      nonce: settle.nonce,
      signature: ed25519.sign(encodeRelease(settle), SECRETS.alice),
    });
    venue.advance(1n);
    sequencer.commit();

    expect(sequencer.balance(gold, KEYS.backer)).toBe(40n);
  });
});

describe("§C3: a lock is withdrawable only past its timeout", () => {
  // Found reviewing 24b. Slice 22 let a set be withdrawn at any index, and the
  // bundle inherited it: a holder freed a lock BEFORE its own timeout, after the
  // commit was witnessed, and one witnessed object then settled at one
  // sequencer and not the other. §C3's abort is "**expired** locks unlock
  // unilaterally". Before that the two exits are complements on the timeout,
  // exactly as release and withdrawal are complements on the acceptance for a
  // demand: at or before it, commit or release; past it, withdrawal; never
  // both, never neither.
  it("refuses a withdrawal at the timeout, which is inside it", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    venue.advance(TIMEOUT);
    expect(() => withdrawSet(sequencer, eur, gold, hash)).toThrow(/expired/);
    // And the whole set stood, the demand with its leg: all or none.
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(120n);
    expect(sequencer.openDemands(eur)).toHaveLength(1);
  });

  it("and allows it one index past", () => {
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, venue, eur, gold, 40n);
    venue.advance(TIMEOUT + 1n);
    withdrawSet(sequencer, eur, gold, hash);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(200n);
    expect(sequencer.openDemands(eur)).toHaveLength(0);
  });
});

/**
 * One backing that can go dark and be adopted from: a silence clause to date
 * the gap, a witnessing venue to read it on. Alice holds 200.
 */
function gapGold() {
  const venue = new LocalVenue();
  const gold = makeBacking({
    obligor: KEYS.backer,
    payout: { thing: "GOLD", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: {
      setting: "transparent",
      operator: KEYS.operator,
      silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
      witnessing: { venue: venue.id, interval: 5n },
    },
  });
  const sequencer = new Sequencer(SECRETS.operator, venue);
  sequencer.register(gold, signBacking(SECRETS.backer, gold));
  const nonce = sequencer.nextNonce(KEYS.backer, gold);
  sequencer.submitIssue(
    { backing: gold, recipient: KEYS.alice, quantity: 200n, nonce },
    ed25519.sign(encodeIssuanceMessage(gold.name, KEYS.alice, 200n, nonce), SECRETS.backer),
  );
  return { venue, gold, sequencer };
}

/** Alice reserves 90 GOLD for Bob under `attempt`, timeout 100, and the operator commits. */
function lockAndCommit(f: ReturnType<typeof gapGold>, attempt: Uint8Array) {
  const lock: LockOp = {
    backing: f.gold,
    attemptId: attempt,
    holder: KEYS.alice,
    beneficiary: KEYS.bob,
    quantity: 90n,
    timeout: 100n,
    decisionVenue: f.venue.id,
    parties: [KEYS.alice],
    nonce: f.sequencer.nextNonce(KEYS.alice, f.gold),
  };
  f.sequencer.submitLock(lock, ed25519.sign(encodeLock(lock), SECRETS.alice));
  const commitment = f.sequencer.commit();
  return { lock, commitment };
}

/** A withdrawal of `attempt`'s lock, published at the venue while the operator is dark. */
function publishWithdrawal(f: ReturnType<typeof gapGold>, attempt: Uint8Array, nonce: bigint) {
  const op = { backing: f.gold, demandHash: attempt, nonce };
  f.venue.publishOp(f.gold.name, {
    kind: "withdrawal",
    demandHash: attempt,
    nonce,
    signature: ed25519.sign(encodeWithdrawal(op), SECRETS.alice),
  });
}

describe("§C3: the gap path reads the same exits, because the rules are the law's and the record's", () => {
  // 24a's lesson: `adopt` applies gap publications straight to the law, so a
  // rule that lived only in the sequencer's submit path would be bypassed by
  // going dark. Both halves of 24c are checked here: the law's (no withdrawal
  // while the lock is live) and the sequencer's (no withdrawal where the record
  // already shows the half committed) — the second sits on adopt as well.
  const ATTEMPT = new Uint8Array(32).fill(0xc3);

  it("a withdrawal published before the timeout is not adopted", () => {
    const f = gapGold();
    const { lock } = lockAndCommit(f, ATTEMPT);
    f.venue.advance(30n);
    publishWithdrawal(f, ATTEMPT, lock.nonce + 1n);
    f.venue.advance(1n);
    f.sequencer.commit();
    expect(f.sequencer.availableBalance(f.gold, KEYS.alice)).toBe(110n);
    // And the commit witnessed in time settles the half she tried to take back.
    f.venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    f.sequencer.settle(f.gold, ATTEMPT);
    expect(f.sequencer.balance(f.gold, KEYS.bob)).toBe(90n);
  });

  it("nor is one published past the timeout, where a commit was witnessed in time", () => {
    const f = gapGold();
    const { lock } = lockAndCommit(f, ATTEMPT);
    f.venue.advance(30n);
    f.venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    advanceWitnessedIndex(f.venue, 101n);
    publishWithdrawal(f, ATTEMPT, lock.nonce + 1n);
    f.venue.advance(1n);
    f.sequencer.commit();
    expect(f.sequencer.availableBalance(f.gold, KEYS.alice)).toBe(110n);
    f.sequencer.settle(f.gold, ATTEMPT);
    expect(f.sequencer.balance(f.gold, KEYS.bob)).toBe(90n);
  });

  it("a withdrawal published past the timeout with nothing committed is adopted", () => {
    // The guard is exactly as wide as its reason.
    const f = gapGold();
    const { lock } = lockAndCommit(f, ATTEMPT);
    advanceWitnessedIndex(f.venue, 101n);
    publishWithdrawal(f, ATTEMPT, lock.nonce + 1n);
    f.venue.advance(1n);
    f.sequencer.commit();
    expect(f.sequencer.availableBalance(f.gold, KEYS.alice)).toBe(200n);
  });
});

/** gapGold's two-backing sibling: EUR relies on GOLD x2, both adoptable, Alice holds 200 of each. */
function gapPair() {
  const venue = new LocalVenue();
  const mk = (thing: string, reliance: { target: Uint8Array; count: bigint }[] = []) =>
    makeBacking({
      obligor: KEYS.backer,
      payout: { thing, quantumExponent: -2, perUnit: 100n },
      reliance,
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
        witnessing: { venue: venue.id, interval: 5n },
      },
    });
  const gold = mk("GOLD");
  const eur = mk("EUR", [{ target: gold.name, count: 2n }]);
  const sequencer = new Sequencer(SECRETS.operator, venue);
  for (const backing of [gold, eur]) {
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
    const nonce = sequencer.nextNonce(KEYS.backer, backing);
    sequencer.submitIssue(
      { backing, recipient: KEYS.alice, quantity: 200n, nonce },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 200n, nonce), SECRETS.backer),
    );
  }
  return { venue, sequencer, eur, gold };
}

describe("§C3: a set published into a gap is read one record at a time", () => {
  it("an early set withdrawal lands the head and leaves the leg to its own timeout", () => {
    // The gap path has no set: adopt applies each publication at its stamped
    // index, so the head's exit (no live acceptance) and the leg's (past its
    // timeout) are read separately. Published at 30 with a timeout of 100, the
    // demand ends and the lock stands — a reservation nobody can settle but
    // its own holder's commit, withdrawable alone once its timeout passes.
    // Pinned so the shape is known rather than assumed; not harmful, since the
    // window is the holder's own.
    const { venue, sequencer, eur, gold } = gapPair();
    const { hash, lock } = file(sequencer, venue, eur, gold, 40n, 100n);
    sequencer.commit();
    venue.advance(30n);
    const head = { backing: eur, demandHash: hash, nonce: 1n };
    venue.publishOp(eur.name, {
      kind: "withdrawal",
      demandHash: hash,
      nonce: head.nonce,
      signature: ed25519.sign(encodeWithdrawal(head), SECRETS.alice),
    });
    const leg = { backing: gold, demandHash: hash, nonce: lock.nonce + 1n };
    venue.publishOp(gold.name, {
      kind: "withdrawal",
      demandHash: hash,
      nonce: leg.nonce,
      signature: ed25519.sign(encodeWithdrawal(leg), SECRETS.alice),
    });
    venue.advance(1n);
    sequencer.commit();
    expect(sequencer.openDemands(eur)).toHaveLength(0);
    expect(sequencer.availableBalance(eur, KEYS.alice)).toBe(200n);
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(120n);

    advanceWitnessedIndex(venue, 101n);
    const alone = { backing: gold, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, gold) };
    sequencer.submitWithdrawal(alone, ed25519.sign(encodeWithdrawal(alone), SECRETS.alice));
    expect(sequencer.availableBalance(gold, KEYS.alice)).toBe(200n);
  });
});

describe("§C3: the verifier's gap fold reads the record the way the operator does", () => {
  it("a withdrawal the operator skips, walkGap skips too, so snapshot redemptions agree", () => {
    // Found reviewing 24c: the sequencer skipped a gap withdrawal of a committed
    // lock while recovery.ts's fold applied it, so a verifier saw 90 more units
    // free than the operator did — and a demand for 150, accepted and released
    // in the gap, read as a redemption to one and as over-spent to the other.
    const f = gapGold();
    const ATTEMPT = new Uint8Array(32).fill(0xd1);
    const { lock, commitment } = lockAndCommit(f, ATTEMPT);
    const served = { snapshots: f.sequencer.snapshot(), commitment };
    f.venue.advance(30n);
    f.venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    advanceWitnessedIndex(f.venue, 101n);
    publishWithdrawal(f, ATTEMPT, lock.nonce + 1n);
    f.venue.advance(1n);
    const demand: DemandOp = {
      backing: f.gold,
      holder: KEYS.alice,
      quantity: 150n,
      instant: f.venue.witnessedIndex(),
      deadline: 300n,
      nonce: lock.nonce + 2n,
    };
    const hash = demandHash(demand);
    f.venue.publishOp(f.gold.name, {
      kind: "demand",
      holder: demand.holder,
      quantity: demand.quantity,
      instant: demand.instant,
      deadline: demand.deadline,
      nonce: demand.nonce,
      signature: ed25519.sign(encodeDemand(demand), SECRETS.alice),
    });
    f.venue.advance(1n);
    const answer = { backing: f.gold, demandHash: hash, instant: demand.instant, deadline: 200n, nonce: 1n };
    f.venue.publishOp(f.gold.name, {
      kind: "acceptance",
      demandHash: hash,
      instant: answer.instant,
      deadline: answer.deadline,
      nonce: answer.nonce,
      signature: ed25519.sign(encodeAcceptance(answer), SECRETS.backer),
    });
    f.venue.advance(1n);
    const settle = { backing: f.gold, demandHash: hash, nonce: demand.nonce + 1n };
    f.venue.publishOp(f.gold.name, {
      kind: "release",
      demandHash: hash,
      nonce: settle.nonce,
      signature: ed25519.sign(encodeRelease(settle), SECRETS.alice),
    });
    // The verifier: no redemption, because the 90 are still reserved.
    expect(snapshotRedemptions(f.venue, f.gold, served)).toEqual([]);
    // The operator, on return: the same. The commit settles the lock, nothing else moved.
    f.venue.advance(1n);
    f.sequencer.commit();
    f.sequencer.settle(f.gold, ATTEMPT);
    expect(f.sequencer.balance(f.gold, KEYS.bob)).toBe(90n);
    expect(f.sequencer.balance(f.gold, KEYS.backer)).toBe(0n);
    expect(f.sequencer.openDemands(f.gold)).toHaveLength(0);
  });
});
