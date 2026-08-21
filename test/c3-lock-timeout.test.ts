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
} from "../src/presentation.js";
import { Sequencer } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

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
// settle, so the holder's exit needs nobody's cooperation. Withdrawal was
// already that, and it is why nothing new was needed for the exit itself.

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
    demandHash: hash,
    holder: KEYS.alice,
    beneficiary: KEYS.backer,
    quantity: quantity * 2n,
    timeout,
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
    const { hash } = file(sequencer, eur, gold, 40n);
    accept(sequencer, eur, hash);
    venue.advance(TIMEOUT);
    releaseSet(sequencer, eur, gold, hash);
    expect(sequencer.balance(gold, KEYS.backer)).toBe(80n);
  });

  it("and refuses to settle one index past it", () => {
    // "was a valid release witnessed at or before the lock timeout?" — at is
    // inside, one past is not.
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, eur, gold, 40n);
    accept(sequencer, eur, hash);
    venue.advance(TIMEOUT + 1n);
    expect(() => releaseSet(sequencer, eur, gold, hash)).toThrow(/timeout/);
    expect(sequencer.balance(gold, KEYS.backer)).toBe(0n);
  });

  it("refuses a lock whose timeout has already passed", () => {
    const { venue, sequencer, eur, gold } = setup();
    venue.advance(50n);
    expect(() => file(sequencer, eur, gold, 40n, 40n)).toThrow(/timeout/);
  });

  it("the demand outlives its locks, and can be relocked", () => {
    // §C3: "the timeout ends the atomic attempt, the deadline governs evidence,
    // and a demand outlives its locks." So an expired attempt is a retry, not a
    // lost demand — the whole point of the timeout being separate.
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, eur, gold, 40n);
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
    const { hash } = file(sequencer, eur, gold, 40n);
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
    file(sequencer, eur, gold, 40n);
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
    const { hash } = file(sequencer, eur, gold, 40n);
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
