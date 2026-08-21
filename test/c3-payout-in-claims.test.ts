import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { decodeBacking, encodeBacking, makeBacking, signBacking, type Backing } from "../src/backing.js";
import { encodeIssuanceMessage } from "../src/messages.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeLock,
  encodeRelease,
  encodeWithdrawal,
  type AcceptanceOp,
  type DemandOp,
  type LockOp,
} from "../src/presentation.js";
import { payoutOf } from "../src/presentability.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// §C3: "A payout paying in claims settles as a swap inside the settlement. The
// acceptance names the claims, or the fresh issuance, that will pay, and the
// release executes as one atomic exchange, surrendered set against paying
// claims, co-signed by every sequencer either side needs. That is §C1's swap
// run at settlement, so the backer cannot take the set and not pay. Neither
// party can write the other's outcome."
//
// P gains a form: one unit of this backing pays `perUnit` units of a named
// backing. The backer's ACCEPTANCE reserves them — a lock, the backer's own
// units, to the demand holder, under the demand's hash, convertible by the
// holder alone — and the holder's RELEASE settles surrendered set and payout
// as one act. The backer consented at the acceptance; the holder's release is
// the only signature that moves anything; the sequencer applies all or none.

const DEADLINE = 100n;

/** GOLD, plain; EUR pays 2 GOLD per unit. One operator serves both. */
function setup() {
  const venue = new LocalVenue();
  const gold = makeBacking({
    obligor: KEYS.backer,
    payout: { thing: "GOLD", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: KEYS.operator },
  });
  const eur = makeBacking({
    obligor: KEYS.backer,
    payout: { backing: gold.name, perUnit: 2n },
    reliance: [],
    evidence: { setting: "transparent", operator: KEYS.operator },
  });
  const sequencer = new Sequencer(SECRETS.operator, venue);
  for (const backing of [gold, eur]) sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = (backing: Backing, to: Uint8Array, quantity: bigint) => {
    const nonce = sequencer.nextNonce(KEYS.backer, backing);
    sequencer.submitIssue(
      { backing, recipient: to, quantity, nonce },
      ed25519.sign(encodeIssuanceMessage(backing.name, to, quantity, nonce), SECRETS.backer),
    );
  };
  issue(eur, KEYS.alice, 100n);
  issue(gold, KEYS.backer, 500n);
  return { venue, sequencer, eur, gold };
}

function file(f: ReturnType<typeof setup>, quantity: bigint) {
  const demand: DemandOp = {
    backing: f.eur,
    holder: KEYS.alice,
    quantity,
    instant: 0n,
    deadline: DEADLINE,
    nonce: f.sequencer.nextNonce(KEYS.alice, f.eur),
  };
  f.sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
  return { demand, hash: demandHash(demand) };
}

/** The backer's answer, with the paying lock §C3 asks for, or a variant of it. */
function accept(
  f: ReturnType<typeof setup>,
  hash: Uint8Array,
  quantity: bigint,
  variant: Partial<LockOp> = {},
  paying = true,
) {
  const op: AcceptanceOp = {
    backing: f.eur,
    demandHash: hash,
    instant: 0n,
    deadline: 90n,
    nonce: f.sequencer.nextNonce(KEYS.backer, f.eur),
  };
  const lock: LockOp = {
    backing: f.gold,
    attemptId: hash,
    holder: KEYS.backer,
    beneficiary: KEYS.alice,
    quantity: quantity * 2n,
    timeout: 95n,
    decisionVenue: f.venue.id,
    parties: [KEYS.alice],
    nonce: f.sequencer.nextNonce(KEYS.backer, f.gold),
    ...variant,
  };
  return f.sequencer.submitAcceptance(
    op,
    ed25519.sign(encodeAcceptance(op), SECRETS.backer),
    paying ? [{ op: lock, signature: ed25519.sign(encodeLock(lock), SECRETS.backer) }] : [],
  );
}

/** The holder's release of the set: the demand and the payout, one act, one signer. */
function release(f: ReturnType<typeof setup>, hash: Uint8Array, withPayout = true) {
  const head = { backing: f.eur, demandHash: hash, nonce: f.sequencer.nextNonce(KEYS.alice, f.eur) };
  const pay = { backing: f.gold, demandHash: hash, nonce: f.sequencer.nextNonce(KEYS.alice, f.gold) };
  return f.sequencer.submitRelease(
    head,
    ed25519.sign(encodeRelease(head), SECRETS.alice),
    withPayout ? [{ op: pay, signature: ed25519.sign(encodeRelease(pay), SECRETS.alice) }] : [],
  );
}

describe("§C3: a payout paying in claims", () => {
  it("is a form of P, inside the name, and round-trips", () => {
    const { eur, gold } = setup();
    expect(decodeBacking(encodeBacking(eur)).payout).toEqual({ backing: gold.name, perUnit: 2n });
    const constant = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: { setting: "transparent", operator: KEYS.operator },
    });
    expect(eur.name).not.toEqual(constant.name);
  });

  it("the acceptance reserves the payout and the holder's release settles both sides", () => {
    const f = setup();
    const { hash } = file(f, 40n);
    accept(f, hash, 40n);
    expect(f.sequencer.availableBalance(f.gold, KEYS.backer)).toBe(500n - 80n);
    release(f, hash);
    expect(f.sequencer.balance(f.eur, KEYS.backer)).toBe(40n);
    expect(f.sequencer.balance(f.gold, KEYS.alice)).toBe(80n);
    expect(f.sequencer.balance(f.gold, KEYS.backer)).toBe(420n);
    expect(f.sequencer.openDemands(f.eur)).toHaveLength(0);
  });
});

describe("§C3: the backer cannot take the set and not pay, and the holder cannot take the payout and not surrender", () => {
  it("an acceptance of a claims-paying backing must reserve the payout", () => {
    const f = setup();
    const { hash } = file(f, 40n);
    expect(() => accept(f, hash, 40n, {}, false)).toThrow(/reserves its payout/);
    expect(f.sequencer.openDemands(f.eur)[0]?.acceptedDeadline).toBeUndefined();
  });

  it("and the paying lock must carry the set's terms, the holder's key alone, and outlast the answer", () => {
    const f = setup();
    const { hash } = file(f, 40n);
    expect(() => accept(f, hash, 40n, { quantity: 79n })).toThrow(/does not cover/);
    expect(() => accept(f, hash, 40n, { beneficiary: KEYS.bob })).toThrow(/obligor|holder|convert/);
    expect(() => accept(f, hash, 40n, { parties: [KEYS.alice, KEYS.bob].sort(Buffer.compare) })).toThrow(/convert/);
    expect(() => accept(f, hash, 40n, { timeout: 89n })).toThrow(/outlast/);
    // Nothing of the above stuck: the demand stands unanswered, the GOLD is the backer's.
    expect(f.sequencer.availableBalance(f.gold, KEYS.backer)).toBe(500n);
    expect(f.sequencer.openDemands(f.eur)[0]?.acceptedDeadline).toBeUndefined();
  });

  it("the release must carry the payout leg, signed by the holder like every other", () => {
    const f = setup();
    const { hash } = file(f, 40n);
    accept(f, hash, 40n);
    expect(() => release(f, hash, false)).toThrow(/every reliance leg/);
    expect(f.sequencer.balance(f.eur, KEYS.backer)).toBe(0n);
    release(f, hash);
    expect(f.sequencer.balance(f.gold, KEYS.alice)).toBe(80n);
  });

  it("the paying lock released alone takes nothing: it is a leg, and a leg is not the head", () => {
    const f = setup();
    const { hash } = file(f, 40n);
    accept(f, hash, 40n);
    const pay = { backing: f.gold, demandHash: hash, nonce: f.sequencer.nextNonce(KEYS.alice, f.gold) };
    expect(() =>
      f.sequencer.submitRelease(pay, ed25519.sign(encodeRelease(pay), SECRETS.alice)),
    ).toThrow(/leg of this demand/);
    expect(f.sequencer.balance(f.gold, KEYS.alice)).toBe(0n);
  });

  it("a backer whose acceptance expires unpaid frees its own payout, and only past its lock's timeout", () => {
    const f = setup();
    const { hash } = file(f, 40n);
    accept(f, hash, 40n);
    f.venue.advance(96n);
    const back = { backing: f.gold, demandHash: hash, nonce: f.sequencer.nextNonce(KEYS.backer, f.gold) };
    f.sequencer.submitWithdrawal(back, ed25519.sign(encodeWithdrawal(back), SECRETS.backer));
    expect(f.sequencer.availableBalance(f.gold, KEYS.backer)).toBe(500n);
    // The demand still stands for the holder to withdraw: the answer lapsed, the claims did not move.
    expect(f.sequencer.openDemands(f.eur)).toHaveLength(1);
  });
});

describe("§C3: reading the payout, and the gap", () => {
  it("payoutOf tells the holder whether the payout is reserved before it releases", () => {
    const f = setup();
    const { hash } = file(f, 40n);
    const terms = (name: Uint8Array) => (Buffer.compare(name, f.gold.name) === 0 ? f.gold : undefined);
    const served = () => ({ snapshots: f.sequencer.snapshot(), commitment: f.sequencer.commit() });
    expect(payoutOf(f.eur, f.venue, terms, served(), hash)).toBe("unreserved");
    accept(f, hash, 40n);
    expect(payoutOf(f.eur, f.venue, terms, served(), hash)).toBe("reserved");
    expect(payoutOf(f.gold, f.venue, terms, served(), hash)).toBe("outside");
    expect(payoutOf(f.eur, f.venue, () => undefined, served(), hash)).toBe("unreadable");
  });

  it("in a gap a presentation with a payout leg neither opens nor settles: it waits for the operator", () => {
    // adopt takes operations one at a time, never a set; a paying lock released
    // alone there would hand the holder the payout for nothing. 24a's posture,
    // one step further: claims go illiquid rather than dead.
    const venue = new LocalVenue();
    const mk = (payout: { thing: string; quantumExponent: number; perUnit: bigint } | { backing: Uint8Array; perUnit: bigint }) =>
      makeBacking({
        obligor: KEYS.backer,
        payout,
        reliance: [],
        evidence: {
          setting: "transparent",
          operator: KEYS.operator,
          silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
          witnessing: { venue: venue.id, interval: 5n },
        },
      });
    const gold = mk({ thing: "GOLD", quantumExponent: -2, perUnit: 100n });
    const eur = mk({ backing: gold.name, perUnit: 2n });
    const sequencer = new Sequencer(SECRETS.operator, venue);
    for (const b of [gold, eur]) sequencer.register(b, signBacking(SECRETS.backer, b));
    const n0 = sequencer.nextNonce(KEYS.backer, eur);
    sequencer.submitIssue(
      { backing: eur, recipient: KEYS.alice, quantity: 100n, nonce: n0 },
      ed25519.sign(encodeIssuanceMessage(eur.name, KEYS.alice, 100n, n0), SECRETS.backer),
    );
    sequencer.commit();
    venue.advance(30n);
    const demand: DemandOp = { backing: eur, holder: KEYS.alice, quantity: 40n, instant: 30n, deadline: 200n, nonce: 0n };
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
    sequencer.commit();
    expect(sequencer.openDemands(eur)).toHaveLength(0);
  });
});
