import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { type Backing } from "../src/backing.js";
import { LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { signBacking } from "../src/backing.js";
import { replayLog } from "../src/ledger.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
} from "../src/presentation.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { KEYS, makeTransparentBacking, pub, register, SECRETS } from "./support.js";

// Invariant 10: outstanding = issued − burned, in claim quantity, per
// backing, at every published moment. Presentation destroys nothing: handing
// claims to the backer is an ordinary transfer, and only a burn lowers the
// count.

/** Deterministic PRNG (mulberry32) so the sequence is reproducible. */
function prng(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function assertConservation(ledger: TransparentLedger, backing: Backing): void {
  const outstanding = ledger.outstanding(backing);
  expect(outstanding).toBe(ledger.issued(backing) - ledger.burned(backing));
  let held = 0n;
  for (const units of ledger.balancesOf(backing).values()) held += units;
  expect(held).toBe(outstanding);
}

describe("invariant 10: outstanding = issued - burned at every moment", () => {
  it("holds after every operation of a generated 200-step sequence", () => {
    const ledger = new TransparentLedger();
    const backers = [SECRETS.backer, SECRETS.backer2];
    const backings = [
      register(ledger, SECRETS.backer, "EUR"),
      register(ledger, SECRETS.backer2, "kWh"),
    ];
    const holders = [SECRETS.alice, SECRETS.bob, SECRETS.carol].map((secret) => ({
      secret,
      key: pub(secret),
    }));
    const random = prng(0xb0b);
    const applied = { issue: 0, transfer: 0, burn: 0 };

    for (let step = 0; step < 200; step++) {
      const which = Math.floor(random() * backings.length);
      const backing = backings[which] as Backing;
      const backerSecret = backers[which] as Uint8Array;
      const backerKey = pub(backerSecret);
      const holder = holders[Math.floor(random() * holders.length)] as (typeof holders)[0];
      const other = holders[Math.floor(random() * holders.length)] as (typeof holders)[0];
      const quantity = BigInt(1 + Math.floor(random() * 50));
      const kind = random();

      try {
        if (kind < 0.4) {
          const op = { backing, recipient: holder.key, quantity, nonce: ledger.nextNonce(backerKey, backing) };
          ledger.issue(op, ed25519.sign(encodeIssuance(op), backerSecret));
          applied.issue++;
        } else if (kind < 0.8) {
          const op = {
            backing,
            from: holder.key,
            to: other.key,
            quantity,
            nonce: ledger.nextNonce(holder.key, backing),
          };
          ledger.transfer(op, ed25519.sign(encodeTransfer(op), holder.secret));
          applied.transfer++;
        } else {
          const op = { backing, holder: holder.key, quantity, nonce: ledger.nextNonce(holder.key, backing) };
          ledger.burn(op, ed25519.sign(encodeBurn(op), holder.secret));
          applied.burn++;
        }
      } catch (error) {
        // Insufficient balance is a legitimate outcome of a random sequence;
        // anything else is a real failure. Either way the books must balance.
        if (!(error instanceof LedgerError)) throw error;
      }
      for (const b of backings) assertConservation(ledger, b);
    }
    // The sequence must have actually exercised all three operations, so a
    // regression that silently disabled one (e.g. burn always throwing) can
    // not leave conservation trivially satisfied.
    expect(applied.issue).toBeGreaterThan(0);
    expect(applied.transfer).toBeGreaterThan(0);
    expect(applied.burn).toBeGreaterThan(0);
  });

  it("holds in served state by construction, not by inspection", () => {
    // The committed state used to carry issued, burned and balances beside the
    // log, and an encoder check policed the identity between them. They are
    // folds over the log now, so the identity is a property of the fold: every
    // operation either conserves the total or moves issued/burned with it. This
    // is that property, checked over a log carrying all seven operation kinds.
    const venue = new Venue();
    const sequencer = new Sequencer(SECRETS.operator, venue);
    const backing = makeTransparentBacking(SECRETS.backer);
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    const burn = { backing, holder: KEYS.bob, quantity: 10n, nonce: 0n };
    sequencer.submitBurn(burn, ed25519.sign(encodeBurn(burn), SECRETS.bob));

    venue.advance(5n);
    const demand = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
    const answer = {
      backing,
      demandHash: demandHash(demand),
      instant: 5n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.backer, backing),
    };
    sequencer.submitAcceptance(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer));
    const settle = {
      backing,
      demandHash: demandHash(demand),
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    sequencer.submitRelease(settle, ed25519.sign(encodeRelease(settle), SECRETS.alice));

    const log = sequencer.snapshot()[0]!.opLog;
    expect(log.map((entry) => entry.kind)).toEqual([
      "issue",
      "transfer",
      "burn",
      "demand",
      "acceptance",
      "release",
    ]);
    // The identity, over every prefix of the log: it cannot be broken part-way
    // through and repaired later.
    for (let i = 0; i <= log.length; i++) {
      const replay = replayLog(backing, log.slice(0, i))!;
      const held = [...replay.balances.values()].reduce((a, b) => a + b, 0n);
      expect(held).toBe(replay.issued - replay.burned);
    }
  });

  it("presentation destroys nothing: redemption is a transfer to the backer", () => {
    const ledger = new TransparentLedger();
    const backing = register(ledger, SECRETS.backer, "EUR");
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));

    // Alice presents: her claims go to the backer, who is then their holder.
    const present = { backing, from: KEYS.alice, to: KEYS.backer, quantity: 100n, nonce: 0n };
    ledger.transfer(present, ed25519.sign(encodeTransfer(present), SECRETS.alice));

    expect(ledger.outstanding(backing)).toBe(100n);
    expect(ledger.balance(backing, KEYS.backer)).toBe(100n);
  });

  it("only a burn lowers outstanding, and only by the burned quantity", () => {
    const ledger = new TransparentLedger();
    const backing = register(ledger, SECRETS.backer, "EUR");
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    const burn = { backing, holder: KEYS.alice, quantity: 30n, nonce: 0n };
    ledger.burn(burn, ed25519.sign(encodeBurn(burn), SECRETS.alice));

    expect(ledger.issued(backing)).toBe(100n);
    expect(ledger.burned(backing)).toBe(30n);
    expect(ledger.outstanding(backing)).toBe(70n);
  });

  it("issuance that would exceed the quantity bound is rejected", () => {
    const ledger = new TransparentLedger();
    const backing = register(ledger, SECRETS.backer, "EUR");
    const half = 2n ** 255n;
    const first = { backing, recipient: KEYS.alice, quantity: half, nonce: 0n };
    ledger.issue(first, ed25519.sign(encodeIssuance(first), SECRETS.backer));
    // A second near-max issuance would push outstanding to 2^256, which the
    // canonical quantity encoding cannot represent.
    const second = { backing, recipient: KEYS.bob, quantity: half, nonce: 1n };
    expect(() => ledger.issue(second, ed25519.sign(encodeIssuance(second), SECRETS.backer))).toThrow(
      /beyond the quantity bound/,
    );
    expect(ledger.outstanding(backing)).toBe(half);
  });
});
