import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";

// Invariant 10: outstanding = issued − burned, in claim quantity, per
// backing, at every published moment. Presentation destroys nothing: handing
// claims to the backer is an ordinary transfer, and only a burn lowers the
// count.

const BACKER_SECRET = new Uint8Array(32).fill(0x01);
const BACKER_2_SECRET = new Uint8Array(32).fill(0x02);
const HOLDER_SECRETS = [
  new Uint8Array(32).fill(0x03),
  new Uint8Array(32).fill(0x05),
  new Uint8Array(32).fill(0x07),
];
const OPERATOR = new Uint8Array(32).fill(0x22);

function makeRegistered(ledger: TransparentLedger, secret: Uint8Array, thing: string): Backing {
  const backing = makeBacking({
    obligor: ed25519.getPublicKey(secret),
    payout: { thing, quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: OPERATOR },
  });
  ledger.register(backing, signBacking(secret, backing));
  return backing;
}

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
    const random = prng(0xb0b);
    const backers = [BACKER_SECRET, BACKER_2_SECRET];
    const backings = [
      makeRegistered(ledger, BACKER_SECRET, "EUR"),
      makeRegistered(ledger, BACKER_2_SECRET, "kWh"),
    ];
    const holders = HOLDER_SECRETS.map((secret) => ({
      secret,
      key: ed25519.getPublicKey(secret),
    }));
    // The ledger consumes a nonce only on success, so ask it rather than
    // tracking a counter that would desync on a failed operation.
    const nextNonce = (key: Uint8Array) => ledger.nextNonce(key);

    let applied = 0;
    for (let step = 0; step < 200; step++) {
      const which = Math.floor(random() * backings.length);
      const backing = backings[which] as Backing;
      const backerSecret = backers[which] as Uint8Array;
      const backerKey = ed25519.getPublicKey(backerSecret);
      const holder = holders[Math.floor(random() * holders.length)] as (typeof holders)[0];
      const other = holders[Math.floor(random() * holders.length)] as (typeof holders)[0];
      const quantity = BigInt(1 + Math.floor(random() * 50));
      const kind = random();

      try {
        if (kind < 0.4) {
          const op = { backing, recipient: holder.key, quantity, nonce: nextNonce(backerKey) };
          ledger.issue(op, ed25519.sign(encodeIssuance(op), backerSecret));
        } else if (kind < 0.8) {
          const op = {
            backing,
            from: holder.key,
            to: other.key,
            quantity,
            nonce: nextNonce(holder.key),
          };
          ledger.transfer(op, ed25519.sign(encodeTransfer(op), holder.secret));
        } else {
          const op = { backing, holder: holder.key, quantity, nonce: nextNonce(holder.key) };
          ledger.burn(op, ed25519.sign(encodeBurn(op), holder.secret));
        }
        applied++;
      } catch (error) {
        // Insufficient balance is a legitimate outcome of a random sequence;
        // anything else is a real failure. Either way the books must balance.
        if (!(error instanceof LedgerError)) throw error;
      }
      for (const b of backings) assertConservation(ledger, b);
    }
    // The sequence must have actually exercised the ledger.
    expect(applied).toBeGreaterThan(100);
  });

  it("presentation destroys nothing: redemption is a transfer to the backer", () => {
    const ledger = new TransparentLedger();
    const backing = makeRegistered(ledger, BACKER_SECRET, "EUR");
    const backer = ed25519.getPublicKey(BACKER_SECRET);
    const alice = ed25519.getPublicKey(HOLDER_SECRETS[0] as Uint8Array);

    const issue = { backing, recipient: alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));

    // Alice presents: her claims go to the backer, who is then their holder.
    const present = { backing, from: alice, to: backer, quantity: 100n, nonce: 0n };
    ledger.transfer(present, ed25519.sign(encodeTransfer(present), HOLDER_SECRETS[0] as Uint8Array));

    expect(ledger.outstanding(backing)).toBe(100n);
    expect(ledger.balance(backing, backer)).toBe(100n);
  });

  it("only a burn lowers outstanding, and only by the burned quantity", () => {
    const ledger = new TransparentLedger();
    const backing = makeRegistered(ledger, BACKER_SECRET, "EUR");
    const aliceSecret = HOLDER_SECRETS[0] as Uint8Array;
    const alice = ed25519.getPublicKey(aliceSecret);

    const issue = { backing, recipient: alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));
    const burn = { backing, holder: alice, quantity: 30n, nonce: 0n };
    ledger.burn(burn, ed25519.sign(encodeBurn(burn), aliceSecret));

    expect(ledger.issued(backing)).toBe(100n);
    expect(ledger.burned(backing)).toBe(30n);
    expect(ledger.outstanding(backing)).toBe(70n);
  });
});
