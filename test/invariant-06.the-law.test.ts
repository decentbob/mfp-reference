import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking } from "../src/backing.js";
import { LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";

// The law: nothing you owe (your written maximum) grows without your
// signature; nothing you hold leaves without your signature.

const BACKER_SECRET = new Uint8Array(32).fill(0x01);
const ALICE_SECRET = new Uint8Array(32).fill(0x03);
const MALLORY_SECRET = new Uint8Array(32).fill(0x04);
const BACKER = ed25519.getPublicKey(BACKER_SECRET);
const ALICE = ed25519.getPublicKey(ALICE_SECRET);
const MALLORY = ed25519.getPublicKey(MALLORY_SECRET);
const OPERATOR = new Uint8Array(32).fill(0x22);

function freshLedger() {
  const backing = makeBacking({
    obligor: BACKER,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: OPERATOR },
  });
  const ledger = new TransparentLedger();
  ledger.register(backing, signBacking(BACKER_SECRET, backing));
  return { ledger, backing };
}

describe("the law: nothing you owe grows without your signature", () => {
  it("issuance signed by the backer grows outstanding", () => {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    ledger.issue(op, ed25519.sign(encodeIssuance(op), BACKER_SECRET));
    expect(ledger.outstanding(backing)).toBe(100n);
    expect(ledger.balance(backing, ALICE)).toBe(100n);
  });

  it("issuance signed by anyone else is rejected and changes nothing", () => {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: MALLORY, quantity: 100n, nonce: 0n };
    expect(() => ledger.issue(op, ed25519.sign(encodeIssuance(op), MALLORY_SECRET))).toThrow(
      LedgerError,
    );
    expect(ledger.outstanding(backing)).toBe(0n);
    expect(ledger.balance(backing, MALLORY)).toBe(0n);
  });

  it("a corrupted backer signature is rejected", () => {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    const signature = ed25519.sign(encodeIssuance(op), BACKER_SECRET);
    signature[0] = (signature[0] as number) ^ 0xff;
    expect(() => ledger.issue(op, signature)).toThrow(LedgerError);
    expect(ledger.outstanding(backing)).toBe(0n);
  });
});

describe("the law: nothing you hold leaves without your signature", () => {
  function ledgerWithAliceHolding100() {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    ledger.issue(op, ed25519.sign(encodeIssuance(op), BACKER_SECRET));
    return { ledger, backing };
  }

  it("a transfer signed by the holder moves the units", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, from: ALICE, to: MALLORY, quantity: 40n, nonce: 0n };
    ledger.transfer(op, ed25519.sign(encodeTransfer(op), ALICE_SECRET));
    expect(ledger.balance(backing, ALICE)).toBe(60n);
    expect(ledger.balance(backing, MALLORY)).toBe(40n);
  });

  it("a transfer out of Alice's holding signed by Mallory is rejected", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, from: ALICE, to: MALLORY, quantity: 40n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), MALLORY_SECRET))).toThrow(
      LedgerError,
    );
    expect(ledger.balance(backing, ALICE)).toBe(100n);
  });

  it("a burn of Alice's holding signed by anyone else is rejected", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, holder: ALICE, quantity: 40n, nonce: 0n };
    expect(() => ledger.burn(op, ed25519.sign(encodeBurn(op), BACKER_SECRET))).toThrow(
      LedgerError,
    );
    expect(ledger.balance(backing, ALICE)).toBe(100n);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("more than the holding cannot leave", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, from: ALICE, to: MALLORY, quantity: 101n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), ALICE_SECRET))).toThrow(
      LedgerError,
    );
    expect(ledger.balance(backing, ALICE)).toBe(100n);
  });
});
