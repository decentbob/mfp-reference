import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { KEYS, register, SECRETS } from "./support.js";

// The law: nothing you owe (your written maximum) grows without your
// signature; nothing you hold leaves without your signature.

function freshLedger() {
  const ledger = new TransparentLedger();
  const backing = register(ledger, SECRETS.backer);
  return { ledger, backing };
}

describe("the law: nothing you owe grows without your signature", () => {
  it("issuance signed by the backer grows outstanding", () => {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(op, ed25519.sign(encodeIssuance(op), SECRETS.backer));
    expect(ledger.outstanding(backing)).toBe(100n);
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("issuance signed by anyone else is rejected and changes nothing", () => {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: KEYS.mallory, quantity: 100n, nonce: 0n };
    expect(() => ledger.issue(op, ed25519.sign(encodeIssuance(op), SECRETS.mallory))).toThrow(
      /only the obligor issues/,
    );
    expect(ledger.outstanding(backing)).toBe(0n);
    expect(ledger.balance(backing, KEYS.mallory)).toBe(0n);
  });

  it("a corrupted backer signature is rejected", () => {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    const signature = ed25519.sign(encodeIssuance(op), SECRETS.backer);
    signature[0] = (signature[0] as number) ^ 0xff;
    expect(() => ledger.issue(op, signature)).toThrow(/only the obligor issues/);
    expect(ledger.outstanding(backing)).toBe(0n);
  });
});

describe("the law: nothing you hold leaves without your signature", () => {
  function ledgerWithAliceHolding100() {
    const { ledger, backing } = freshLedger();
    const op = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(op, ed25519.sign(encodeIssuance(op), SECRETS.backer));
    return { ledger, backing };
  }

  it("a transfer signed by the holder moves the units", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, from: KEYS.alice, to: KEYS.mallory, quantity: 40n, nonce: 0n };
    ledger.transfer(op, ed25519.sign(encodeTransfer(op), SECRETS.alice));
    expect(ledger.balance(backing, KEYS.alice)).toBe(60n);
    expect(ledger.balance(backing, KEYS.mallory)).toBe(40n);
  });

  it("a transfer out of Alice's holding signed by Mallory is rejected", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, from: KEYS.alice, to: KEYS.mallory, quantity: 40n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), SECRETS.mallory))).toThrow(
      /only the holder moves/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("a burn of Alice's holding signed by anyone else is rejected", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, holder: KEYS.alice, quantity: 40n, nonce: 0n };
    expect(() => ledger.burn(op, ed25519.sign(encodeBurn(op), SECRETS.backer))).toThrow(
      /only the holder burns/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("more than the holding cannot leave", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const op = { backing, from: KEYS.alice, to: KEYS.mallory, quantity: 101n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), SECRETS.alice))).toThrow(
      /insufficient balance/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("a malformed holder key is a LedgerError, not an escaping EncodingError", () => {
    const { ledger, backing } = ledgerWithAliceHolding100();
    const shortKey = new Uint8Array(31);
    const badTransfer = { backing, from: shortKey, to: KEYS.bob, quantity: 1n, nonce: 0n };
    expect(() => ledger.transfer(badTransfer, new Uint8Array(64))).toThrow(LedgerError);
    const badBurn = { backing, holder: shortKey, quantity: 1n, nonce: 0n };
    expect(() => ledger.burn(badBurn, new Uint8Array(64))).toThrow(LedgerError);
  });
});
