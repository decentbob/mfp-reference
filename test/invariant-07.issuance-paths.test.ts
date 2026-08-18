import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking } from "../src/backing.js";
import { LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeIssuance, encodeTransfer } from "../src/messages.js";

// Invariant 7: issuance changes the outstanding count and needs the backer's
// signature. Movement of existing units preserves the count and needs no
// backer signature. Never one code path for both.

const BACKER_SECRET = new Uint8Array(32).fill(0x01);
const ALICE_SECRET = new Uint8Array(32).fill(0x03);
const BOB_SECRET = new Uint8Array(32).fill(0x05);
const BACKER = ed25519.getPublicKey(BACKER_SECRET);
const ALICE = ed25519.getPublicKey(ALICE_SECRET);
const BOB = ed25519.getPublicKey(BOB_SECRET);
const OPERATOR = new Uint8Array(32).fill(0x22);

function setup() {
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

describe("invariant 7: issuance and movement are separate paths", () => {
  it("issuance raises issued and outstanding; movement touches neither", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));
    expect(ledger.issued(backing)).toBe(100n);
    expect(ledger.outstanding(backing)).toBe(100n);

    const move = { backing, from: ALICE, to: BOB, quantity: 30n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), ALICE_SECRET));
    expect(ledger.issued(backing)).toBe(100n);
    expect(ledger.burned(backing)).toBe(0n);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("movement needs no backer signature; issuance accepts no holder signature", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));

    // Alice moves units with only her own signature.
    const move = { backing, from: ALICE, to: BOB, quantity: 30n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), ALICE_SECRET));
    expect(ledger.balance(backing, BOB)).toBe(30n);

    // A holder cannot use the issuance path.
    const fakeIssue = { backing, recipient: ALICE, quantity: 100n, nonce: 1n };
    expect(() =>
      ledger.issue(fakeIssue, ed25519.sign(encodeIssuance(fakeIssue), ALICE_SECRET)),
    ).toThrow(LedgerError);
  });

  it("an issuance message cannot be replayed", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    const signature = ed25519.sign(encodeIssuance(issue), BACKER_SECRET);
    ledger.issue(issue, signature);
    expect(() => ledger.issue(issue, signature)).toThrow(LedgerError);
    expect(ledger.issued(backing)).toBe(100n);
  });

  it("a transfer message cannot be replayed", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));

    const move = { backing, from: ALICE, to: BOB, quantity: 30n, nonce: 0n };
    const signature = ed25519.sign(encodeTransfer(move), ALICE_SECRET);
    ledger.transfer(move, signature);
    expect(() => ledger.transfer(move, signature)).toThrow(LedgerError);
    expect(ledger.balance(backing, BOB)).toBe(30n);
  });

  it("issuance is logged in the open with quantity and recipient", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));
    const log = ledger.issuanceLog(backing);
    expect(log.length).toBe(1);
    expect(log[0]?.quantity).toBe(100n);
    expect(log[0]?.recipient).toEqual(ALICE);
  });
});
