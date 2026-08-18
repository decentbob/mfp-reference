import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking } from "../src/backing.js";
import { LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";

// Invariant 8: no clawback, no reversal, no privileged party who can move
// claims. The rule is not "don't call it" — the path must not exist. These
// tests prove every mutation route demands the holder's own signature.

const BACKER_SECRET = new Uint8Array(32).fill(0x01);
const OPERATOR_SECRET = new Uint8Array(32).fill(0x06);
const ALICE_SECRET = new Uint8Array(32).fill(0x03);
const BACKER = ed25519.getPublicKey(BACKER_SECRET);
const OPERATOR = ed25519.getPublicKey(OPERATOR_SECRET);
const ALICE = ed25519.getPublicKey(ALICE_SECRET);

function setup() {
  const backing = makeBacking({
    obligor: BACKER,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: OPERATOR },
  });
  const ledger = new TransparentLedger();
  ledger.register(backing, signBacking(BACKER_SECRET, backing));
  const issue = { backing, recipient: ALICE, quantity: 100n, nonce: 0n };
  ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));
  return { ledger, backing };
}

describe("invariant 8: no privileged party can move a holder's claims", () => {
  it("the backer cannot transfer out of a holding", () => {
    const { ledger, backing } = setup();
    const op = { backing, from: ALICE, to: BACKER, quantity: 100n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), BACKER_SECRET))).toThrow(
      LedgerError,
    );
    expect(ledger.balance(backing, ALICE)).toBe(100n);
  });

  it("the operator cannot transfer out of a holding", () => {
    const { ledger, backing } = setup();
    const op = { backing, from: ALICE, to: OPERATOR, quantity: 100n, nonce: 0n };
    expect(() =>
      ledger.transfer(op, ed25519.sign(encodeTransfer(op), OPERATOR_SECRET)),
    ).toThrow(LedgerError);
    expect(ledger.balance(backing, ALICE)).toBe(100n);
  });

  it("the backer cannot burn a holder's claims", () => {
    const { ledger, backing } = setup();
    const op = { backing, holder: ALICE, quantity: 100n, nonce: 0n };
    expect(() => ledger.burn(op, ed25519.sign(encodeBurn(op), BACKER_SECRET))).toThrow(
      LedgerError,
    );
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("a signed transfer cannot be reversed by anyone but the new holder", () => {
    const { ledger, backing } = setup();
    const bobSecret = new Uint8Array(32).fill(0x05);
    const bob = ed25519.getPublicKey(bobSecret);
    const move = { backing, from: ALICE, to: bob, quantity: 100n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), ALICE_SECRET));

    // Alice regrets it; her signature over a reverse of Bob's holding fails.
    const reverse = { backing, from: bob, to: ALICE, quantity: 100n, nonce: 0n };
    expect(() =>
      ledger.transfer(reverse, ed25519.sign(encodeTransfer(reverse), ALICE_SECRET)),
    ).toThrow(LedgerError);
    // Bob's own signature succeeds — reversal is just a new transfer.
    ledger.transfer(reverse, ed25519.sign(encodeTransfer(reverse), bobSecret));
    expect(ledger.balance(backing, ALICE)).toBe(100n);
  });

  it("a captured message+signature cannot be replayed by a third party", () => {
    const { ledger, backing } = setup();
    const bobSecret = new Uint8Array(32).fill(0x05);
    const bob = ed25519.getPublicKey(bobSecret);
    const move = { backing, from: ALICE, to: bob, quantity: 10n, nonce: 0n };
    const signature = ed25519.sign(encodeTransfer(move), ALICE_SECRET);
    ledger.transfer(move, signature);
    // Mallory saw the message and signature on the wire and replays them.
    expect(() => ledger.transfer(move, signature)).toThrow(LedgerError);
    expect(ledger.balance(backing, bob)).toBe(10n);
  });
});
