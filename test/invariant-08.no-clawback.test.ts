import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { NonceError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { KEYS, register, SECRETS } from "./support.js";

// Invariant 8: no clawback, no reversal, no privileged party who can move
// claims. The rule is not "don't call it" — the path must not exist. These
// tests prove every mutation route demands the holder's own signature, and
// that no accessor hands out a live write path into ledger state.

function setup() {
  const ledger = new TransparentLedger();
  const backing = register(ledger, SECRETS.backer);
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { ledger, backing };
}

describe("invariant 8: no privileged party can move a holder's claims", () => {
  it("the backer cannot transfer out of a holding", () => {
    const { ledger, backing } = setup();
    const op = { backing, from: KEYS.alice, to: KEYS.backer, quantity: 100n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), SECRETS.backer))).toThrow(
      /only the holder moves/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("the operator cannot transfer out of a holding", () => {
    const { ledger, backing } = setup();
    const op = { backing, from: KEYS.alice, to: KEYS.operator, quantity: 100n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), SECRETS.operator))).toThrow(
      /only the holder moves/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("the backer cannot burn a holder's claims", () => {
    const { ledger, backing } = setup();
    const op = { backing, holder: KEYS.alice, quantity: 100n, nonce: 0n };
    expect(() => ledger.burn(op, ed25519.sign(encodeBurn(op), SECRETS.backer))).toThrow(
      /only the holder burns/,
    );
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("a signed transfer cannot be reversed by anyone but the new holder", () => {
    const { ledger, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 100n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));

    // Alice regrets it; her signature over a reverse of Bob's holding fails.
    const reverse = { backing, from: KEYS.bob, to: KEYS.alice, quantity: 100n, nonce: 0n };
    expect(() => ledger.transfer(reverse, ed25519.sign(encodeTransfer(reverse), SECRETS.alice))).toThrow(
      /only the holder moves/,
    );
    // Bob's own signature succeeds — reversal is just a new transfer.
    ledger.transfer(reverse, ed25519.sign(encodeTransfer(reverse), SECRETS.bob));
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("a captured message+signature cannot be replayed by a third party", () => {
    const { ledger, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 10n, nonce: 0n };
    const signature = ed25519.sign(encodeTransfer(move), SECRETS.alice);
    ledger.transfer(move, signature);
    expect(() => ledger.transfer(move, signature)).toThrow(NonceError);
    expect(ledger.balance(backing, KEYS.bob)).toBe(10n);
  });
});

describe("invariant 8: accessors expose no mutation path into ledger state", () => {
  it("mutating the map from balancesOf cannot mint units", () => {
    const { ledger, backing } = setup();
    ledger.balancesOf(backing).set(bytesToHex(KEYS.mallory), 10n ** 9n);
    expect(ledger.balance(backing, KEYS.mallory)).toBe(0n);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("mutating the array from opLog/issuanceLog cannot fabricate records", () => {
    const { ledger, backing } = setup();
    ledger.opLog(backing).push({
      position: 99,
      kind: "issue",
      recipient: KEYS.mallory,
      quantity: 10n ** 9n,
      nonce: 0n,
    });
    ledger.issuanceLog(backing)[0]!.recipient.fill(0xff);
    expect(ledger.opLog(backing).length).toBe(1);
    expect(ledger.issuanceLog(backing)[0]!.recipient).toEqual(KEYS.alice);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("mutating a registered backing's key bytes does not re-home its state", () => {
    const { ledger, backing } = setup();
    backing.obligor[0] = (backing.obligor[0] as number) ^ 0x01;
    // The name was fixed at construction, so the backing still resolves.
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });
});
