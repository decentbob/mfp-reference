import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { NonceError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { KEYS, register, SECRETS } from "./support.js";

// Invariant 7: issuance changes the outstanding count and needs the backer's
// signature. Movement of existing units preserves the count and needs no
// backer signature. Never one code path for both.

function setup() {
  const ledger = new TransparentLedger();
  const backing = register(ledger, SECRETS.backer);
  return { ledger, backing };
}

describe("invariant 7: issuance and movement are separate paths", () => {
  it("issuance raises issued and outstanding; movement touches neither", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    expect(ledger.issued(backing)).toBe(100n);
    expect(ledger.outstanding(backing)).toBe(100n);

    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(ledger.issued(backing)).toBe(100n);
    expect(ledger.burned(backing)).toBe(0n);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("movement needs no backer signature; issuance accepts no holder signature", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));

    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(ledger.balance(backing, KEYS.bob)).toBe(30n);

    // A holder cannot use the issuance path: the obligor's next nonce is 1.
    const fakeIssue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 1n };
    expect(() =>
      ledger.issue(fakeIssue, ed25519.sign(encodeIssuance(fakeIssue), SECRETS.alice)),
    ).toThrow(/only the obligor issues/);
  });

  it("an issuance message cannot be replayed", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    const signature = ed25519.sign(encodeIssuance(issue), SECRETS.backer);
    ledger.issue(issue, signature);
    expect(() => ledger.issue(issue, signature)).toThrow(NonceError);
    expect(ledger.issued(backing)).toBe(100n);
  });

  it("a transfer message cannot be replayed", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));

    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    const signature = ed25519.sign(encodeTransfer(move), SECRETS.alice);
    ledger.transfer(move, signature);
    expect(() => ledger.transfer(move, signature)).toThrow(NonceError);
    expect(ledger.balance(backing, KEYS.bob)).toBe(30n);
  });

  it("the operation log records issuance, transfer, and burn", () => {
    const { ledger, backing } = setup();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    const burn = { backing, holder: KEYS.bob, quantity: 10n, nonce: 0n };
    ledger.burn(burn, ed25519.sign(encodeBurn(burn), SECRETS.bob));

    expect(ledger.opLog(backing).map((e) => e.kind)).toEqual(["issue", "transfer", "burn"]);
    // Issuance is logged in the open with quantity and recipient (§C1).
    const log = ledger.opLog(backing).filter((entry) => entry.kind === "issue");
    expect(log.length).toBe(1);
    expect(log[0]?.quantity).toBe(100n);
    expect(log[0]?.recipient).toEqual(KEYS.alice);
  });
});

describe("invariant 7: nonces are per (signer, backing)", () => {
  it("a stuck op on one backing does not block the signer on another", () => {
    const ledger = new TransparentLedger();
    const eur = register(ledger, SECRETS.backer, "EUR");
    const kwh = register(ledger, SECRETS.backer2, "kWh");
    for (const [backing, secret] of [
      [eur, SECRETS.backer],
      [kwh, SECRETS.backer2],
    ] as const) {
      const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
      ledger.issue(issue, ed25519.sign(encodeIssuance(issue), secret));
    }

    // Alice never acts on EUR, yet her first kWh transfer at nonce 0 succeeds:
    // the counter is not shared across backings.
    const onKwh = { backing: kwh, from: KEYS.alice, to: KEYS.bob, quantity: 20n, nonce: 0n };
    ledger.transfer(onKwh, ed25519.sign(encodeTransfer(onKwh), SECRETS.alice));
    // And EUR is likewise still at nonce 0 for Alice.
    const onEur = { backing: eur, from: KEYS.alice, to: KEYS.bob, quantity: 20n, nonce: 0n };
    ledger.transfer(onEur, ed25519.sign(encodeTransfer(onEur), SECRETS.alice));

    expect(ledger.balance(kwh, KEYS.bob)).toBe(20n);
    expect(ledger.balance(eur, KEYS.bob)).toBe(20n);
    expect(ledger.nextNonce(KEYS.alice, eur)).toBe(1n);
    expect(ledger.nextNonce(KEYS.alice, kwh)).toBe(1n);
  });
});
