import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { backingName } from "../src/backing.js";
import { TransparentLedger } from "../src/ledger.js";
import { encodeIssuance, encodeTransfer } from "../src/messages.js";
import { presentableFor } from "../src/presentability.js";
import { KEYS, register, SECRETS } from "./support.js";

// Invariant 17: an unaccompanied claim is inert, never invalid, and still
// transferable.

describe("invariant 17: an unaccompanied claim is inert, never invalid", () => {
  it("without its reliance a claim is not presentable, but still moves", () => {
    const ledger = new TransparentLedger();
    const a = register(ledger, SECRETS.backer2, "USD");
    const b = register(ledger, SECRETS.backer, "EUR", [{ target: backingName(a), count: 1n }]);

    const issue = { backing: b, recipient: KEYS.alice, quantity: 10n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));

    // Alice holds no A: her b-claims are inert...
    expect(presentableFor(ledger.holdingView(KEYS.alice), b, 1n)).toBe(false);

    // ...but not invalid: they transfer exactly like any claim.
    const move = { backing: b, from: KEYS.alice, to: KEYS.bob, quantity: 10n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(ledger.balance(b, KEYS.bob)).toBe(10n);

    // And they wake up the moment the accompaniment arrives.
    const giveA = { backing: a, recipient: KEYS.bob, quantity: 10n, nonce: 0n };
    ledger.issue(giveA, ed25519.sign(encodeIssuance(giveA), SECRETS.backer2));
    expect(presentableFor(ledger.holdingView(KEYS.bob), b, 10n)).toBe(true);
  });
});
