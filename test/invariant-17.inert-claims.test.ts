import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { backingName, makeBacking, signBacking } from "../src/backing.js";
import { TransparentLedger } from "../src/ledger.js";
import { encodeIssuance, encodeTransfer } from "../src/messages.js";
import { presentableFor } from "../src/presentability.js";

// Invariant 17: an unaccompanied claim is inert, never invalid, and still
// transferable.

const BACKER_SECRET = new Uint8Array(32).fill(0x01);
const A_SECRET = new Uint8Array(32).fill(0x02);
const ALICE_SECRET = new Uint8Array(32).fill(0x03);
const BOB_SECRET = new Uint8Array(32).fill(0x05);
const ALICE = ed25519.getPublicKey(ALICE_SECRET);
const BOB = ed25519.getPublicKey(BOB_SECRET);
const OPERATOR = new Uint8Array(32).fill(0x22);

describe("invariant 17: an unaccompanied claim is inert, never invalid", () => {
  it("without its reliance a claim is not presentable, but still moves", () => {
    const ledger = new TransparentLedger();
    const a = makeBacking({
      obligor: ed25519.getPublicKey(A_SECRET),
      payout: { thing: "USD", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: { setting: "transparent", operator: OPERATOR },
    });
    ledger.register(a, signBacking(A_SECRET, a));
    const b = makeBacking({
      obligor: ed25519.getPublicKey(BACKER_SECRET),
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [{ target: backingName(a), count: 1n }],
      evidence: { setting: "transparent", operator: OPERATOR },
    });
    ledger.register(b, signBacking(BACKER_SECRET, b));

    const issue = { backing: b, recipient: ALICE, quantity: 10n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), BACKER_SECRET));

    // Alice holds no A: her b-claims are inert...
    expect(presentableFor(ledger.holdingView(ALICE), b, 1n)).toBe(false);

    // ...but not invalid: they transfer exactly like any claim.
    const move = { backing: b, from: ALICE, to: BOB, quantity: 10n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), ALICE_SECRET));
    expect(ledger.balance(b, BOB)).toBe(10n);

    // And they wake up the moment the accompaniment arrives.
    const giveA = { backing: a, recipient: BOB, quantity: 10n, nonce: 0n };
    ledger.issue(giveA, ed25519.sign(encodeIssuance(giveA), A_SECRET));
    expect(presentableFor(ledger.holdingView(BOB), b, 10n)).toBe(true);
  });
});
