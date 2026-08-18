import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { backingName, makeBacking, signBacking, type Backing } from "../src/backing.js";
import { TransparentLedger } from "../src/ledger.js";
import { encodeIssuance } from "../src/messages.js";
import { presentableFor } from "../src/presentability.js";

// Invariant 13: a holding is presentable at b for q iff it contains q units
// of b and q·cᵢ units of each (bᵢ, cᵢ) in R(b). Units, never claims. One
// level, no traversal.

const BACKER_SECRET = new Uint8Array(32).fill(0x01);
const A_SECRET = new Uint8Array(32).fill(0x02);
const C_SECRET = new Uint8Array(32).fill(0x08);
const ALICE_SECRET = new Uint8Array(32).fill(0x03);
const ALICE = ed25519.getPublicKey(ALICE_SECRET);
const OPERATOR = new Uint8Array(32).fill(0x22);

function registered(
  ledger: TransparentLedger,
  secret: Uint8Array,
  thing: string,
  reliance: Backing["reliance"] = [],
): Backing {
  const backing = makeBacking({
    obligor: ed25519.getPublicKey(secret),
    payout: { thing, quantumExponent: -2, perUnit: 100n },
    reliance,
    evidence: { setting: "transparent", operator: OPERATOR },
  });
  ledger.register(backing, signBacking(secret, backing));
  return backing;
}

function give(ledger: TransparentLedger, secret: Uint8Array, backing: Backing, quantity: bigint, nonce: bigint) {
  const op = { backing, recipient: ALICE, quantity, nonce };
  ledger.issue(op, ed25519.sign(encodeIssuance(op), secret));
}

describe("invariant 13: presentability is unit arithmetic over one level", () => {
  it("with empty reliance, presentable exactly up to the balance", () => {
    const ledger = new TransparentLedger();
    const b = registered(ledger, BACKER_SECRET, "EUR");
    give(ledger, BACKER_SECRET, b, 10n, 0n);
    const view = ledger.holdingView(ALICE);
    expect(presentableFor(view, b, 10n)).toBe(true);
    expect(presentableFor(view, b, 11n)).toBe(false);
    expect(presentableFor(view, b, 1n)).toBe(true);
  });

  it("with reliance (A,2): q needs q units of b and 2q of A", () => {
    const ledger = new TransparentLedger();
    const a = registered(ledger, A_SECRET, "USD");
    const b = registered(ledger, BACKER_SECRET, "EUR", [
      { target: backingName(a), count: 2n },
    ]);
    give(ledger, BACKER_SECRET, b, 10n, 0n);
    give(ledger, A_SECRET, a, 19n, 0n);
    const view = ledger.holdingView(ALICE);
    // 19 units of A cover q=9 (needs 18) but not q=10 (needs 20).
    expect(presentableFor(view, b, 9n)).toBe(true);
    expect(presentableFor(view, b, 10n)).toBe(false);
  });

  it("one level only: the reliance of a reliance is not consulted", () => {
    const ledger = new TransparentLedger();
    const c = registered(ledger, C_SECRET, "XAU");
    const a = registered(ledger, A_SECRET, "USD", [{ target: backingName(c), count: 5n }]);
    const b = registered(ledger, BACKER_SECRET, "EUR", [
      { target: backingName(a), count: 1n },
    ]);
    give(ledger, BACKER_SECRET, b, 10n, 0n);
    give(ledger, A_SECRET, a, 10n, 0n);
    // Alice holds no C at all. A's own reliance is A's presentation problem,
    // not b's: b must still be presentable.
    const view = ledger.holdingView(ALICE);
    expect(presentableFor(view, b, 10n)).toBe(true);
    expect(presentableFor(view, a, 1n)).toBe(false);
  });

  it("quantity must be a whole positive number of units", () => {
    const ledger = new TransparentLedger();
    const b = registered(ledger, BACKER_SECRET, "EUR");
    give(ledger, BACKER_SECRET, b, 10n, 0n);
    const view = ledger.holdingView(ALICE);
    expect(presentableFor(view, b, 0n)).toBe(false);
    expect(presentableFor(view, b, -1n)).toBe(false);
  });
});
