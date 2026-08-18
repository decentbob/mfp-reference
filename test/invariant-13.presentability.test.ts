import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { backingName } from "../src/backing.js";
import { TransparentLedger } from "../src/ledger.js";
import { encodeIssuance } from "../src/messages.js";
import { presentableFor } from "../src/presentability.js";
import { KEYS, register, SECRETS } from "./support.js";

// Invariant 13: a holding is presentable at b for q iff it contains q units
// of b and q·cᵢ units of each (bᵢ, cᵢ) in R(b). Units, never claims. One
// level, no traversal.

function give(
  ledger: TransparentLedger,
  secret: Uint8Array,
  backing: Parameters<typeof encodeIssuance>[0]["backing"],
  quantity: bigint,
  nonce: bigint,
) {
  const op = { backing, recipient: KEYS.alice, quantity, nonce };
  ledger.issue(op, ed25519.sign(encodeIssuance(op), secret));
}

describe("invariant 13: presentability is unit arithmetic over one level", () => {
  it("with empty reliance, presentable exactly up to the balance", () => {
    const ledger = new TransparentLedger();
    const b = register(ledger, SECRETS.backer, "EUR");
    give(ledger, SECRETS.backer, b, 10n, 0n);
    const view = ledger.holdingView(KEYS.alice);
    expect(presentableFor(view, b, 10n)).toBe(true);
    expect(presentableFor(view, b, 11n)).toBe(false);
    expect(presentableFor(view, b, 1n)).toBe(true);
  });

  it("with reliance (A,2): q needs q units of b and 2q of A", () => {
    const ledger = new TransparentLedger();
    const a = register(ledger, SECRETS.backer2, "USD");
    const b = register(ledger, SECRETS.backer, "EUR", [{ target: backingName(a), count: 2n }]);
    give(ledger, SECRETS.backer, b, 10n, 0n);
    give(ledger, SECRETS.backer2, a, 19n, 0n);
    const view = ledger.holdingView(KEYS.alice);
    // 19 units of A cover q=9 (needs 18) but not q=10 (needs 20).
    expect(presentableFor(view, b, 9n)).toBe(true);
    expect(presentableFor(view, b, 10n)).toBe(false);
  });

  it("one level only: the reliance of a reliance is not consulted", () => {
    const ledger = new TransparentLedger();
    const c = register(ledger, SECRETS.carol, "XAU");
    const a = register(ledger, SECRETS.backer2, "USD", [{ target: backingName(c), count: 5n }]);
    const b = register(ledger, SECRETS.backer, "EUR", [{ target: backingName(a), count: 1n }]);
    give(ledger, SECRETS.backer, b, 10n, 0n);
    give(ledger, SECRETS.backer2, a, 10n, 0n);
    // Alice holds no C at all. A's own reliance is A's presentation problem,
    // not b's: b must still be presentable.
    const view = ledger.holdingView(KEYS.alice);
    expect(presentableFor(view, b, 10n)).toBe(true);
    expect(presentableFor(view, a, 1n)).toBe(false);
  });

  it("quantity must be a whole positive number of units", () => {
    const ledger = new TransparentLedger();
    const b = register(ledger, SECRETS.backer, "EUR");
    give(ledger, SECRETS.backer, b, 10n, 0n);
    const view = ledger.holdingView(KEYS.alice);
    expect(presentableFor(view, b, 0n)).toBe(false);
    expect(presentableFor(view, b, -1n)).toBe(false);
  });
});
