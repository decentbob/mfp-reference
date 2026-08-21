import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { backingName, type Backing, type RelianceEntry } from "../src/backing.js";
import { TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { replayLog } from "../src/ledger.js";
import { presentableFor } from "../src/presentability.js";
import { encodeDemand } from "../src/presentation.js";
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

// Invariant 13 defines presentability: "a holding is presentable at b for q if
// and only if it contains q units of b and q·cᵢ units of each (bᵢ, cᵢ) in R(b)."
// It was written and never enforced — presentation checked only the backing's
// own balance, and settlement moved only its own units, so a backer could be
// handed a claim without the accompaniment the invariant requires.
//
// §C3 licenses single-phase presentation "wherever every lock in the set can be
// taken in one atomically signed decision: R empty and the payout settling
// outside the claim layer, or the whole set and the paying leg inside one
// operator". Nothing checked the first condition, so the implementation was
// running outside the licence its own design rests on. Until the reliance legs
// exist a backing with reliance cannot be presented — and stays fully usable for
// everything else, because invariant 17 keeps an unaccompanied claim inert
// rather than invalid.

describe("§C3: presentation, and where a reliance leg is reserved", () => {
  const TARGET = new Uint8Array(32).fill(0x33);

  function withReliance(reliance: readonly RelianceEntry[]) {
    const ledger = new TransparentLedger();
    const backing = register(ledger, SECRETS.backer, "EUR", reliance);
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    return { ledger, backing };
  }

  const demandOn = (ledger: TransparentLedger, backing: Backing) => () => {
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 0n,
      deadline: 10n,
      nonce: ledger.nextNonce(KEYS.alice, backing),
    };
    return ledger.demand(op, ed25519.sign(encodeDemand(op), SECRETS.alice), 0n);
  };

  it("takes a demand on a backing that relies on another, and says nothing about the legs", () => {
    // This refused until slice 22. The ledger is per backing and invariant 13's
    // q·cᵢ units live in other backings' states, so THIS state cannot check them
    // and no longer pretends to: each leg is reserved by a lock in its own log,
    // and the sequencer takes the demand and every lock as one set or none.
    const { ledger, backing } = withReliance([{ target: TARGET, count: 2n }]);
    expect(demandOn(ledger, backing)()).toMatchObject({ kind: "demand", quantity: 40n });
    expect(ledger.openDemands(backing)).toHaveLength(1);
  });

  it("and the claim was inert rather than invalid throughout (invariant 17)", () => {
    // True while the presentation was refused, and still true now.
    const { ledger, backing } = withReliance([{ target: TARGET, count: 2n }]);
    const move = {
      backing,
      from: KEYS.alice,
      to: KEYS.bob,
      quantity: 30n,
      nonce: ledger.nextNonce(KEYS.alice, backing),
    };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(ledger.balance(backing, KEYS.bob)).toBe(30n);
    const burn = {
      backing,
      holder: KEYS.bob,
      quantity: 10n,
      nonce: ledger.nextNonce(KEYS.bob, backing),
    };
    ledger.burn(burn, ed25519.sign(encodeBurn(burn), SECRETS.bob));
    expect(ledger.outstanding(backing)).toBe(90n);
  });

  it("a backing with no reliance presents as before", () => {
    const { ledger, backing } = withReliance([]);
    expect(demandOn(ledger, backing)()).toMatchObject({ kind: "demand", quantity: 40n });
  });

  it("and such a log replays, because the leg is another backing's record", () => {
    // The mirror of the above on the other input. A verifier folding THIS
    // backing's log sees a lawful demand; whether its legs were locked is read
    // across the served state, where the leg backings' own logs are.
    const { ledger, backing } = withReliance([{ target: TARGET, count: 2n }]);
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 0n,
      deadline: 10n,
      nonce: 0n,
    };
    const entry = {
      position: 1,
      kind: "demand" as const,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 0n,
      deadline: 10n,
      nonce: 0n,
      signature: ed25519.sign(encodeDemand(op), SECRETS.alice),
    };
    expect(replayLog(backing, [...ledger.opLog(backing), entry])).toBeDefined();
  });
});
