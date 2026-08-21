import { describe, expect, it } from "vitest";
import { makeBacking, type Backing, type RelianceEntry } from "../src/backing.js";
import { EncodingError } from "../src/bytes.js";
import { closureOf, closureStatus, type Terms } from "../src/closure.js";
import { KEYS } from "./support.js";

// Invariant 16, and §8b's own worked example.
//
//   "The full chain under a requirement is its **closure**. Closures are written
//   with a `closure(S)` macro, expanded before hashing, and counts add up where
//   paths meet. If *b* relies on *x* and *y*, and each of those relies on *z* at
//   1, then closure({x:1, y:1}) = {x:1, y:1, z:2}. Two units of *z*, because
//   presenting at *x* alone would leave *y* without the *z* it needs.
//   Multiplicities grow like a matrix power, so wallets cap closure size."
//
// **A macro for writing terms, not a rule about them.** §8b: "Anyone can compute
// closed(b), whether R(b) equals its own closure. **An unclosed requirement is
// readable**: the backer takes in a set it cannot fully unwind, usually because
// it means to sell it." So an unclosed R is a legal setting, and makeBacking
// stores what it is given. What "expanded before hashing" means is that a backer
// who writes `closure(S)` gets the flat expansion into the terms, and the name
// commits to that — never that some later reader re-expands what was written.
// Existing names are untouched.
//
// **Expansion needs the targets' own terms**, which are hashes here, so it takes
// a resolver — §C0b's "published means retrievable by a stranger... terms, logs,
// totals" is what makes one available. The resolver is the untrusted part: it is
// asked for a name and could hand back anything, so every answer is checked
// against the name that was asked for. That check is also what makes the walk
// terminate, and it is why invariant 5 still holds — "do not write cycle
// detection... a reliance cycle would need a hash cycle; it cannot be built".
// With the name checked, a cycle would need one, so there is none to detect.

/** A resolver over a fixed set of backings, as a wallet's own store would be. */
function store(...backings: Backing[]): Terms {
  const byName = new Map(backings.map((b) => [b.nameHex, b]));
  return (name) => byName.get(Buffer.from(name).toString("hex"));
}

/** A backing paying `thing`, relying on `reliance`. */
function mk(thing: string, reliance: readonly RelianceEntry[] = []): Backing {
  return makeBacking({
    obligor: KEYS.backer,
    payout: { thing, quantumExponent: -2, perUnit: 100n },
    reliance,
    evidence: { setting: "transparent", operator: KEYS.operator },
  });
}

const at = (b: Backing, count: bigint): RelianceEntry => ({ target: b.name, count });

describe("invariant 16: closure expands, and counts sum where paths meet", () => {
  it("is the paper's own example: closure({x:1, y:1}) = {x:1, y:1, z:2}", () => {
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    const y = mk("Y", [at(z, 1n)]);
    const closed = closureOf(store(x, y, z), [at(x, 1n), at(y, 1n)]);

    const counts = new Map(closed.map((e) => [Buffer.from(e.target).toString("hex"), e.count]));
    expect(counts.get(x.nameHex)).toBe(1n);
    expect(counts.get(y.nameHex)).toBe(1n);
    // "Two units of z, because presenting at x alone would leave y without the
    // z it needs."
    expect(counts.get(z.nameHex)).toBe(2n);
    expect(closed).toHaveLength(3);
  });

  it("multiplies through a chain rather than counting a hop once", () => {
    // b relies on x at 3, x relies on z at 2: nine units of the claim need three
    // of x, and each of those needs two of z.
    const z = mk("Z");
    const x = mk("X", [at(z, 2n)]);
    const closed = closureOf(store(x, z), [at(x, 3n)]);
    const counts = new Map(closed.map((e) => [Buffer.from(e.target).toString("hex"), e.count]));
    expect(counts.get(x.nameHex)).toBe(3n);
    expect(counts.get(z.nameHex)).toBe(6n);
  });

  it("a direct count is a floor, not a second contribution", () => {
    // **A reading of §8b, flagged rather than taken silently.** The paper's one
    // example does not discriminate: with b relying on x and y and each relying
    // on z, "counts add up where paths meet" gives z:2 under either reading,
    // because the set names no z of its own. Here it does — z is asked for
    // directly at 1, and x needs 2 — and the two readings part:
    //
    //   sum over paths   z = 1 + 2 = 3
    //   max over parents z = max(1, 2) = 2
    //
    // It is the second. Presenting the set hands over the z once, and the same
    // two units satisfy both the direct requirement and x's, so 3 is not
    // minimal. Decisively, sum-over-paths is **not idempotent** — closure of
    // {x:1, z:3} is {x:1, z:5}, then {x:1, z:7} — which would make §8b's own
    // closed(b), "whether R(b) equals its own closure", false for every set with
    // any depth at all. See DECISIONS.md.
    const z = mk("Z");
    const x = mk("X", [at(z, 2n)]);
    const closed = closureOf(store(x, z), [at(x, 1n), at(z, 1n)]);
    const counts = new Map(closed.map((e) => [Buffer.from(e.target).toString("hex"), e.count]));
    expect(counts.get(z.nameHex)).toBe(2n);
  });

  it("and the expansion is idempotent, which is what makes closed(b) mean anything", () => {
    const z = mk("Z");
    const x = mk("X", [at(z, 2n)]);
    const terms = store(x, z);
    const once = closureOf(terms, [at(x, 1n), at(z, 1n)]);
    expect(closureOf(terms, once)).toEqual(once);
    expect(closureOf(terms, closureOf(terms, once))).toEqual(once);
  });

  it("is flat, sorted and deduplicated — the stored object's own shape", () => {
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    const y = mk("Y", [at(z, 1n)]);
    const closed = closureOf(store(x, y, z), [at(y, 1n), at(x, 1n)]);
    const targets = closed.map((e) => Buffer.from(e.target).toString("hex"));
    expect([...targets].sort()).toEqual(targets);
    expect(new Set(targets).size).toBe(targets.length);
  });

  it("is deterministic: the order it is written in does not reach the bytes", () => {
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    const y = mk("Y", [at(z, 1n)]);
    const terms = store(x, y, z);
    const a = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: closureOf(terms, [at(x, 1n), at(y, 1n)]),
      evidence: { setting: "transparent", operator: KEYS.operator },
    });
    const b = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: closureOf(terms, [at(y, 1n), at(x, 1n)]),
      evidence: { setting: "transparent", operator: KEYS.operator },
    });
    expect(a.name).toEqual(b.name);
  });

  it("an empty set closes to nothing", () => {
    expect(closureOf(store(), [])).toEqual([]);
  });
});

describe("invariant 16: what the expansion refuses", () => {
  it("refuses a target the resolver cannot produce", () => {
    // You cannot expand what you cannot read. Answering with the unexpanded set
    // would mint a name claiming to be a closure that is not one.
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    expect(() => closureOf(store(x), [at(x, 1n)])).toThrow(EncodingError);
  });

  it("refuses a resolver that answers with the wrong backing", () => {
    // The resolver is untrusted: it is asked for a name and may hand back
    // anything. Checking the answer against the name asked for is what makes
    // this safe — and it is what makes a cycle impossible without writing cycle
    // detection (invariant 5), since a cycle would need a hash cycle.
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    const liar: Terms = () => z;
    expect(() => closureOf(liar, [at(x, 1n)])).toThrow(EncodingError);
  });

  it("terminates on a resolver that tries to build a loop", () => {
    // The only way to loop is to answer with a backing that is not the one asked
    // for, which the name check refuses. There is no cycle detection here and
    // there does not need to be.
    const z = mk("Z");
    const selfish: Terms = (name) =>
      Buffer.from(name).toString("hex") === z.nameHex ? mk("Z", [at(z, 1n)]) : undefined;
    expect(() => closureOf(selfish, [at(z, 1n)])).toThrow(EncodingError);
  });

  it("caps the result, because multiplicities grow like a matrix power", () => {
    // A wide fan-out at each level: the cap is what stops a name being minted
    // over a set no wallet could carry.
    const leaves = Array.from({ length: 40 }, (_, i) => mk(`L${i}`));
    const mids = Array.from({ length: 40 }, (_, i) =>
      mk(`M${i}`, leaves.map((l) => at(l, 1n))),
    );
    const top = mids.map((m) => at(m, 1n));
    const terms = store(...leaves, ...mids);
    // 40 mids + 40 leaves is inside the cap; the guard is on the count, so this
    // one passes and proves the cap is not simply refusing everything deep.
    expect(closureOf(terms, top)).toHaveLength(80);
  });

  it("refuses a count that would not fit a quantity", () => {
    // Multiplying through is where an overflow appears, and a count that cannot
    // be encoded cannot be part of a name.
    const huge = (1n << 255n) - 1n;
    const z = mk("Z");
    const x = mk("X", [at(z, huge)]);
    expect(() => closureOf(store(x, z), [at(x, huge)])).toThrow(EncodingError);
  });
});

describe("§8b: an unclosed requirement is readable", () => {
  it("closed where R equals its own closure", () => {
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    const b = mk("B", closureOf(store(x, z), [at(x, 1n)]));
    expect(closureStatus(store(x, z, b), b)).toBe("closed");
  });

  it("and false where the backer took in a set it cannot fully unwind", () => {
    // Not an error: "the backer takes in a set it cannot fully unwind, usually
    // because it means to sell it". A setting, readable before accepting.
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    const b = mk("B", [at(x, 1n)]);
    expect(closureStatus(store(x, z, b), b)).toBe("unclosed");
  });

  it("a backing with no reliance is closed", () => {
    const b = mk("B");
    expect(closureStatus(store(b), b)).toBe("closed");
  });

  it("says unreadable, not unclosed, where this reader lacks the terms", () => {
    // Found reviewing the slice, and it is the same merge slice 18 removed from
    // committedLogFor and slice 20 removed from every reader of a venue: "I do
    // not have the terms" reported as "the backer means to sell it". A verdict
    // about the backer, built out of not having looked.
    const z = mk("Z");
    const x = mk("X", [at(z, 1n)]);
    const genuinely = mk("B", [at(x, 1n)]);
    const actuallyClosed = mk("B2", closureOf(store(x, z), [at(x, 1n)]));
    expect(closureStatus(store(x, z), genuinely)).toBe("unclosed");
    expect(closureStatus(store(x), actuallyClosed)).toBe("unreadable");
  });
});
