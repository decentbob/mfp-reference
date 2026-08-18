import { describe, expect, it } from "vitest";

// Toolchain smoke test — and a demonstration of why CLAUDE.md forbids
// `number` for quantities.

describe("toolchain", () => {
  it("floating point cannot carry quantities", () => {
    // This is the bug class the bigint rule exists to prevent.
    expect(0.1 + 0.2 === 0.3).toBe(false);
  });

  it("bigint arithmetic is exact at any size", () => {
    const oneQuadrillion = 1_000_000_000_000_000n;
    expect(oneQuadrillion * oneQuadrillion + 1n - 1n).toBe(
      1_000_000_000_000_000_000_000_000_000_000n,
    );
  });
});
