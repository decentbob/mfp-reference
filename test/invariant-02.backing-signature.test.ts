import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import {
  signBacking,
  verifyBackingSignature,
  type Backing,
} from "../src/backing.js";
import { EncodingError } from "../src/bytes.js";

// Invariant 2: a backing exists only with a valid signature by K over its
// own name — or anyone can publish well-formed terms naming somebody else's
// key as obligor.

const OBLIGOR_SECRET = new Uint8Array(32).fill(0x01);
const STRANGER_SECRET = new Uint8Array(32).fill(0x02);
const OBLIGOR = ed25519.getPublicKey(OBLIGOR_SECRET);
const OPERATOR = new Uint8Array(32).fill(0x22);

function backing(overrides?: Partial<Backing>): Backing {
  return {
    obligor: OBLIGOR,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: OPERATOR },
    ...overrides,
  };
}

describe("invariant 2: a backing exists only with K's signature over its name", () => {
  it("the obligor's signature over the name verifies", () => {
    const b = backing();
    const signature = signBacking(OBLIGOR_SECRET, b);
    expect(verifyBackingSignature(b, signature)).toBe(true);
  });

  it("a stranger cannot sign terms naming somebody else's key as obligor", () => {
    expect(() => signBacking(STRANGER_SECRET, backing())).toThrow(EncodingError);
  });

  it("a stranger's signature does not verify against the obligor's key", () => {
    const b = backing();
    const forged = signBacking(STRANGER_SECRET, {
      ...b,
      obligor: ed25519.getPublicKey(STRANGER_SECRET),
    });
    expect(verifyBackingSignature(b, forged)).toBe(false);
  });

  it("a signature over one backing does not carry to changed terms", () => {
    const original = backing();
    const signature = signBacking(OBLIGOR_SECRET, original);
    const changedTerms = backing({
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 200n },
    });
    expect(verifyBackingSignature(changedTerms, signature)).toBe(false);
  });

  it("a corrupted signature does not verify", () => {
    const b = backing();
    const signature = signBacking(OBLIGOR_SECRET, b);
    const corrupted = signature.slice();
    corrupted[0] = (corrupted[0] as number) ^ 0xff;
    expect(verifyBackingSignature(b, corrupted)).toBe(false);
  });
});
