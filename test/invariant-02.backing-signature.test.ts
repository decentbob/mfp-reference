import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import {
  makeBacking,
  signBacking,
  SigningError,
  verifyBackingSignature,
  type BackingFields,
} from "../src/backing.js";
import { EncodingError } from "../src/bytes.js";

// Invariant 2: a backing exists only with a valid signature by K over its
// own name — or anyone can publish well-formed terms naming somebody else's
// key as obligor.

const OBLIGOR_SECRET = new Uint8Array(32).fill(0x01);
const STRANGER_SECRET = new Uint8Array(32).fill(0x02);
const OBLIGOR = ed25519.getPublicKey(OBLIGOR_SECRET);
const OPERATOR = new Uint8Array(32).fill(0x22);

function fields(overrides?: Partial<BackingFields>): BackingFields {
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
    const b = makeBacking(fields());
    expect(verifyBackingSignature(b, signBacking(OBLIGOR_SECRET, b))).toBe(true);
  });

  it("a stranger cannot sign terms naming somebody else's key as obligor", () => {
    expect(() => signBacking(STRANGER_SECRET, makeBacking(fields()))).toThrow(SigningError);
  });

  it("a stranger's signature does not verify against the obligor's key", () => {
    const b = makeBacking(fields());
    const forged = signBacking(STRANGER_SECRET, makeBacking(fields({ obligor: ed25519.getPublicKey(STRANGER_SECRET) })));
    expect(verifyBackingSignature(b, forged)).toBe(false);
  });

  it("a signature over one backing does not carry to changed terms", () => {
    const original = makeBacking(fields());
    const signature = signBacking(OBLIGOR_SECRET, original);
    const changed = makeBacking(fields({ payout: { thing: "EUR", quantumExponent: -2, perUnit: 200n } }));
    expect(verifyBackingSignature(changed, signature)).toBe(false);
  });

  it("a corrupted signature does not verify", () => {
    const b = makeBacking(fields());
    const signature = signBacking(OBLIGOR_SECRET, b);
    const corrupted = signature.slice();
    corrupted[0] = (corrupted[0] as number) ^ 0xff;
    expect(verifyBackingSignature(b, corrupted)).toBe(false);
  });

  it("a wrong-length signature returns false instead of throwing", () => {
    const b = makeBacking(fields());
    for (const length of [0, 63, 65]) {
      expect(verifyBackingSignature(b, new Uint8Array(length))).toBe(false);
    }
  });

  it("a small-order obligor key cannot be made into a backing", () => {
    // The identity point (0x01 then zeros) would accept a forged signature
    // over any name; makeBacking must reject it at construction.
    const identity = new Uint8Array(32);
    identity[0] = 0x01;
    expect(() => makeBacking(fields({ obligor: identity }))).toThrow(EncodingError);
  });

  it("a malformed secret key raises a SigningError, not an opaque error", () => {
    const b = makeBacking(fields());
    expect(() => signBacking(new Uint8Array(31), b)).toThrow(SigningError);
  });
});
