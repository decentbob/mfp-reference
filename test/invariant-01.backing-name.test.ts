import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  backingName,
  decodeBacking,
  encodeBacking,
  makeBacking,
  type BackingFields,
} from "../src/backing.js";
import { EncodingError } from "../src/bytes.js";

// Invariant 1: a backing's name is the hash, under a declared function, of a
// canonical encoding of (K, P, R, E). Same fields must give the same bytes
// on every machine, forever; any field change must change the name; and no
// second byte-spelling of the same backing may be accepted.

// Obligors must be real, non-small-order Ed25519 points, so fixtures derive
// them from fixed seeds rather than using arbitrary bytes.
const OBLIGOR = ed25519.getPublicKey(new Uint8Array(32).fill(0x01));
const OBLIGOR_2 = ed25519.getPublicKey(new Uint8Array(32).fill(0x02));
const OPERATOR = new Uint8Array(32).fill(0x22); // a key, validated by length only
const TARGET_A = new Uint8Array(32).fill(0x33); // a backing name (hash), any 32 bytes
const TARGET_B = new Uint8Array(32).fill(0x44);

function baseFields(): BackingFields {
  return {
    obligor: OBLIGOR,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [{ target: TARGET_A, count: 1n }],
    evidence: { setting: "transparent", operator: OPERATOR },
  };
}

const twoEntry = makeBacking({
  ...baseFields(),
  reliance: [
    { target: TARGET_A, count: 1n },
    { target: TARGET_B, count: 2n },
  ],
});

// The layout stated independently of src/backing.ts, so the format itself is
// pinned by tests: if the implementation's byte layout drifts, this breaks.
function manualEncoding(options?: {
  relianceOrder?: "swapped";
  trailingByte?: boolean;
  nonMinimalPerUnit?: boolean;
  unknownEvidenceTag?: boolean;
}): Uint8Array {
  const parts: string[] = [];
  parts.push("4d465042"); // "MFPB"
  parts.push("01"); // version
  parts.push("01", bytesToHex(OBLIGOR)); // K: tag, key
  const perUnit = options?.nonMinimalPerUnit ? "000000020064" : "0000000164";
  parts.push("01", "00000003", "455552", "fe", perUnit); // P: tag, "EUR", exp -2, perUnit 100
  const entryA = "01" + bytesToHex(TARGET_A) + "0000000101"; // tag, target, count 1
  const entryB = "01" + bytesToHex(TARGET_B) + "0000000102"; // tag, target, count 2
  parts.push("00000002"); // R: two entries
  parts.push(...(options?.relianceOrder === "swapped" ? [entryB, entryA] : [entryA, entryB]));
  parts.push(options?.unknownEvidenceTag ? "02" : "01", bytesToHex(OPERATOR)); // E: tag, operator
  if (options?.trailingByte) parts.push("00");
  return hexToBytes(parts.join(""));
}

describe("invariant 1: the name is the hash of a canonical encoding", () => {
  it("identical fields give identical bytes and an identical name", () => {
    expect(encodeBacking(makeBacking(baseFields()))).toEqual(
      encodeBacking(makeBacking(baseFields())),
    );
    expect(backingName(makeBacking(baseFields()))).toEqual(
      backingName(makeBacking(baseFields())),
    );
  });

  it("the implementation's encoding matches the documented byte layout", () => {
    expect(bytesToHex(encodeBacking(twoEntry))).toBe(bytesToHex(manualEncoding()));
  });

  it("reliance list order does not affect the name", () => {
    const reordered = makeBacking({
      ...baseFields(),
      reliance: [
        { target: TARGET_B, count: 2n },
        { target: TARGET_A, count: 1n },
      ],
    });
    expect(backingName(reordered)).toEqual(backingName(twoEntry));
  });

  it("every field change changes the name", () => {
    const base = baseFields();
    const variants: BackingFields[] = [
      { ...base, obligor: OBLIGOR_2 },
      { ...base, payout: { ...base.payout, thing: "USD" } },
      { ...base, payout: { ...base.payout, quantumExponent: -3 } },
      { ...base, payout: { ...base.payout, perUnit: 101n } },
      { ...base, reliance: [{ target: TARGET_A, count: 2n }] },
      { ...base, reliance: [{ target: TARGET_B, count: 1n }] },
      { ...base, reliance: [] },
      { ...base, evidence: { setting: "transparent", operator: new Uint8Array(32).fill(0x55) } },
    ];
    const names = new Set([bytesToHex(backingName(makeBacking(base)))]);
    for (const variant of variants) {
      names.add(bytesToHex(backingName(makeBacking(variant))));
    }
    expect(names.size).toBe(variants.length + 1);
  });

  it("decode is the inverse of encode", () => {
    const decoded = decodeBacking(encodeBacking(twoEntry));
    expect(encodeBacking(decoded)).toEqual(encodeBacking(twoEntry));
    expect(decoded.payout).toEqual(twoEntry.payout);
    expect(decoded.reliance).toEqual(twoEntry.reliance);
  });

  it("a decoded backing does not alias its source buffer", () => {
    // Node Buffer.slice returns a view; decoding from one must still copy, or
    // a reused socket buffer would silently mutate an accepted backing.
    const buffer = Buffer.from(encodeBacking(twoEntry));
    const decoded = decodeBacking(buffer);
    const nameBefore = bytesToHex(backingName(decoded));
    buffer.fill(0xff);
    expect(bytesToHex(backingName(decoded))).toBe(nameBefore);
  });

  it("a validated backing is frozen against structural mutation", () => {
    const b = makeBacking(baseFields());
    expect(Object.isFrozen(b)).toBe(true);
    expect(Object.isFrozen(b.reliance)).toBe(true);
    expect(Object.isFrozen(b.payout)).toBe(true);
    expect(Object.isFrozen(b.evidence)).toBe(true);
    // A frozen array rejects structural mutation under ESM strict mode.
    expect(() => (b.reliance as unknown as unknown[]).push(0)).toThrow();
  });

  it("rejects a second spelling of the same backing", () => {
    expect(() => decodeBacking(manualEncoding({ relianceOrder: "swapped" }))).toThrow(
      EncodingError,
    );
    expect(() => decodeBacking(manualEncoding({ trailingByte: true }))).toThrow(EncodingError);
    // A non-minimal integer (leading zero byte) is the strongest second
    // spelling: same value, different bytes. It must be rejected.
    expect(() => decodeBacking(manualEncoding({ nonMinimalPerUnit: true }))).toThrow(
      EncodingError,
    );
  });

  it("rejects bytes that are not a backing at all", () => {
    const encoded = encodeBacking(baseFieldsBacking());
    const badMagic = encoded.slice();
    badMagic[0] = 0x00;
    expect(() => decodeBacking(badMagic)).toThrow(EncodingError);
    const badVersion = encoded.slice();
    badVersion[4] = 0x02;
    expect(() => decodeBacking(badVersion)).toThrow(EncodingError);
    expect(() => decodeBacking(encoded.slice(0, encoded.length - 1))).toThrow(EncodingError);
    expect(() => decodeBacking(manualEncoding({ unknownEvidenceTag: true }))).toThrow(
      EncodingError,
    );
  });

  it("rejects a payout thing with unpaired surrogates", () => {
    expect(() =>
      makeBacking({ ...baseFields(), payout: { thing: "EUR\uD800", quantumExponent: -2, perUnit: 100n } }),
    ).toThrow(EncodingError);
  });

  it("rejects duplicate reliance targets", () => {
    expect(() =>
      makeBacking({
        ...baseFields(),
        reliance: [
          { target: TARGET_A, count: 1n },
          { target: TARGET_A, count: 2n },
        ],
      }),
    ).toThrow(EncodingError);
  });

  it("rejects zero and negative quantities", () => {
    const base = baseFields();
    expect(() => makeBacking({ ...base, payout: { ...base.payout, perUnit: 0n } })).toThrow(
      EncodingError,
    );
    expect(() =>
      makeBacking({ ...base, reliance: [{ target: TARGET_A, count: 0n }] }),
    ).toThrow(EncodingError);
    expect(() => makeBacking({ ...base, payout: { ...base.payout, perUnit: -1n } })).toThrow(
      EncodingError,
    );
  });

  it("golden vector: the layout and name are frozen", () => {
    // GOLDEN_ENCODING_HEX freezes the documented layout as a literal contract;
    // manualEncoding is the single expected-bytes source checked against the
    // implementation above. GOLDEN_NAME_HEX is SHA-256 of those exact bytes.
    // If either fails, the format changed — a breaking event, not a refactor.
    expect(bytesToHex(manualEncoding())).toBe(GOLDEN_ENCODING_HEX);
    expect(bytesToHex(backingName(twoEntry))).toBe(GOLDEN_NAME_HEX);
  });
});

function baseFieldsBacking() {
  return makeBacking(baseFields());
}

const GOLDEN_ENCODING_HEX =
  "4d46504201018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0100000003455552fe0000000164000000020133333333333333333333333333333333333333333333333333333333333333330000000101014444444444444444444444444444444444444444444444444444444444444444" +
  "0000000102012222222222222222222222222222222222222222222222222222222222222222";
const GOLDEN_NAME_HEX = "9be9c2da6e525a84f632d0ff4ca502a03c66e9a693f8aa59089dc5fd36fcb5c9";
