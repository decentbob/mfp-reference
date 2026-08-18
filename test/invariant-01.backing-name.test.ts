import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  backingName,
  decodeBacking,
  encodeBacking,
  type Backing,
} from "../src/backing.js";
import { EncodingError } from "../src/bytes.js";

// Invariant 1: a backing's name is the hash, under a declared function, of a
// canonical encoding of (K, P, R, E). Same fields must give the same bytes
// on every machine, forever; any field change must change the name; and no
// second byte-spelling of the same backing may be accepted.

const OBLIGOR = new Uint8Array(32).fill(0x11);
const OPERATOR = new Uint8Array(32).fill(0x22);
const TARGET_A = new Uint8Array(32).fill(0x33);
const TARGET_B = new Uint8Array(32).fill(0x44);

function baseBacking(): Backing {
  return {
    obligor: OBLIGOR,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [{ target: TARGET_A, count: 1n }],
    evidence: { setting: "transparent", operator: OPERATOR },
  };
}

// The layout stated independently of src/backing.ts, so the format itself is
// pinned by tests: if the implementation's byte layout drifts, this breaks.
function manualEncoding(options?: { relianceOrder?: "swapped"; trailingByte?: boolean }): Uint8Array {
  const parts: string[] = [];
  parts.push("4d465042"); // "MFPB"
  parts.push("01"); // version
  parts.push("01", bytesToHex(OBLIGOR)); // K: tag, key
  parts.push("01", "00000003", "455552", "fe", "00000001", "64"); // P: tag, "EUR", exp -2, perUnit 100
  const entryA = "01" + bytesToHex(TARGET_A) + "0000000101"; // tag, target, count 1
  const entryB = "01" + bytesToHex(TARGET_B) + "0000000102"; // tag, target, count 2
  parts.push("00000002"); // R: two entries
  parts.push(...(options?.relianceOrder === "swapped" ? [entryB, entryA] : [entryA, entryB]));
  parts.push("01", bytesToHex(OPERATOR)); // E: tag, operator
  if (options?.trailingByte) parts.push("00");
  return hexToBytes(parts.join(""));
}

const twoEntryBacking: Backing = {
  ...baseBacking(),
  reliance: [
    { target: TARGET_A, count: 1n },
    { target: TARGET_B, count: 2n },
  ],
};

describe("invariant 1: the name is the hash of a canonical encoding", () => {
  it("identical fields give identical bytes and an identical name", () => {
    expect(encodeBacking(baseBacking())).toEqual(encodeBacking(baseBacking()));
    expect(backingName(baseBacking())).toEqual(backingName(baseBacking()));
  });

  it("the encoding matches the documented byte layout exactly", () => {
    expect(bytesToHex(encodeBacking(twoEntryBacking))).toBe(bytesToHex(manualEncoding()));
  });

  it("reliance list order does not affect the name", () => {
    const reordered: Backing = {
      ...twoEntryBacking,
      reliance: [...twoEntryBacking.reliance].reverse(),
    };
    expect(backingName(reordered)).toEqual(backingName(twoEntryBacking));
  });

  it("every field change changes the name", () => {
    const base = baseBacking();
    const variants: Backing[] = [
      { ...base, obligor: new Uint8Array(32).fill(0x99) },
      { ...base, payout: { ...base.payout, thing: "USD" } },
      { ...base, payout: { ...base.payout, quantumExponent: -3 } },
      { ...base, payout: { ...base.payout, perUnit: 101n } },
      { ...base, reliance: [{ target: TARGET_A, count: 2n }] },
      { ...base, reliance: [{ target: TARGET_B, count: 1n }] },
      { ...base, reliance: [] },
      { ...base, evidence: { setting: "transparent", operator: new Uint8Array(32).fill(0x55) } },
    ];
    const names = new Set([bytesToHex(backingName(base))]);
    for (const variant of variants) {
      names.add(bytesToHex(backingName(variant)));
    }
    expect(names.size).toBe(variants.length + 1);
  });

  it("decode is the inverse of encode", () => {
    const decoded = decodeBacking(encodeBacking(twoEntryBacking));
    expect(decoded).toEqual(twoEntryBacking);
    expect(encodeBacking(decoded)).toEqual(encodeBacking(twoEntryBacking));
  });

  it("rejects a second spelling of the same backing", () => {
    expect(() => decodeBacking(manualEncoding({ relianceOrder: "swapped" }))).toThrow(
      EncodingError,
    );
    expect(() => decodeBacking(manualEncoding({ trailingByte: true }))).toThrow(
      EncodingError,
    );
  });

  it("rejects bytes that are not a backing at all", () => {
    const encoded = encodeBacking(baseBacking());
    const badMagic = encoded.slice();
    badMagic[0] = 0x00;
    expect(() => decodeBacking(badMagic)).toThrow(EncodingError);
    const badVersion = encoded.slice();
    badVersion[4] = 0x02;
    expect(() => decodeBacking(badVersion)).toThrow(EncodingError);
    expect(() => decodeBacking(encoded.slice(0, encoded.length - 1))).toThrow(
      EncodingError,
    );
  });

  it("rejects duplicate reliance targets", () => {
    const duplicated: Backing = {
      ...baseBacking(),
      reliance: [
        { target: TARGET_A, count: 1n },
        { target: TARGET_A, count: 2n },
      ],
    };
    expect(() => encodeBacking(duplicated)).toThrow(EncodingError);
  });

  it("rejects zero and negative quantities", () => {
    const base = baseBacking();
    expect(() =>
      encodeBacking({ ...base, payout: { ...base.payout, perUnit: 0n } }),
    ).toThrow(EncodingError);
    expect(() =>
      encodeBacking({ ...base, reliance: [{ target: TARGET_A, count: 0n }] }),
    ).toThrow(EncodingError);
    expect(() =>
      encodeBacking({ ...base, payout: { ...base.payout, perUnit: -1n } }),
    ).toThrow(EncodingError);
  });

  it("golden vector: encoding and name are frozen", () => {
    // These hex strings are the contract with every future implementation.
    // If this test ever fails, the format changed — that is a breaking event,
    // not a refactor.
    expect(bytesToHex(encodeBacking(twoEntryBacking))).toBe(GOLDEN_ENCODING_HEX);
    expect(bytesToHex(backingName(twoEntryBacking))).toBe(GOLDEN_NAME_HEX);
  });
});

const GOLDEN_ENCODING_HEX =
  "4d465042010111111111111111111111111111111111111111111111111111111111111111110100000003455552fe0000000164000000020133333333333333333333333333333333333333333333333333333333333333330000000101014444444444444444444444444444444444444444444444444444444444444444" +
  "0000000102012222222222222222222222222222222222222222222222222222222222222222";
const GOLDEN_NAME_HEX =
  "26379f3da4f22100b957e411445e18db9dd96f329cb5374075bff9d4a4ab4399";
