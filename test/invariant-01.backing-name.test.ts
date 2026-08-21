import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  backingName,
  decodeBacking,
  encodeBacking,
  makeBacking,
  type BackingFields,
  type ConstantPayout,
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
const OPERATOR = new Uint8Array(32).fill(0x22); // a valid non-small-order point
const TARGET_A = new Uint8Array(32).fill(0x33); // a backing name (hash), any 32 bytes
const TARGET_B = new Uint8Array(32).fill(0x44);
const VENUE_ID = new Uint8Array(32).fill(0x55); // a venue identity, any 32 bytes
const OTHER_VENUE_ID = new Uint8Array(32).fill(0x66);

// The two clauses that exist, as the bytes they are written as.
const SILENCE_CLAUSE_HEX = "01" + "0000000000000032" + "0000000000000005";
const WITNESSING_CLAUSE_HEX = "02" + bytesToHex(VENUE_ID) + "000000000000000a";

/** A well-formed backing with its whole E field replaced by hand-built bytes. */
function withEvidence(evidenceHex: string): Uint8Array {
  const base = encodeBacking(makeBacking(baseFields()));
  // Tag 0x01 is one tag byte and a 32-byte operator key, at the very end.
  return hexToBytes(bytesToHex(base.slice(0, base.length - 33)) + evidenceHex);
}

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

  it("backingName returns a fresh array each call (cache cannot be poisoned)", () => {
    const b = makeBacking(baseFields());
    const first = backingName(b);
    first.fill(0);
    expect(backingName(b)).toEqual(backingName(makeBacking(baseFields())));
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

  it("a payout thing with a byte-order mark round-trips to one name", () => {
    // A BOM-stripping decoder would give one backing two names: the encoder's
    // and the decoder's. Identity must survive the round trip exactly.
    const withBom = makeBacking({
      ...baseFields(),
      payout: { thing: "﻿EUR", quantumExponent: -2, perUnit: 100n },
    });
    const decoded = decodeBacking(encodeBacking(withBom));
    expect((decoded.payout as ConstantPayout).thing).toBe("﻿EUR");
    expect(bytesToHex(backingName(decoded))).toBe(bytesToHex(backingName(withBom)));
  });

  it("invalid UTF-8 in the payout thing is an EncodingError", () => {
    const bytes = encodeBacking(makeBacking(baseFields()));
    bytes[bytes.indexOf(0x45)] = 0xff; // corrupt the "E" of EUR
    expect(() => decodeBacking(bytes)).toThrow(EncodingError);
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

  it("rejects an operator key that is not a valid Ed25519 point", () => {
    // Both keys in E-and-K are validated at the one boundary that owns backing
    // well-formedness. The operator used to be length-checked here and
    // point-checked at the sequencer, which is one property enforced at two
    // boundaries; the recorded reason was that checking it here would change
    // which backings are representable and the slice-1 name format is frozen.
    // The golden vector's own operator key is a valid non-small-order point, so
    // the format is untouched and the reason no longer holds.
    const notAPoint = new Uint8Array(32).fill(0x04);
    expect(() =>
      makeBacking({ ...baseFields(), evidence: { setting: "transparent", operator: notAPoint } }),
    ).toThrow(EncodingError);
    // And on the way in from the wire, since decode routes through makeBacking.
    const bytes = encodeBacking(makeBacking(baseFields()));
    const tampered = bytes.slice();
    tampered.set(notAPoint, tampered.length - 32);
    expect(() => decodeBacking(tampered)).toThrow(EncodingError);
  });

  it("a tag-0x01 backing declares no clauses, and is byte-identical to before", () => {
    const bare = makeBacking(baseFields());
    const bytes = encodeBacking(bare);
    expect(bytesToHex(bytes)).toContain("01" + bytesToHex(OPERATOR));
    const decoded = decodeBacking(bytes);
    expect(decoded.evidence.silence).toBeUndefined();
    expect(decoded.evidence.witnessing).toBeUndefined();
    expect(decoded.nameHex).toBe(bare.nameHex);
  });

  it("evidence tag 0x05 carries the silence clause as a clause, and round-trips", () => {
    // §C2b's durations are declared in E, so they are inside the name and no
    // backer can edit the standard its own silence is measured against
    // (invariant 1). What changed is only how a declaration is spelled: one
    // extensible list, rather than a tag per combination of blocks. E has
    // several more blocks to come — the replacement rule, the non-service and
    // refusal aggregates — and enumerating combinations doubles with each.
    const declared = makeBacking({
      ...baseFields(),
      evidence: {
        setting: "transparent",
        operator: OPERATOR,
        silence: { noCommitmentDuration: 50n, challengeWindow: 5n },
      },
    });
    const bytes = encodeBacking(declared);
    // ...0x05 || operator || u32 1 || clause 0x01 || u64 50 || u64 5
    expect(bytesToHex(bytes)).toContain(
      "05" + bytesToHex(OPERATOR) + "00000001" + SILENCE_CLAUSE_HEX,
    );
    const decoded = decodeBacking(bytes);
    expect(decoded.nameHex).toBe(declared.nameHex);
    expect(decoded.evidence.silence).toEqual({ noCommitmentDuration: 50n, challengeWindow: 5n });
    expect(decoded.evidence.witnessing).toBeUndefined();
  });

  it("evidence tag 0x05 carries the witnessing terms, and round-trips", () => {
    const declared = makeBacking({
      ...baseFields(),
      evidence: {
        setting: "transparent",
        operator: OPERATOR,
        witnessing: { venue: VENUE_ID, interval: 10n },
      },
    });
    const bytes = encodeBacking(declared);
    expect(bytesToHex(bytes)).toContain(
      "05" + bytesToHex(OPERATOR) + "00000001" + WITNESSING_CLAUSE_HEX,
    );
    const decoded = decodeBacking(bytes);
    expect(decoded.nameHex).toBe(declared.nameHex);
    expect(decoded.evidence.witnessing?.interval).toBe(10n);
    expect(bytesToHex(decoded.evidence.witnessing?.venue as Uint8Array)).toBe(bytesToHex(VENUE_ID));
    expect(decoded.evidence.silence).toBeUndefined();
  });

  it("writes several clauses in ascending tag order, whatever order they arrived in", () => {
    // Sorted and duplicate-free, exactly as the reliance list is, and for the
    // same reason: one set of terms must have one spelling.
    const declared = makeBacking({
      ...baseFields(),
      evidence: {
        setting: "transparent",
        operator: OPERATOR,
        witnessing: { venue: VENUE_ID, interval: 10n },
        silence: { noCommitmentDuration: 50n, challengeWindow: 5n },
      },
    });
    const bytes = encodeBacking(declared);
    expect(bytesToHex(bytes)).toContain(
      "05" + bytesToHex(OPERATOR) + "00000002" + SILENCE_CLAUSE_HEX + WITNESSING_CLAUSE_HEX,
    );
    const decoded = decodeBacking(bytes);
    expect(decoded.nameHex).toBe(declared.nameHex);
    expect(decoded.evidence.silence).toEqual({ noCommitmentDuration: 50n, challengeWindow: 5n });
    expect(decoded.evidence.witnessing?.interval).toBe(10n);
  });

  it("the venue and the interval are both inside the name", () => {
    const witnessed = (venue: Uint8Array, interval: bigint) =>
      makeBacking({
        ...baseFields(),
        evidence: { setting: "transparent", operator: OPERATOR, witnessing: { venue, interval } },
      }).nameHex;
    const base = witnessed(VENUE_ID, 10n);
    expect(witnessed(OTHER_VENUE_ID, 10n)).not.toBe(base);
    expect(witnessed(VENUE_ID, 11n)).not.toBe(base);
    expect(witnessed(VENUE_ID, 10n)).toBe(base);
  });

  it("rejects a venue id that is not 32 bytes, or an interval outside u64", () => {
    const witnessed = (venue: Uint8Array, interval: bigint) =>
      makeBacking({
        ...baseFields(),
        evidence: { setting: "transparent", operator: OPERATOR, witnessing: { venue, interval } },
      });
    expect(() => witnessed(new Uint8Array(31), 10n)).toThrow(EncodingError);
    expect(() => witnessed(new Uint8Array(33), 10n)).toThrow(EncodingError);
    expect(() => witnessed(VENUE_ID, -1n)).toThrow(EncodingError);
    expect(() => witnessed(VENUE_ID, 1n << 64n)).toThrow(EncodingError);
  });

  it("carries the replacement rule as clause 0x03, sorted after the others", () => {
    // §C2's rule, and §C2b's answer to whether a sequencer can be replaced at
    // all. Inside the name like the rest: the party that may hand the backing to
    // a successor is not the operator's to nominate.
    const declared = makeBacking({
      ...baseFields(),
      evidence: {
        setting: "transparent",
        operator: OPERATOR,
        replacementRule: OBLIGOR,
        witnessing: { venue: VENUE_ID, interval: 10n },
        silence: { noCommitmentDuration: 50n, challengeWindow: 5n },
      },
    });
    expect(bytesToHex(encodeBacking(declared))).toContain(
      "05" +
        bytesToHex(OPERATOR) +
        "00000003" +
        SILENCE_CLAUSE_HEX +
        WITNESSING_CLAUSE_HEX +
        "03" +
        bytesToHex(OBLIGOR),
    );
    const decoded = decodeBacking(encodeBacking(declared));
    expect(decoded.nameHex).toBe(declared.nameHex);
    expect(bytesToHex(decoded.evidence.replacementRule as Uint8Array)).toBe(bytesToHex(OBLIGOR));
  });

  it("puts the replacement rule inside the name", () => {
    const ruled = (rule: Uint8Array | undefined) =>
      makeBacking({
        ...baseFields(),
        evidence: {
          setting: "transparent",
          operator: OPERATOR,
          ...(rule === undefined ? {} : { replacementRule: rule }),
        },
      }).nameHex;
    expect(ruled(OBLIGOR)).not.toBe(ruled(undefined));
    expect(ruled(OBLIGOR)).not.toBe(ruled(OBLIGOR_2));
    expect(ruled(OBLIGOR)).toBe(ruled(OBLIGOR));
  });

  it("rejects an empty clause list, which tag 0x01 already spells", () => {
    // The canonicality rule the extensible form needs: two spellings of one
    // backing would make the name stop being a function of the terms, so the
    // clause list is refused where a shorter tag says the same thing.
    expect(() => decodeBacking(withEvidence("05" + bytesToHex(OPERATOR) + "00000000"))).toThrow(
      EncodingError,
    );
  });

  it("rejects clauses out of canonical order, or repeated", () => {
    const two = (a: string, b: string) =>
      withEvidence("05" + bytesToHex(OPERATOR) + "00000002" + a + b);
    expect(() => decodeBacking(two(WITNESSING_CLAUSE_HEX, SILENCE_CLAUSE_HEX))).toThrow(
      EncodingError,
    );
    expect(() => decodeBacking(two(SILENCE_CLAUSE_HEX, SILENCE_CLAUSE_HEX))).toThrow(EncodingError);
  });

  it("rejects an unknown clause tag rather than skipping it", () => {
    // A clause payload is NOT length-prefixed, deliberately: a reader that
    // could skip a clause it does not understand would report terms it cannot
    // check, which is worse than declaring nothing (the tag-0x02 rule).
    expect(() =>
      decodeBacking(withEvidence("05" + bytesToHex(OPERATOR) + "00000001" + "07" + "00")),
    ).toThrow(EncodingError);
  });

  it("rejects an unknown evidence tag rather than guessing", () => {
    expect(() => decodeBacking(withEvidence("09" + bytesToHex(OPERATOR)))).toThrow(EncodingError);
  });


  it("rejects a silence duration outside the u64 range", () => {
    const withClause = (silence: { noCommitmentDuration: bigint; challengeWindow: bigint }) =>
      makeBacking({
        ...baseFields(),
        evidence: { setting: "transparent", operator: OPERATOR, silence },
      });
    expect(() => withClause({ noCommitmentDuration: -1n, challengeWindow: 5n })).toThrow(
      EncodingError,
    );
    expect(() => withClause({ noCommitmentDuration: 1n << 64n, challengeWindow: 5n })).toThrow(
      EncodingError,
    );
    expect(() => withClause({ noCommitmentDuration: 5n, challengeWindow: -1n })).toThrow(
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
