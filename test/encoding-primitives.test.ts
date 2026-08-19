import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { bigintToMinimalBytes, ByteWriter, EncodingError } from "../src/bytes.js";
import { contextsArePrefixFree } from "../src/contexts.js";

// The byte primitives, pinned against literal expected output.
//
// These cannot be checked by round-trip tests: signing and verifying use the
// same encoder, so a byte-order bug in u64 would round-trip perfectly and pass
// every signature test while producing a wire format no other implementation
// agrees with. Only literal expectations catch that.

function hex(write: (w: ByteWriter) => void): string {
  const w = new ByteWriter();
  write(w);
  return bytesToHex(w.finish());
}

describe("ByteWriter primitives are big-endian and exact", () => {
  it("u64 is 8 bytes, big-endian", () => {
    expect(hex((w) => w.u64(0n))).toBe("0000000000000000");
    expect(hex((w) => w.u64(1n))).toBe("0000000000000001");
    expect(hex((w) => w.u64(258n))).toBe("0000000000000102");
    expect(hex((w) => w.u64(0x0100000000000000n))).toBe("0100000000000000");
    expect(hex((w) => w.u64(0xffffffffffffffffn))).toBe("ffffffffffffffff");
  });

  it("u32 is 4 bytes, big-endian; i8 is two's complement", () => {
    expect(hex((w) => w.u32(258))).toBe("00000102");
    expect(hex((w) => w.i8(-2))).toBe("fe");
    expect(hex((w) => w.i8(127))).toBe("7f");
  });

  it("lengthPrefixed writes a u32 count then the bytes", () => {
    expect(hex((w) => w.lengthPrefixed(Uint8Array.of(1, 2, 3)))).toBe("00000003010203");
  });

  it("out-of-range values are rejected rather than truncated", () => {
    expect(() => hex((w) => w.u64(-1n))).toThrow(EncodingError);
    expect(() => hex((w) => w.u64(1n << 64n))).toThrow(EncodingError);
    expect(() => hex((w) => w.u32(-1))).toThrow(EncodingError);
    expect(() => hex((w) => w.i8(128))).toThrow(EncodingError);
  });
});

describe("the framing rule is enforced at the writer", () => {
  it("key32 accepts exactly 32 bytes and rejects anything else", () => {
    expect(hex((w) => w.key32(new Uint8Array(32).fill(0xab), "k")).length).toBe(64);
    expect(() => hex((w) => w.key32(new Uint8Array(31), "k"))).toThrow(EncodingError);
    expect(() => hex((w) => w.key32(new Uint8Array(33), "k"))).toThrow(EncodingError);
  });

  it("two fixed fields cannot borrow bytes from each other", () => {
    // The collision the rule exists to prevent: 31+33 concatenates exactly
    // like 32+32, so an unframed writer gives two field pairs one encoding.
    const all = new Uint8Array(64);
    for (let i = 0; i < 64; i++) all[i] = i + 1;
    const framed = hex((w) => {
      w.key32(all.slice(0, 32), "a");
      w.key32(all.slice(32), "b");
    });
    expect(framed).toBe(bytesToHex(all));
    expect(() =>
      hex((w) => {
        w.key32(all.slice(0, 31), "a");
        w.key32(all.slice(31), "b");
      }),
    ).toThrow(EncodingError);
  });
});

describe("bigintToMinimalBytes is unsigned big-endian with no leading zero", () => {
  it("matches literal expectations across the range", () => {
    expect(bytesToHex(bigintToMinimalBytes(0n))).toBe("");
    expect(bytesToHex(bigintToMinimalBytes(1n))).toBe("01");
    expect(bytesToHex(bigintToMinimalBytes(255n))).toBe("ff");
    expect(bytesToHex(bigintToMinimalBytes(256n))).toBe("0100");
    expect(bytesToHex(bigintToMinimalBytes(0x1ffn))).toBe("01ff");
    expect(bytesToHex(bigintToMinimalBytes(1n << 255n))).toBe(
      "8000000000000000000000000000000000000000000000000000000000000000",
    );
  });

  it("rejects a negative quantity", () => {
    expect(() => bigintToMinimalBytes(-1n)).toThrow(EncodingError);
  });
});

describe("domain-separation tags are prefix-free", () => {
  it("no live tag is a prefix of another", () => {
    expect(contextsArePrefixFree()).toBe(true);
  });

  it("the check actually detects a prefix collision", () => {
    const enc = new TextEncoder();
    expect(contextsArePrefixFree([enc.encode("mfp/burn/v1"), enc.encode("mfp/burn/v11")])).toBe(false);
    expect(contextsArePrefixFree([enc.encode("mfp/a/v1"), enc.encode("mfp/b/v1")])).toBe(true);
  });
});
