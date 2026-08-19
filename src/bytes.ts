// Byte-level primitives, and the framing rule everything signed or hashed
// obeys.
//
// Invariant 1 requires "same fields, same bytes, on every machine, forever",
// and commitment roots require the converse: two different values must never
// produce one byte string. Both come from one rule (CLAUDE.md, Design rules):
// **every field is fixed-width and asserted, or length-prefixed. Nothing
// variable-length is ever written raw.** Adjacent unframed fields silently
// destroy injectivity — 31+33 bytes concatenate exactly like 32+32.
//
// Readers are strict for the same reason: a byte sequence either is THE
// canonical encoding of a value or it is rejected. There is never a second
// accepted spelling.

export class EncodingError extends Error {}

/** Quantities are whole, positive, and below this bound (invariant 15). */
export const MAX_QUANTITY_BYTES = 32;
export const MAX_QUANTITY_EXCLUSIVE = 1n << (8n * BigInt(MAX_QUANTITY_BYTES));

export function isValidQuantity(n: bigint): boolean {
  return n >= 1n && n < MAX_QUANTITY_EXCLUSIVE;
}

export function validateQuantity(n: bigint, what: string): void {
  if (!isValidQuantity(n)) throw new EncodingError(`${what} out of range`);
}

/**
 * The one byte-copy in the codebase. Node's Buffer overrides `slice` to return
 * a view sharing memory, so the copying form must be forced explicitly or a
 * decoded value silently aliases (and mutates with) the caller's buffer.
 */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.prototype.slice.call(bytes);
}

/** Unsigned big-endian, minimal length: no leading zero byte, 0n -> empty. */
export function bigintToMinimalBytes(n: bigint): Uint8Array {
  if (n < 0n) throw new EncodingError("negative quantity");
  if (n === 0n) return new Uint8Array(0);
  // Size first, then fill back-to-front. Prepending per byte would memmove the
  // whole buffer each time, which is quadratic on an attacker-sized value.
  let length = 0;
  for (let v = n; v > 0n; v >>= 8n) length++;
  const out = new Uint8Array(length);
  let v = n;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function minimalBytesToBigint(bytes: Uint8Array): bigint {
  if (bytes.length > 0 && bytes[0] === 0) {
    throw new EncodingError("non-minimal bigint encoding");
  }
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** Lexicographic byte comparison, the sort order for reliance lists. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** Keys, backing names and hashes are all 32 bytes. */
export const FIXED32 = 32;

export class ByteWriter {
  private readonly out: number[] = [];

  u8(n: number): void {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) {
      throw new EncodingError("u8 out of range");
    }
    this.out.push(n);
  }

  /** Signed byte, two's complement. */
  i8(n: number): void {
    if (!Number.isInteger(n) || n < -128 || n > 127) {
      throw new EncodingError("i8 out of range");
    }
    this.out.push(n & 0xff);
  }

  u32(n: number): void {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
      throw new EncodingError("u32 out of range");
    }
    this.out.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }

  u64(n: bigint): void {
    if (n < 0n || n > 0xffffffffffffffffn) {
      throw new EncodingError("u64 out of range");
    }
    for (let shift = 56n; shift >= 0n; shift -= 8n) {
      this.out.push(Number((n >> shift) & 0xffn));
    }
  }

  /**
   * A fixed-width field, asserted. This is the framing rule's enforcement
   * point: every raw byte field in every signed or hashed message goes through
   * here or through lengthPrefixed, so no two field values can ever share an
   * encoding.
   */
  fixed(bytes: Uint8Array, length: number, what: string): void {
    if (bytes.length !== length) {
      throw new EncodingError(`${what} must be ${length} bytes`);
    }
    for (const b of bytes) this.out.push(b);
  }

  /** A 32-byte key, name, or hash. */
  key32(bytes: Uint8Array, what: string): void {
    this.fixed(bytes, FIXED32, what);
  }

  /**
   * A domain-separation tag, written first and unframed. This is the one
   * legitimate raw write: contexts are compile-time constants from
   * contexts.ts, and that module asserts they are prefix-free, so the first
   * field of two different message types always differs within the shorter
   * tag. Framing them would add bytes without adding a property.
   */
  context(tag: Uint8Array): void {
    for (const b of tag) this.out.push(b);
  }

  /** u32 length followed by the bytes. */
  lengthPrefixed(bytes: Uint8Array): void {
    this.u32(bytes.length);
    for (const b of bytes) this.out.push(b);
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.out);
  }
}

export class ByteReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  u8(): number {
    if (this.offset + 1 > this.bytes.length) throw new EncodingError("truncated");
    return this.bytes[this.offset++] as number;
  }

  i8(): number {
    const n = this.u8();
    return n > 127 ? n - 256 : n;
  }

  u32(): number {
    let n = 0;
    for (let i = 0; i < 4; i++) n = n * 256 + this.u8();
    return n;
  }

  raw(length: number): Uint8Array {
    if (this.offset + length > this.bytes.length) throw new EncodingError("truncated");
    const out = copyBytes(this.bytes.subarray(this.offset, this.offset + length));
    this.offset += length;
    return out;
  }

  lengthPrefixed(maxLength: number): Uint8Array {
    const length = this.u32();
    if (length > maxLength) throw new EncodingError("field too long");
    return this.raw(length);
  }

  /** Every decode must end here: trailing bytes are not canonical. */
  expectEnd(): void {
    if (this.offset !== this.bytes.length) {
      throw new EncodingError("trailing bytes");
    }
  }
}
