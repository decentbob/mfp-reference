// Byte-level primitives for the canonical encoding.
//
// Invariant 1 requires "same fields, same bytes, on every machine, forever",
// so every primitive here is deterministic and every reader is strict: a
// byte sequence either is THE canonical encoding of a value or it is
// rejected. There is never a second accepted spelling.

export class EncodingError extends Error {}

/** Unsigned big-endian, minimal length: no leading zero byte, 0n → empty. */
export function bigintToMinimalBytes(n: bigint): Uint8Array {
  if (n < 0n) throw new EncodingError("negative quantity");
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
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

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return compareBytes(a, b) === 0;
}

export class ByteWriter {
  private chunks: Uint8Array[] = [];

  u8(n: number): void {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) {
      throw new EncodingError("u8 out of range");
    }
    this.chunks.push(Uint8Array.of(n));
  }

  /** Signed byte, two's complement. */
  i8(n: number): void {
    if (!Number.isInteger(n) || n < -128 || n > 127) {
      throw new EncodingError("i8 out of range");
    }
    this.u8(n & 0xff);
  }

  u32(n: number): void {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
      throw new EncodingError("u32 out of range");
    }
    this.chunks.push(
      Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff),
    );
  }

  raw(bytes: Uint8Array): void {
    this.chunks.push(bytes);
  }

  /** u32 length followed by the bytes. */
  lengthPrefixed(bytes: Uint8Array): void {
    this.u32(bytes.length);
    this.raw(bytes);
  }

  finish(): Uint8Array {
    let total = 0;
    for (const c of this.chunks) total += c.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of this.chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
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
    if (this.offset + 4 > this.bytes.length) throw new EncodingError("truncated");
    const b = this.bytes;
    const n =
      (b[this.offset] as number) * 0x1000000 +
      ((b[this.offset + 1] as number) << 16) +
      ((b[this.offset + 2] as number) << 8) +
      (b[this.offset + 3] as number);
    this.offset += 4;
    return n;
  }

  raw(length: number): Uint8Array {
    if (this.offset + length > this.bytes.length) throw new EncodingError("truncated");
    const out = this.bytes.slice(this.offset, this.offset + length);
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
