// The backing object B = (K, P, R, E) and its identity.
//
// Invariant 1: a backing's name is the hash, under a declared function, of a
// canonical encoding of (K, P, R, E). Invariant 2: a backing exists only
// with a valid signature by K over its own name.
//
// Canonical encoding v1 (all lengths u32 big-endian, hash = SHA-256):
//
//   magic    "MFPB" (4 bytes)
//   version  u8 = 0x01
//   K        u8 tag 0x01 (single Ed25519) || 32-byte verification key
//   P        u8 tag 0x01 (constant payout)
//              || u32 length || thing (UTF-8, exact bytes, no normalization)
//              || i8 quantumExponent   (settlement quantum = 10^e of thing)
//              || u32 length || perUnit (unsigned big-endian, minimal)
//   R        u32 entry count, then per entry, sorted strictly ascending by
//            target bytes (so duplicates are unrepresentable):
//              u8 tag 0x01 (backing) || 32-byte target name
//              || u32 length || count (unsigned big-endian, minimal)
//   E        u8 tag 0x01 (transparent) || 32-byte operator key
//
// Tags not listed (threshold obligors, the payout expression language,
// chain-asset reliance targets, shielded evidence settings) are future
// slices; a strict decoder rejects them today rather than guessing.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bigintToMinimalBytes,
  ByteReader,
  ByteWriter,
  compareBytes,
  EncodingError,
  minimalBytesToBigint,
} from "./bytes.js";

const MAGIC = Uint8Array.of(0x4d, 0x46, 0x50, 0x42); // "MFPB"
const VERSION = 0x01;
const TAG_OBLIGOR_ED25519 = 0x01;
const TAG_PAYOUT_CONSTANT = 0x01;
const TAG_TARGET_BACKING = 0x01;
const TAG_EVIDENCE_TRANSPARENT = 0x01;

const KEY_LENGTH = 32;
const NAME_LENGTH = 32;
const MAX_THING_BYTES = 1024;
const MAX_QUANTITY_BYTES = 32; // quantities are < 2^256
const MAX_RELIANCE_ENTRIES = 4096;

const SIGNATURE_CONTEXT = new TextEncoder().encode("mfp/backing-signature/v1");

export interface ConstantPayout {
  /** The named thing one unit pays, compared as exact bytes. */
  readonly thing: string;
  /** Settlement quantum, as a power of ten of the thing (cents of EUR: -2). */
  readonly quantumExponent: number;
  /** Quanta paid per unit of claim quantity. */
  readonly perUnit: bigint;
}

export interface RelianceEntry {
  /** Name of the backing that must be handed over alongside this one. */
  readonly target: Uint8Array;
  /** Whole units of the target per unit of this claim. */
  readonly count: bigint;
}

export interface TransparentEvidence {
  readonly setting: "transparent";
  /** Verification key of the sequencer that witnesses spends. */
  readonly operator: Uint8Array;
}

export interface Backing {
  /** K: the Ed25519 verification key that owes. */
  readonly obligor: Uint8Array;
  /** P: what one unit pays. */
  readonly payout: ConstantPayout;
  /** R: what must be handed over alongside a claim. May be empty. */
  readonly reliance: readonly RelianceEntry[];
  /** E: who says a claim has not already been spent. */
  readonly evidence: TransparentEvidence;
}

function validateQuantity(n: bigint, what: string): void {
  if (n < 1n) throw new EncodingError(`${what} must be at least 1`);
  if (bigintToMinimalBytes(n).length > MAX_QUANTITY_BYTES) {
    throw new EncodingError(`${what} too large`);
  }
}

function validateKey(key: Uint8Array, what: string): void {
  if (key.length !== KEY_LENGTH) {
    throw new EncodingError(`${what} must be ${KEY_LENGTH} bytes`);
  }
}

/**
 * Reliance is canonicalized here, not by the caller: entries are sorted by
 * target bytes, so two backings differing only in list order get one name.
 */
export function encodeBacking(backing: Backing): Uint8Array {
  validateKey(backing.obligor, "obligor key");
  validateKey(backing.evidence.operator, "operator key");

  const thingBytes = new TextEncoder().encode(backing.payout.thing);
  if (thingBytes.length === 0) throw new EncodingError("payout thing is empty");
  if (thingBytes.length > MAX_THING_BYTES) {
    throw new EncodingError("payout thing too long");
  }
  if (
    !Number.isInteger(backing.payout.quantumExponent) ||
    backing.payout.quantumExponent < -128 ||
    backing.payout.quantumExponent > 127
  ) {
    throw new EncodingError("quantum exponent out of range");
  }
  validateQuantity(backing.payout.perUnit, "payout per unit");

  if (backing.reliance.length > MAX_RELIANCE_ENTRIES) {
    throw new EncodingError("too many reliance entries");
  }
  for (const entry of backing.reliance) {
    if (entry.target.length !== NAME_LENGTH) {
      throw new EncodingError(`reliance target must be ${NAME_LENGTH} bytes`);
    }
    validateQuantity(entry.count, "reliance count");
  }
  const sorted = [...backing.reliance].sort((a, b) => compareBytes(a.target, b.target));
  for (let i = 1; i < sorted.length; i++) {
    const previous = sorted[i - 1] as RelianceEntry;
    const current = sorted[i] as RelianceEntry;
    if (compareBytes(previous.target, current.target) === 0) {
      throw new EncodingError("duplicate reliance target");
    }
  }

  const w = new ByteWriter();
  w.raw(MAGIC);
  w.u8(VERSION);

  w.u8(TAG_OBLIGOR_ED25519);
  w.raw(backing.obligor);

  w.u8(TAG_PAYOUT_CONSTANT);
  w.lengthPrefixed(thingBytes);
  w.i8(backing.payout.quantumExponent);
  w.lengthPrefixed(bigintToMinimalBytes(backing.payout.perUnit));

  w.u32(sorted.length);
  for (const entry of sorted) {
    w.u8(TAG_TARGET_BACKING);
    w.raw(entry.target);
    w.lengthPrefixed(bigintToMinimalBytes(entry.count));
  }

  w.u8(TAG_EVIDENCE_TRANSPARENT);
  w.raw(backing.evidence.operator);

  return w.finish();
}

function expectTag(r: ByteReader, expected: number, what: string): void {
  const tag = r.u8();
  if (tag !== expected) throw new EncodingError(`unsupported ${what} tag ${tag}`);
}

/**
 * Strict inverse of encodeBacking: accepts exactly the canonical bytes and
 * nothing else, so decode(bytes) succeeding proves bytes is THE encoding of
 * the result.
 */
export function decodeBacking(bytes: Uint8Array): Backing {
  const r = new ByteReader(bytes);

  const magic = r.raw(MAGIC.length);
  if (compareBytes(magic, MAGIC) !== 0) throw new EncodingError("bad magic");
  const version = r.u8();
  if (version !== VERSION) throw new EncodingError(`unsupported version ${version}`);

  expectTag(r, TAG_OBLIGOR_ED25519, "obligor");
  const obligor = r.raw(KEY_LENGTH);

  expectTag(r, TAG_PAYOUT_CONSTANT, "payout");
  const thingBytes = r.lengthPrefixed(MAX_THING_BYTES);
  if (thingBytes.length === 0) throw new EncodingError("payout thing is empty");
  const thing = new TextDecoder("utf-8", { fatal: true }).decode(thingBytes);
  const quantumExponent = r.i8();
  const perUnit = minimalBytesToBigint(r.lengthPrefixed(MAX_QUANTITY_BYTES));
  validateQuantity(perUnit, "payout per unit");

  const entryCount = r.u32();
  if (entryCount > MAX_RELIANCE_ENTRIES) {
    throw new EncodingError("too many reliance entries");
  }
  const reliance: RelianceEntry[] = [];
  let previousTarget: Uint8Array | undefined;
  for (let i = 0; i < entryCount; i++) {
    expectTag(r, TAG_TARGET_BACKING, "reliance target");
    const target = r.raw(NAME_LENGTH);
    if (previousTarget !== undefined && compareBytes(previousTarget, target) >= 0) {
      throw new EncodingError("reliance targets not in canonical order");
    }
    previousTarget = target;
    const count = minimalBytesToBigint(r.lengthPrefixed(MAX_QUANTITY_BYTES));
    validateQuantity(count, "reliance count");
    reliance.push({ target, count });
  }

  expectTag(r, TAG_EVIDENCE_TRANSPARENT, "evidence");
  const operator = r.raw(KEY_LENGTH);

  r.expectEnd();
  return {
    obligor,
    payout: { thing, quantumExponent, perUnit },
    reliance,
    evidence: { setting: "transparent", operator },
  };
}

/** The backing's name: SHA-256 of its canonical encoding (invariant 1). */
export function backingName(backing: Backing): Uint8Array {
  return sha256(encodeBacking(backing));
}

function signedMessage(name: Uint8Array): Uint8Array {
  const message = new Uint8Array(SIGNATURE_CONTEXT.length + name.length);
  message.set(SIGNATURE_CONTEXT, 0);
  message.set(name, SIGNATURE_CONTEXT.length);
  return message;
}

/** Sign a backing's name with the obligor's secret key (invariant 2). */
export function signBacking(secretKey: Uint8Array, backing: Backing): Uint8Array {
  const publicKey = ed25519.getPublicKey(secretKey);
  if (compareBytes(publicKey, backing.obligor) !== 0) {
    throw new EncodingError("secret key does not belong to the obligor");
  }
  return ed25519.sign(signedMessage(backingName(backing)), secretKey);
}

/**
 * A backing without this check passing does not exist (invariant 2): anyone
 * could publish well-formed terms naming somebody else's key as obligor.
 */
export function verifyBackingSignature(
  backing: Backing,
  signature: Uint8Array,
): boolean {
  return ed25519.verify(signature, signedMessage(backingName(backing)), backing.obligor);
}
