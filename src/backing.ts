// The backing object B = (K, P, R, E) and its identity.
//
// Invariant 1: a backing's name is the hash, under a declared function, of a
// canonical encoding of (K, P, R, E). Invariant 2: a backing exists only
// with a valid signature by K over its own name.
//
// A Backing is produced only by makeBacking, which validates every field,
// canonicalizes the reliance list, and takes private copies of all byte
// arrays. The type is branded so the rest of the system cannot fabricate an
// unvalidated backing structurally; encode/hash/sign therefore trust it.
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
import { isValidPublicKey, KEY_LENGTH, verifySignatureStrict } from "./keys.js";
import { MAX_QUANTITY_BYTES, validateQuantity } from "./quantity.js";

const MAGIC = Uint8Array.of(0x4d, 0x46, 0x50, 0x42); // "MFPB"
const VERSION = 0x01;
const TAG_OBLIGOR_ED25519 = 0x01;
const TAG_PAYOUT_CONSTANT = 0x01;
const TAG_TARGET_BACKING = 0x01;
const TAG_EVIDENCE_TRANSPARENT = 0x01;

const NAME_LENGTH = 32;
const MAX_THING_BYTES = 1024;
const MAX_RELIANCE_ENTRIES = 4096;

const textEncoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const SIGNATURE_CONTEXT = textEncoder.encode("mfp/backing-signature/v1");

/** Raised when a signing key does not match the obligor, or is malformed. */
export class SigningError extends Error {}

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

/** The unvalidated input shape accepted by makeBacking. */
export interface BackingFields {
  /** K: the Ed25519 verification key that owes. */
  readonly obligor: Uint8Array;
  /** P: what one unit pays. */
  readonly payout: ConstantPayout;
  /** R: what must be handed over alongside a claim. May be empty. */
  readonly reliance: readonly RelianceEntry[];
  /** E: who says a claim has not already been spent. */
  readonly evidence: TransparentEvidence;
}

declare const validated: unique symbol;

/**
 * A validated, canonical backing. Only makeBacking (and decodeBacking, which
 * routes through it) can produce one, so any Backing value is safe to encode,
 * hash, and sign without re-checking.
 */
export type Backing = BackingFields & { readonly [validated]: true };

function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.prototype.slice.call(bytes);
}

/**
 * The one constructor for a Backing: validate every field, reject a
 * non-canonical payout string, canonicalize the reliance list (sorted, no
 * duplicates), and snapshot every byte array so the value cannot be mutated
 * through the caller's references afterwards.
 */
export function makeBacking(fields: BackingFields): Backing {
  // K must be a valid, non-small-order Ed25519 point. Without this, an
  // obligor set to a small-order point (e.g. the identity) accepts a forged
  // signature over any name, defeating invariant 2. See DECISIONS.md.
  if (!isValidPublicKey(fields.obligor)) {
    throw new EncodingError("obligor key is not a valid non-small-order Ed25519 point");
  }

  if (fields.evidence.setting !== "transparent") {
    throw new EncodingError(`unsupported evidence setting ${String(fields.evidence.setting)}`);
  }
  if (fields.evidence.operator.length !== KEY_LENGTH) {
    throw new EncodingError(`operator key must be ${KEY_LENGTH} bytes`);
  }

  const { thing, quantumExponent, perUnit } = fields.payout;
  // Unpaired surrogates would silently become U+FFFD on encode, collapsing
  // two distinct things to one name; reject them rather than lose them.
  if (!thing.isWellFormed()) {
    throw new EncodingError("payout thing contains unpaired surrogates");
  }
  const thingByteLength = textEncoder.encode(thing).length;
  if (thingByteLength === 0) throw new EncodingError("payout thing is empty");
  if (thingByteLength > MAX_THING_BYTES) throw new EncodingError("payout thing too long");
  if (
    !Number.isInteger(quantumExponent) ||
    quantumExponent < -128 ||
    quantumExponent > 127
  ) {
    throw new EncodingError("quantum exponent out of range");
  }
  validateQuantity(perUnit, "payout per unit");

  if (fields.reliance.length > MAX_RELIANCE_ENTRIES) {
    throw new EncodingError("too many reliance entries");
  }
  for (const entry of fields.reliance) {
    if (entry.target.length !== NAME_LENGTH) {
      throw new EncodingError(`reliance target must be ${NAME_LENGTH} bytes`);
    }
    validateQuantity(entry.count, "reliance count");
  }
  const reliance = fields.reliance
    .map((entry) => Object.freeze({ target: copyBytes(entry.target), count: entry.count }))
    .sort((a, b) => compareBytes(a.target, b.target));
  for (let i = 1; i < reliance.length; i++) {
    const previous = reliance[i - 1] as RelianceEntry;
    const current = reliance[i] as RelianceEntry;
    if (compareBytes(previous.target, current.target) === 0) {
      throw new EncodingError("duplicate reliance target");
    }
  }

  // Freeze the object graph so a validated backing cannot be structurally
  // mutated (e.g. reliance.push, or reassigning obligor) into terms its name
  // no longer describes. The raw bytes inside each Uint8Array cannot be
  // frozen in JS; mutating them is unsupported (see DECISIONS.md), and the
  // backingName memo below means identity is fixed at construction regardless.
  const backing: BackingFields = Object.freeze({
    obligor: copyBytes(fields.obligor),
    payout: Object.freeze({ thing, quantumExponent, perUnit }),
    reliance: Object.freeze(reliance),
    evidence: Object.freeze({
      setting: "transparent" as const,
      operator: copyBytes(fields.evidence.operator),
    }),
  });
  // The brand is a phantom type with no runtime property, so the cast goes
  // through unknown. makeBacking is the only place that mints it.
  return backing as unknown as Backing;
}

/**
 * Serialize a validated backing. Because Backing is canonical by
 * construction, this writes fields in the order they already hold.
 */
export function encodeBacking(backing: Backing): Uint8Array {
  const w = new ByteWriter();
  w.raw(MAGIC);
  w.u8(VERSION);

  w.u8(TAG_OBLIGOR_ED25519);
  w.raw(backing.obligor);

  w.u8(TAG_PAYOUT_CONSTANT);
  w.lengthPrefixed(textEncoder.encode(backing.payout.thing));
  w.i8(backing.payout.quantumExponent);
  w.lengthPrefixed(bigintToMinimalBytes(backing.payout.perUnit));

  w.u32(backing.reliance.length);
  for (const entry of backing.reliance) {
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
 * nothing else, then routes the parsed fields through makeBacking so wire
 * data gets the same validation (including the small-order key check) as
 * locally constructed backings. decode(bytes) succeeding proves bytes is THE
 * encoding of the result.
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
  const thing = utf8Decoder.decode(thingBytes);
  const quantumExponent = r.i8();
  const perUnit = minimalBytesToBigint(r.lengthPrefixed(MAX_QUANTITY_BYTES));

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
    reliance.push({ target, count });
  }

  expectTag(r, TAG_EVIDENCE_TRANSPARENT, "evidence");
  const operator = r.raw(KEY_LENGTH);

  r.expectEnd();
  return makeBacking({
    obligor,
    payout: { thing, quantumExponent, perUnit },
    reliance,
    evidence: { setting: "transparent", operator },
  });
}

// A backing is immutable by construction (makeBacking freezes it), so its
// name is fixed for the object's lifetime. Memoize it: backingName is on the
// hot path (every ledger operation resolves state and signs by name), and
// caching also fixes identity at construction, so raw byte mutation of a key
// array cannot silently re-home an already-registered backing.
const nameCache = new WeakMap<Backing, Uint8Array>();

/** The backing's name: SHA-256 of its canonical encoding (invariant 1). */
export function backingName(backing: Backing): Uint8Array {
  let name = nameCache.get(backing);
  if (name === undefined) {
    name = sha256(encodeBacking(backing));
    nameCache.set(backing, name);
  }
  return name;
}

function signedMessage(name: Uint8Array): Uint8Array {
  const message = new Uint8Array(SIGNATURE_CONTEXT.length + name.length);
  message.set(SIGNATURE_CONTEXT, 0);
  message.set(name, SIGNATURE_CONTEXT.length);
  return message;
}

/** Sign a backing's name with the obligor's secret key (invariant 2). */
export function signBacking(secretKey: Uint8Array, backing: Backing): Uint8Array {
  let publicKey: Uint8Array;
  try {
    publicKey = ed25519.getPublicKey(secretKey);
  } catch {
    throw new SigningError("invalid secret key");
  }
  if (compareBytes(publicKey, backing.obligor) !== 0) {
    throw new SigningError("secret key does not belong to the obligor");
  }
  return ed25519.sign(signedMessage(backingName(backing)), secretKey);
}

/**
 * A backing without this check passing does not exist (invariant 2): anyone
 * could publish well-formed terms naming somebody else's key as obligor.
 * Returns false (never throws) for a wrong-length signature, so a malformed
 * signature from a peer is rejected rather than crashing the caller.
 */
export function verifyBackingSignature(
  backing: Backing,
  signature: Uint8Array,
): boolean {
  return verifySignatureStrict(signature, signedMessage(backingName(backing)), backing.obligor);
}
