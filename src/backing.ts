// The backing object B = (K, P, R, E) and its identity.
//
// Invariant 1: a backing's name is the hash, under a declared function, of a
// canonical encoding of (K, P, R, E). Invariant 2: a backing exists only with
// a valid signature by K over its own name.
//
// A Backing is produced only by makeBacking, which validates every field,
// canonicalizes the reliance list, copies all bytes, computes the name once,
// and freezes the result. The type is branded so the rest of the system cannot
// fabricate an unvalidated backing structurally; encode/hash/sign trust it.
// Because the name is a stored field rather than a recomputation, identity is
// fixed at construction: a later (unsupported) mutation of the raw key bytes
// cannot re-home an already-registered backing.
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
//            u8 tag 0x02 (transparent, silence clause declared)
//              || 32-byte operator key
//              || u64 no-commitment duration || u64 challenge window
//
// Tags not listed (threshold obligors, the payout expression language,
// chain-asset reliance targets, shielded evidence settings) are future slices;
// a strict decoder rejects them today rather than guessing.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  bigintToMinimalBytes,
  ByteReader,
  ByteWriter,
  compareBytes,
  copyBytes,
  EncodingError,
  MAX_QUANTITY_BYTES,
  minimalBytesToBigint,
  validateQuantity,
} from "./bytes.js";
import { BACKING_SIGNATURE_CONTEXT, utf8Decoder, utf8Encoder } from "./contexts.js";
import { isValidPublicKey, KEY_LENGTH, verifySignatureStrict } from "./keys.js";

const MAGIC = Uint8Array.of(0x4d, 0x46, 0x50, 0x42); // "MFPB"
const VERSION = 0x01;
const TAG_OBLIGOR_ED25519 = 0x01;
const TAG_PAYOUT_CONSTANT = 0x01;
const TAG_TARGET_BACKING = 0x01;
const TAG_EVIDENCE_TRANSPARENT = 0x01;
const TAG_EVIDENCE_SILENCE = 0x02;

const NAME_LENGTH = 32;
const MAX_THING_BYTES = 1024;
const MAX_RELIANCE_ENTRIES = 4096;

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

/**
 * §C2b's aggravated grade, declared by the backer. Both are durations in
 * witnessed indices at the venue. Declared in E rather than passed around, so
 * they are inside the name: a backer cannot edit the standard its own silence is
 * measured against (invariant 1), and "the holder read the choice before
 * accepting". The paper leaves the calibration to the backer - "set m low and
 * one scripted wallet replaces an operator; set it high and the clause never
 * fires" - so no value is policed here beyond being a u64.
 */
export interface SilenceClause {
  /** No commitment for longer than this is the aggravated grade. */
  readonly noCommitmentDuration: bigint;
  /** How long a snapshot redemption stands open to challenge. */
  readonly challengeWindow: bigint;
}

export interface TransparentEvidence {
  readonly setting: "transparent";
  /** Verification key of the sequencer that witnesses spends. */
  readonly operator: Uint8Array;
  /**
   * Absent (tag 0x01) means the backer declared no silence clause, so snapshot
   * redemption never opens and claims can go illiquid forever. That is a
   * coherent setting rather than an oversight - the backer's choice, readable in
   * the terms before anyone accepts them.
   */
  readonly silence?: SilenceClause;
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
 * A validated, canonical backing with its identity already computed. Only
 * makeBacking (and decodeBacking, which routes through it) can produce one, so
 * any Backing value is safe to encode, hash, and sign without re-checking.
 */
export type Backing = BackingFields & {
  /** SHA-256 of the canonical encoding (invariant 1), computed once. */
  readonly name: Uint8Array;
  /** The name as lowercase hex — the key every registry uses. */
  readonly nameHex: string;
  readonly [validated]: true;
};

/** Serialize validated fields. Fixed-width fields are asserted by key32. */
function encodeFields(b: BackingFields): Uint8Array {
  const w = new ByteWriter();
  w.fixed(MAGIC, MAGIC.length, "magic");
  w.u8(VERSION);

  w.u8(TAG_OBLIGOR_ED25519);
  w.key32(b.obligor, "obligor key");

  w.u8(TAG_PAYOUT_CONSTANT);
  w.lengthPrefixed(utf8Encoder.encode(b.payout.thing));
  w.i8(b.payout.quantumExponent);
  w.lengthPrefixed(bigintToMinimalBytes(b.payout.perUnit));

  w.u32(b.reliance.length);
  for (const entry of b.reliance) {
    w.u8(TAG_TARGET_BACKING);
    w.key32(entry.target, "reliance target");
    w.lengthPrefixed(bigintToMinimalBytes(entry.count));
  }

  const silence = b.evidence.silence;
  w.u8(silence === undefined ? TAG_EVIDENCE_TRANSPARENT : TAG_EVIDENCE_SILENCE);
  w.key32(b.evidence.operator, "operator key");
  if (silence !== undefined) {
    w.u64(silence.noCommitmentDuration);
    w.u64(silence.challengeWindow);
  }

  return w.finish();
}

/** Field by field, so nothing rides along on a spread of caller input. */
function canonicalEvidence(evidence: TransparentEvidence): TransparentEvidence {
  const operator = copyBytes(evidence.operator);
  const silence = evidence.silence;
  if (silence === undefined) return { setting: "transparent", operator };
  return {
    setting: "transparent",
    operator,
    silence: Object.freeze({
      noCommitmentDuration: silence.noCommitmentDuration,
      challengeWindow: silence.challengeWindow,
    }),
  };
}

/**
 * The one constructor for a Backing: validate every field, reject a
 * non-canonical payout string, canonicalize the reliance list (sorted, no
 * duplicates), snapshot every byte array, compute the name, and freeze.
 */
export function makeBacking(fields: BackingFields): Backing {
  // K must be a valid, non-small-order Ed25519 point. Without this, an obligor
  // set to a small-order point (e.g. the identity) accepts a forged signature
  // over any name, defeating invariant 2. See DECISIONS.md.
  if (!isValidPublicKey(fields.obligor)) {
    throw new EncodingError("obligor key is not a valid non-small-order Ed25519 point");
  }

  if (fields.evidence.setting !== "transparent") {
    throw new EncodingError(`unsupported evidence setting ${String(fields.evidence.setting)}`);
  }
  // The same rule as K, at the same boundary. It was once length-only here and
  // point-checked at the sequencer instead, on the ground that checking it here
  // would change which backings are representable and the slice-1 name format is
  // frozen -- but the golden vector's own operator key is a valid non-small-order
  // point, so the format is untouched and one property stops being enforced at
  // two boundaries. See DECISIONS.md.
  if (!isValidPublicKey(fields.evidence.operator)) {
    throw new EncodingError("operator key is not a valid non-small-order Ed25519 point");
  }

  const { thing, quantumExponent, perUnit } = fields.payout;
  // Unpaired surrogates would silently become U+FFFD on encode, collapsing
  // two distinct things to one name; reject them rather than lose them.
  if (!thing.isWellFormed()) {
    throw new EncodingError("payout thing contains unpaired surrogates");
  }
  const thingByteLength = utf8Encoder.encode(thing).length;
  if (thingByteLength === 0) throw new EncodingError("payout thing is empty");
  if (thingByteLength > MAX_THING_BYTES) throw new EncodingError("payout thing too long");
  if (!Number.isInteger(quantumExponent) || quantumExponent < -128 || quantumExponent > 127) {
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
  // mutated (e.g. reliance.push) into terms its name no longer describes. Raw
  // bytes inside a Uint8Array cannot be frozen in JS; mutating them is
  // unsupported (see DECISIONS.md) and harmless to identity, which is the
  // stored name below.
  const canonical: BackingFields = {
    obligor: copyBytes(fields.obligor),
    payout: Object.freeze({ thing, quantumExponent, perUnit }),
    reliance: Object.freeze(reliance),
    evidence: Object.freeze(canonicalEvidence(fields.evidence)),
  };
  const name = sha256(encodeFields(canonical));
  // The brand is a phantom type with no runtime property, so the cast goes
  // through unknown. makeBacking is the only place that mints it.
  return Object.freeze({
    ...canonical,
    name,
    nameHex: bytesToHex(name),
  }) as unknown as Backing;
}

/** Serialize a validated backing. */
export function encodeBacking(backing: Backing): Uint8Array {
  return encodeFields(backing);
}

function expectTag(r: ByteReader, expected: number, what: string): void {
  const tag = r.u8();
  if (tag !== expected) throw new EncodingError(`unsupported ${what} tag ${tag}`);
}

/**
 * Strict inverse of encodeBacking: accepts exactly the canonical bytes and
 * nothing else, then routes the parsed fields through makeBacking so wire data
 * gets the same validation as locally constructed backings. Every rejection is
 * an EncodingError, including invalid UTF-8. decode(bytes) succeeding proves
 * bytes is THE encoding of the result.
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
  let thing: string;
  try {
    thing = utf8Decoder.decode(thingBytes);
  } catch {
    throw new EncodingError("payout thing is not valid UTF-8");
  }
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

  const evidenceTag = r.u8();
  if (evidenceTag !== TAG_EVIDENCE_TRANSPARENT && evidenceTag !== TAG_EVIDENCE_SILENCE) {
    throw new EncodingError(`unsupported evidence tag ${evidenceTag}`);
  }
  const operator = r.raw(KEY_LENGTH);
  const silence =
    evidenceTag === TAG_EVIDENCE_SILENCE
      ? { noCommitmentDuration: r.u64(), challengeWindow: r.u64() }
      : undefined;

  r.expectEnd();
  return makeBacking({
    obligor,
    payout: { thing, quantumExponent, perUnit },
    reliance,
    evidence:
      silence === undefined
        ? { setting: "transparent", operator }
        : { setting: "transparent", operator, silence },
  });
}

/** The backing's name: SHA-256 of its canonical encoding (invariant 1). */
export function backingName(backing: Backing): Uint8Array {
  return copyBytes(backing.name);
}

function signedMessage(name: Uint8Array): Uint8Array {
  const w = new ByteWriter();
  w.context(BACKING_SIGNATURE_CONTEXT);
  w.key32(name, "backing name");
  return w.finish();
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
  return ed25519.sign(signedMessage(backing.name), secretKey);
}

/**
 * A backing without this check passing does not exist (invariant 2): anyone
 * could publish well-formed terms naming somebody else's key as obligor.
 * Returns false (never throws) for any malformed signature or key.
 */
export function verifyBackingSignature(backing: Backing, signature: Uint8Array): boolean {
  return verifySignatureStrict(signature, signedMessage(backing.name), backing.obligor);
}
