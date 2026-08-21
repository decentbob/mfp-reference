// Presentation and dishonour (§C3): the signed messages.
//
// Consent between the parties is demand–accept–release. This slice implements
// the single-phase case, which §C3 licenses "wherever every lock in the set can
// be taken in one atomically signed decision: R empty and the payout settling
// outside the claim layer" — one sequencer, and the backer paying in something
// the claim layer does not carry. Prepare–decide–commit (atomicity across
// sequencers) is a later slice; see DECISIONS.md.
//
// Four messages, each domain-separated (contexts.ts) and framed (bytes.ts):
//
//   demand      context || backing name (32) || holder key (32)
//               || u32 length || quantity || u64 instant || u64 deadline
//               || u64 nonce
//   acceptance  context || backing name (32) || demand hash (32)
//               || u64 instant || u64 deadline || u64 nonce
//   release     context || backing name (32) || demand hash (32) || u64 nonce
//   withdrawal  context || backing name (32) || demand hash (32) || u64 nonce
//
// A demand is identified by the hash of its own canonical encoding, so an
// acceptance, a release and a withdrawal each name one exact demand — the
// "specific claims" §C3 requires, expressed as a commitment to the whole
// demand rather than to a quantity that two demands could share.
//
// As in messages.ts, the field-level encoders take the backing NAME rather than
// the Backing object, so a verifier holding only a committed operation-log
// entry can reconstruct the exact signed message and hence its hash (oplog.ts).
// The op-shaped wrappers below feed them backing.name.
//
// Instants and deadlines are witnessed indices — the operator's commitment
// index at the venue — never wall-clock time (§C0b, invariant 21). The
// acceptance repeats the instant so that agreeing it takes two signatures over
// one value (invariant 24).

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { type Backing } from "./backing.js";
import { bigintToMinimalBytes, ByteReader, ByteWriter, copyBytes, validateQuantity } from "./bytes.js";
import { verifySignatureStrict } from "./keys.js";
import {
  ACCEPTANCE_CONTEXT,
  DEMAND_CONTEXT,
  RELEASE_CONTEXT,
  WITHDRAWAL_CONTEXT,
  LOCK_CONTEXT,
  COMMIT_CONTEXT,
} from "./contexts.js";

/** A holder presenting claims for payment. */
export interface DemandOp {
  readonly backing: Backing;
  readonly holder: Uint8Array;
  readonly quantity: bigint;
  /** The witnessed index the payout is evaluated at (invariant 24). */
  readonly instant: bigint;
  /** The witnessed index past which non-payment is a public fact. */
  readonly deadline: bigint;
  readonly nonce: bigint;
}

/** A backer answering a demand: agrees the instant, carries its own deadline. */
export interface AcceptanceOp {
  readonly backing: Backing;
  readonly demandHash: Uint8Array;
  /** Must equal the demand's instant — two signatures over one value. */
  readonly instant: bigint;
  /** By when the holder may release against this acceptance. */
  readonly deadline: bigint;
  readonly nonce: bigint;
}

/** A holder settling an accepted demand. Settlement needs this AND the acceptance. */
export interface ReleaseOp {
  readonly backing: Backing;
  readonly demandHash: Uint8Array;
  readonly nonce: bigint;
}

/**
 * A holder reserving one reliance leg against a demand (invariant 13, §C3's
 * prepare).
 *
 * Presenting *b* for *q* means handing over *q·cᵢ* units of each *(bᵢ, cᵢ)* in
 * R(b), and those units live in another backing's ledger entirely — so the
 * reservation is an operation in the LEG's own log, signed by the holder whose
 * units it commits. That keeps every backing replayable on its own, which is
 * what provesHolding, the redemption walk and committedOutstanding all rest on.
 *
 * **The beneficiary is signed**, and it is the DEMANDED backing's obligor rather
 * than this leg's: the backer of *b* takes in the whole set and may then present
 * at *bᵢ* itself, which is what reliance is for. Signed rather than supplied at
 * release time, or the operator would choose where the accompaniment goes.
 */
export interface LockOp {
  /** The backing whose units are reserved. */
  readonly backing: Backing;
  /**
   * The atomic attempt these units are reserved for, named by the holder.
   *
   * **A presentation's attempt is its demand**, so the id is that demand's hash
   * and everything about reliance legs reads unchanged. A bundle transfer picks
   * its own id, and nothing else about the mechanism differs — the reservation,
   * the timeout and the exit are one set of rules, because they are one property:
   * units spoken for by an attempt that will either commit or expire.
   */
  readonly attemptId: Uint8Array;
  readonly holder: Uint8Array;
  /** Where these units go if the attempt commits. */
  readonly beneficiary: Uint8Array;
  /** Whole units of this backing reserved. */
  readonly quantity: bigint;
  /**
   * §C3's **lock timeout**: the witnessed index past which this attempt is over.
   *
   * "The lock timeout the holder declared in the prepare, itself a witnessed
   * index, unlocks everywhere... It is not the demand's deadline: the timeout
   * ends the atomic attempt, the deadline governs evidence, and a demand
   * outlives its locks." So an expired attempt is a retry rather than a lost
   * demand, and the holder chooses the window because the holder bears the
   * lock-up — the same reason §C3 makes the deadline theirs.
   */
  readonly timeout: bigint;
  /**
   * The venue whose witnessed indices the timeout is read against, and where the
   * commit must appear (§C3: "A cross-operator prepare names a decision venue:
   * one venue among those the set's backings declare, on whose witnessed indices
   * the lock timeout is read, so every sequencer evaluates one predicate against
   * one clock"). Signed by the holder, or an operator could read the deadline on
   * a friendlier clock. A sequencer that does not watch it refuses to prepare,
   * "which is an abort rather than a fork".
   */
  readonly decisionVenue: Uint8Array;
  readonly nonce: bigint;
}

/**
 * §C3's commit, and the object the whole mechanism turns on.
 *
 * "The holder publishes a release to the witnessed venue, **effective on
 * witnessing rather than delivery**, so every sequencer evaluates one predicate
 * against the same object: was a valid release witnessed at or before the lock
 * timeout?"
 *
 * **It names no backing, deliberately.** The same signed bytes have to be valid
 * in every log in the bundle, or it is n objects rather than one — and n objects
 * can reach some sequencers and not others before the timeout, which is the split
 * this exists to prevent. Delivery is a fact about a message and differs per
 * recipient; witnessing is a fact about the record and is the same for everyone.
 *
 * **And it carries no nonce**, for the same reason: one signature cannot sit at
 * one signer's next nonce in several backings at once. Safe here where it would
 * not be elsewhere — a commit is idempotent, since the lock it settles is gone
 * afterwards, and it is scoped to an attempt only its own holder could have
 * named in a lock. Both departures are the price of "one object", and they are
 * the only two.
 */
export interface Commit {
  readonly attemptId: Uint8Array;
  readonly signature: Uint8Array;
}

/** A holder ending an unanswered demand — the protection against stalling. */
export interface WithdrawalOp {
  readonly backing: Backing;
  readonly demandHash: Uint8Array;
  readonly nonce: bigint;
}

export function encodeDemandMessage(
  backingName: Uint8Array,
  holder: Uint8Array,
  quantity: bigint,
  instant: bigint,
  deadline: bigint,
  nonce: bigint,
): Uint8Array {
  validateQuantity(quantity, "demand quantity");
  const w = new ByteWriter();
  w.context(DEMAND_CONTEXT);
  w.key32(backingName, "backing name");
  w.key32(holder, "holder key");
  w.lengthPrefixed(bigintToMinimalBytes(quantity));
  w.u64(instant);
  w.u64(deadline);
  w.u64(nonce);
  return w.finish();
}

export function encodeAcceptanceMessage(
  backingName: Uint8Array,
  demandHash: Uint8Array,
  instant: bigint,
  deadline: bigint,
  nonce: bigint,
): Uint8Array {
  const w = new ByteWriter();
  w.context(ACCEPTANCE_CONTEXT);
  w.key32(backingName, "backing name");
  w.key32(demandHash, "demand hash");
  w.u64(instant);
  w.u64(deadline);
  w.u64(nonce);
  return w.finish();
}

/** Release and withdrawal are the same shape: one demand, one nonce. */
function endOfDemandMessage(
  context: Uint8Array,
  backingName: Uint8Array,
  demandHash: Uint8Array,
  nonce: bigint,
): Uint8Array {
  const w = new ByteWriter();
  w.context(context);
  w.key32(backingName, "backing name");
  w.key32(demandHash, "demand hash");
  w.u64(nonce);
  return w.finish();
}

export function encodeReleaseMessage(
  backingName: Uint8Array,
  demandHash: Uint8Array,
  nonce: bigint,
): Uint8Array {
  return endOfDemandMessage(RELEASE_CONTEXT, backingName, demandHash, nonce);
}

export function encodeWithdrawalMessage(
  backingName: Uint8Array,
  demandHash: Uint8Array,
  nonce: bigint,
): Uint8Array {
  return endOfDemandMessage(WITHDRAWAL_CONTEXT, backingName, demandHash, nonce);
}

export function encodeLockMessage(
  backingName: Uint8Array,
  attemptId: Uint8Array,
  holder: Uint8Array,
  beneficiary: Uint8Array,
  quantity: bigint,
  timeout: bigint,
  decisionVenue: Uint8Array,
  nonce: bigint,
): Uint8Array {
  validateQuantity(quantity, "lock quantity");
  const w = new ByteWriter();
  w.context(LOCK_CONTEXT);
  w.key32(backingName, "backing name");
  w.key32(attemptId, "attempt id");
  w.key32(holder, "holder key");
  w.key32(beneficiary, "beneficiary key");
  w.lengthPrefixed(bigintToMinimalBytes(quantity));
  w.u64(timeout);
  w.key32(decisionVenue, "decision venue");
  w.u64(nonce);
  return w.finish();
}

/** The bytes a holder signs to commit one attempt, everywhere at once. */
export function commitMessage(attemptId: Uint8Array): Uint8Array {
  const w = new ByteWriter();
  w.context(COMMIT_CONTEXT);
  w.key32(attemptId, "attempt id");
  return w.finish();
}

/** Commit an attempt. Idempotent by construction: the bytes never vary. */
export function signCommit(holderSecret: Uint8Array, attemptId: Uint8Array): Commit {
  return {
    attemptId: copyBytes(attemptId),
    signature: ed25519.sign(commitMessage(attemptId), holderSecret),
  };
}

/** A commit as a record, for a venue that stores bytes: attempt, then signature. */
export function encodeCommit(commit: Commit): Uint8Array {
  const w = new ByteWriter();
  w.key32(commit.attemptId, "attempt id");
  w.fixed(commit.signature, 64, "signature");
  return w.finish();
}

/** Strict inverse of encodeCommit. Throws EncodingError on anything else. */
export function decodeCommit(bytes: Uint8Array): Commit {
  const r = new ByteReader(bytes);
  const attemptId = r.raw(32);
  const signature = r.raw(64);
  r.expectEnd();
  return { attemptId, signature };
}

/** Whether this is a valid commit of that attempt by that key. A verifier. */
export function isSignedCommit(commit: Commit, holder: Uint8Array): boolean {
  try {
    return verifySignatureStrict(commit.signature, commitMessage(commit.attemptId), holder);
  } catch {
    return false;
  }
}

export function encodeLock(op: LockOp): Uint8Array {
  return encodeLockMessage(
    op.backing.name,
    op.attemptId,
    op.holder,
    op.beneficiary,
    op.quantity,
    op.timeout,
    op.decisionVenue,
    op.nonce,
  );
}

export function encodeDemand(op: DemandOp): Uint8Array {
  return encodeDemandMessage(
    op.backing.name,
    op.holder,
    op.quantity,
    op.instant,
    op.deadline,
    op.nonce,
  );
}

/** A demand's identity: the hash of its canonical encoding. */
export function demandHash(op: DemandOp): Uint8Array {
  return sha256(encodeDemand(op));
}

export function encodeAcceptance(op: AcceptanceOp): Uint8Array {
  return encodeAcceptanceMessage(
    op.backing.name,
    op.demandHash,
    op.instant,
    op.deadline,
    op.nonce,
  );
}

export function encodeRelease(op: ReleaseOp): Uint8Array {
  return encodeReleaseMessage(op.backing.name, op.demandHash, op.nonce);
}

export function encodeWithdrawal(op: WithdrawalOp): Uint8Array {
  return encodeWithdrawalMessage(op.backing.name, op.demandHash, op.nonce);
}
