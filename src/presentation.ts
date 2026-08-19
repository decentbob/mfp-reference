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
// Instants and deadlines are witnessed indices — the operator's commitment
// index at the venue — never wall-clock time (§C0b, invariant 21). The
// acceptance repeats the instant so that agreeing it takes two signatures over
// one value (invariant 24).

import { sha256 } from "@noble/hashes/sha2.js";
import { type Backing } from "./backing.js";
import { bigintToMinimalBytes, ByteWriter, validateQuantity } from "./bytes.js";
import {
  ACCEPTANCE_CONTEXT,
  DEMAND_CONTEXT,
  RELEASE_CONTEXT,
  WITHDRAWAL_CONTEXT,
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

/** A holder ending an unanswered demand — the protection against stalling. */
export interface WithdrawalOp {
  readonly backing: Backing;
  readonly demandHash: Uint8Array;
  readonly nonce: bigint;
}

export function encodeDemand(op: DemandOp): Uint8Array {
  validateQuantity(op.quantity, "demand quantity");
  const w = new ByteWriter();
  w.context(DEMAND_CONTEXT);
  w.key32(op.backing.name, "backing name");
  w.key32(op.holder, "holder key");
  w.lengthPrefixed(bigintToMinimalBytes(op.quantity));
  w.u64(op.instant);
  w.u64(op.deadline);
  w.u64(op.nonce);
  return w.finish();
}

/** A demand's identity: the hash of its canonical encoding. */
export function demandHash(op: DemandOp): Uint8Array {
  return sha256(encodeDemand(op));
}

export function encodeAcceptance(op: AcceptanceOp): Uint8Array {
  const w = new ByteWriter();
  w.context(ACCEPTANCE_CONTEXT);
  w.key32(op.backing.name, "backing name");
  w.key32(op.demandHash, "demand hash");
  w.u64(op.instant);
  w.u64(op.deadline);
  w.u64(op.nonce);
  return w.finish();
}

export function encodeRelease(op: ReleaseOp): Uint8Array {
  const w = new ByteWriter();
  w.context(RELEASE_CONTEXT);
  w.key32(op.backing.name, "backing name");
  w.key32(op.demandHash, "demand hash");
  w.u64(op.nonce);
  return w.finish();
}

export function encodeWithdrawal(op: WithdrawalOp): Uint8Array {
  const w = new ByteWriter();
  w.context(WITHDRAWAL_CONTEXT);
  w.key32(op.backing.name, "backing name");
  w.key32(op.demandHash, "demand hash");
  w.u64(op.nonce);
  return w.finish();
}
