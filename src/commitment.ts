// Commitments over ledger state (invariants 22, 23).
//
// At each interval a sequencer publishes a commitment: a signed hash over the
// state it serves. Invariant 23 (transparent subset): the commitment commits
// to the issuance log, the spent set and running totals — here, per backing,
// its name, issued/burned totals, current balances, and the full operation
// log. Invariant 22: every state a sequencer asserts must prove against its
// latest published commitment, so two commitments at the same index with
// different roots, both validly signed by the operator, are provable
// equivocation.
//
// The root must be INJECTIVE or invariant 22 is worthless: if two different
// served states hash to one root, an operator equivocates with a single
// signature and no provable fault. Injectivity comes from the framing rule —
// every key and name goes through key32 (fixed width, asserted) and every
// variable-length field is length-prefixed. Writing keys raw is what breaks
// it: a 31-byte and a 33-byte key concatenate exactly like two 32-byte keys.
//
// The root is over the whole served state, which a verifier must be given to
// check (the spec's availability point: "somebody has to serve" the trail).
// Per-element membership / non-membership proofs are deferred with the
// recovery path.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bigintToMinimalBytes,
  ByteWriter,
  compareBytes,
  EncodingError,
  MAX_QUANTITY_EXCLUSIVE,
} from "./bytes.js";
import { COMMITMENT_CONTEXT } from "./contexts.js";
import { verifySignatureStrict } from "./keys.js";
import type { BackingSnapshot, OpLogEntry } from "./ledger.js";

export type { BackingSnapshot } from "./ledger.js";

const KIND_TAG: Record<OpLogEntry["kind"], number> = {
  issue: 0x01,
  transfer: 0x02,
  burn: 0x03,
};

export interface Commitment {
  readonly index: bigint;
  readonly root: Uint8Array;
  readonly operator: Uint8Array;
  readonly signature: Uint8Array;
}

/**
 * Totals and balances may be zero, so they use a non-negative form rather than
 * the >=1 quantity rule — but they are still bounded. Without the bound an
 * attacker-supplied state could carry a multi-megabit integer and make the
 * verifier grind, turning "a malformed state fails the proof" into a hang.
 */
function writeAmount(w: ByteWriter, n: bigint, what: string): void {
  if (n < 0n) throw new EncodingError(`${what} is negative`);
  if (n >= MAX_QUANTITY_EXCLUSIVE) throw new EncodingError(`${what} out of range`);
  w.lengthPrefixed(bigintToMinimalBytes(n));
}

function writeOpEntry(w: ByteWriter, entry: OpLogEntry, index: number): void {
  w.u8(KIND_TAG[entry.kind]);
  // The position is pinned to the array index, not merely well-formed. A
  // self-declared position lets an operator commit to a log with a gap, so a
  // holder's valid receipt for the missing position proves against nothing
  // while the state itself still verifies — asserted state that hides an
  // accepted operation.
  if (entry.position !== index) {
    throw new EncodingError("op-log position does not match its index");
  }
  w.u64(BigInt(entry.position));
  switch (entry.kind) {
    case "issue":
      w.key32(entry.recipient, "recipient key");
      break;
    case "transfer":
      w.key32(entry.from, "from key");
      w.key32(entry.to, "to key");
      break;
    case "burn":
      w.key32(entry.holder, "holder key");
      break;
  }
  writeAmount(w, entry.quantity, "quantity");
  w.u64(entry.nonce);
}

function encodeSnapshot(snapshot: BackingSnapshot): Uint8Array {
  const w = new ByteWriter();
  w.key32(snapshot.name, "backing name");
  writeAmount(w, snapshot.issued, "issued");
  writeAmount(w, snapshot.burned, "burned");
  const balances = [...snapshot.balances].sort((a, b) => compareBytes(a[0], b[0]));
  for (let i = 1; i < balances.length; i++) {
    // One holder twice would leave the committed state without a single
    // meaning: sum, first-wins and last-wins readers would disagree under one
    // valid signature, and no second root exists to prove a fault.
    if (compareBytes((balances[i - 1] as readonly [Uint8Array, bigint])[0], (balances[i] as readonly [Uint8Array, bigint])[0]) === 0) {
      throw new EncodingError("duplicate holder in balances");
    }
  }
  w.u32(balances.length);
  for (const [key, units] of balances) {
    w.key32(key, "holder key");
    writeAmount(w, units, "balance");
  }
  w.u32(snapshot.opLog.length);
  snapshot.opLog.forEach((entry, i) => writeOpEntry(w, entry, i));
  return w.finish();
}

/**
 * The deterministic root over a set of served backings. Sorted by backing name
 * so the root is independent of the order the sequencer iterates, and two
 * snapshots for one backing are rejected rather than silently order-dependent.
 * Throws EncodingError on a malformed state; use stateProvesCommitment when
 * checking state from an untrusted source.
 */
export function stateRoot(snapshots: readonly BackingSnapshot[]): Uint8Array {
  const sorted = [...snapshots].sort((a, b) => compareBytes(a.name, b.name));
  for (let i = 1; i < sorted.length; i++) {
    if (compareBytes((sorted[i - 1] as BackingSnapshot).name, (sorted[i] as BackingSnapshot).name) === 0) {
      throw new EncodingError("duplicate backing in state");
    }
  }
  const w = new ByteWriter();
  w.u32(sorted.length);
  for (const snapshot of sorted) {
    w.key32(sha256(encodeSnapshot(snapshot)), "snapshot digest");
  }
  return sha256(w.finish());
}

/**
 * Whether a served state is the state a commitment commits to (invariant 22).
 * Never throws: a malformed state is a failed proof, not a crash.
 */
export function stateProvesCommitment(
  snapshots: readonly BackingSnapshot[],
  commitment: Commitment,
): boolean {
  let root: Uint8Array;
  try {
    root = stateRoot(snapshots);
  } catch {
    return false;
  }
  return compareBytes(root, commitment.root) === 0 && verifyCommitment(commitment);
}

function commitmentMessage(index: bigint, root: Uint8Array): Uint8Array {
  const w = new ByteWriter();
  w.context(COMMITMENT_CONTEXT);
  w.u64(index);
  w.key32(root, "root");
  return w.finish();
}

export function signCommitment(
  operatorSecret: Uint8Array,
  index: bigint,
  root: Uint8Array,
): Commitment {
  const operator = ed25519.getPublicKey(operatorSecret);
  const signature = ed25519.sign(commitmentMessage(index, root), operatorSecret);
  return { index, root, operator, signature };
}

/** A commitment is valid iff the operator signed exactly (index, root). */
export function verifyCommitment(commitment: Commitment): boolean {
  let message: Uint8Array;
  try {
    message = commitmentMessage(commitment.index, commitment.root);
  } catch {
    return false;
  }
  return verifySignatureStrict(commitment.signature, message, commitment.operator);
}

/**
 * Two commitments are equivocation iff the same operator validly signed two
 * different roots at the same index — a provable fault against invariant 22.
 */
export function isEquivocation(a: Commitment, b: Commitment): boolean {
  return (
    compareBytes(a.operator, b.operator) === 0 &&
    a.index === b.index &&
    compareBytes(a.root, b.root) !== 0 &&
    verifyCommitment(a) &&
    verifyCommitment(b)
  );
}
