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
// The root is over the *whole* served state, which a verifier must be given
// to check (the spec's availability point: "somebody has to serve" the
// trail). Per-element membership / non-membership proofs — the Merkle
// machinery the recovery path needs — are deferred with that path.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bigintToMinimalBytes, ByteWriter, compareBytes } from "./bytes.js";
import { verifySignatureStrict } from "./keys.js";
import type { OpLogEntry } from "./ledger.js";

const textEncoder = new TextEncoder();
const COMMITMENT_CONTEXT = textEncoder.encode("mfp/commitment/v1");

const KIND_TAG: Record<OpLogEntry["kind"], number> = {
  issue: 0x01,
  transfer: 0x02,
  burn: 0x03,
};

/** One served backing's committed state, as published for verification. */
export interface BackingSnapshot {
  readonly name: Uint8Array;
  readonly issued: bigint;
  readonly burned: bigint;
  /** [holder key, units], any order — canonicalized here by key bytes. */
  readonly balances: readonly (readonly [Uint8Array, bigint])[];
  readonly opLog: readonly OpLogEntry[];
}

export interface Commitment {
  readonly index: bigint;
  readonly root: Uint8Array;
  readonly operator: Uint8Array;
  readonly signature: Uint8Array;
}

function writeOpEntry(w: ByteWriter, entry: OpLogEntry): void {
  w.u8(KIND_TAG[entry.kind]);
  w.u64(BigInt(entry.position));
  switch (entry.kind) {
    case "issue":
      w.raw(entry.recipient);
      break;
    case "transfer":
      w.raw(entry.from);
      w.raw(entry.to);
      break;
    case "burn":
      w.raw(entry.holder);
      break;
  }
  w.lengthPrefixed(bigintToMinimalBytes(entry.quantity));
  w.u64(entry.nonce);
}

function encodeSnapshot(snapshot: BackingSnapshot): Uint8Array {
  const w = new ByteWriter();
  w.raw(snapshot.name);
  // issued/burned can be zero, so encode them length-prefixed (minimal bytes,
  // empty for zero) rather than through the >=1 quantity rule.
  w.lengthPrefixed(bigintToMinimalBytes(snapshot.issued));
  w.lengthPrefixed(bigintToMinimalBytes(snapshot.burned));
  const balances = [...snapshot.balances].sort((a, b) => compareBytes(a[0], b[0]));
  w.u32(balances.length);
  for (const [key, units] of balances) {
    w.raw(key);
    w.lengthPrefixed(bigintToMinimalBytes(units));
  }
  w.u32(snapshot.opLog.length);
  for (const entry of snapshot.opLog) writeOpEntry(w, entry);
  return w.finish();
}

/**
 * The deterministic root over a set of served backings. Sorted by backing
 * name so the root is independent of the order the sequencer iterates.
 */
export function stateRoot(snapshots: readonly BackingSnapshot[]): Uint8Array {
  const sorted = [...snapshots].sort((a, b) => compareBytes(a.name, b.name));
  const w = new ByteWriter();
  w.u32(sorted.length);
  for (const snapshot of sorted) {
    w.lengthPrefixed(sha256(encodeSnapshot(snapshot)));
  }
  return sha256(w.finish());
}

function commitmentMessage(index: bigint, root: Uint8Array): Uint8Array {
  const w = new ByteWriter();
  w.raw(COMMITMENT_CONTEXT);
  w.u64(index);
  w.raw(root);
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
  return verifySignatureStrict(
    commitment.signature,
    commitmentMessage(commitment.index, commitment.root),
    commitment.operator,
  );
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
