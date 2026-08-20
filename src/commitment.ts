// Commitments over ledger state (invariants 22, 23).
//
// At each interval a sequencer publishes a commitment: a signed hash over the
// state it serves — per backing, its name and its full operation log, all seven
// kinds with presentation included. Invariant 22: every state a sequencer
// asserts must prove against its latest published commitment, so two
// commitments at one sequence number over different roots, both validly signed
// by the operator, are provable equivocation.
//
// **The log is all that is committed, because the log is all there is.**
// Invariant 23 asks the commitment to commit to "the issuance log, the spent
// set, running totals and the standing demand record"; under transparent the log
// determines every one of them, so committing it commits them all. Balances,
// totals and the standing demands were once committed beside it and re-derived
// by the verifier — three mechanisms for data one of them fixes, and the source
// of a run of "field X is not tied to the log" bugs, each patched separately.
// Deriving them instead does not check that class of lie; it makes it
// unsayable. Invariant 10 comes with it: every operation the replay applies
// either conserves the total or moves issued/burned with it, so
// `outstanding = issued − burned` is a property of the fold rather than an
// assertion to police.
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
// That is also why invariant 23's per-element non-membership proofs are not
// here: under transparent the whole state is served and rehashed, so serving
// everything IS the proof. The Merkle machinery is what a construction needs
// when it cannot serve everything, which is the shielded ones. See DECISIONS.md.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ByteWriter, compareBytes, copyBytes, EncodingError } from "./bytes.js";
import { COMMITMENT_CONTEXT } from "./contexts.js";
import { verifySignatureStrict } from "./keys.js";
import type { Backing } from "./backing.js";
import type { BackingSnapshot } from "./ledger.js";
import { isAnOperator } from "./replacement.js";
import type { Venue } from "./venue.js";
import { opMessageOfEntry, type OpLogEntry } from "./oplog.js";

export type { BackingSnapshot } from "./ledger.js";

export interface Commitment {
  /**
   * The operator's own count of its commitments — NOT the venue's witnessed
   * index. Equivocation is two different roots signed at one sequence number;
   * the clock deadlines are read against is the venue's (venue.ts).
   */
  readonly sequence: bigint;
  readonly root: Uint8Array;
  readonly operator: Uint8Array;
  readonly signature: Uint8Array;
}

/**
 * A snapshot of a commitment's bytes. `readonly` is erased at runtime and does
 * not stop a Uint8Array's contents changing, so anything that stores or serves a
 * commitment copies it (CLAUDE.md: copy on the way in, copy on the way out).
 * Without it an operator can mutate the object it published and retroactively
 * deny its own commitment.
 */
export function copyCommitment(commitment: Commitment): Commitment {
  return {
    sequence: commitment.sequence,
    root: copyBytes(commitment.root),
    operator: copyBytes(commitment.operator),
    signature: copyBytes(commitment.signature),
  };
}

/**
 * A logged operation is committed as the exact bytes the party signed. So the
 * commitment commits the operation a receipt attests to rather than a
 * re-description of it, "the committed entry reconstructs to the receipt's op
 * hash" holds by construction, and no kind tag is needed: every message opens
 * with its own domain tag, and contexts.ts asserts those are prefix-free.
 */
function writeOpEntry(w: ByteWriter, name: Uint8Array, entry: OpLogEntry, index: number): void {
  // The position is pinned to the array index, not merely well-formed. A
  // self-declared position lets an operator commit to a log with a gap, so a
  // holder's valid receipt for the missing position proves against nothing
  // while the state itself still verifies — asserted state that hides an
  // accepted operation. Pinned, the position carries no information the index
  // does not, so it is not written.
  if (entry.position !== index) {
    throw new EncodingError("op-log position does not match its index");
  }
  w.lengthPrefixed(opMessageOfEntry(name, entry));
}

function encodeSnapshot(snapshot: BackingSnapshot): Uint8Array {
  const w = new ByteWriter();
  w.key32(snapshot.name, "backing name");
  w.u32(snapshot.opLog.length);
  snapshot.opLog.forEach((entry, i) => writeOpEntry(w, snapshot.name, entry, i));
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

/** A served state and the commitment it must prove against — what a holder is handed. */
export interface ServedState {
  readonly snapshots: readonly BackingSnapshot[];
  readonly commitment: Commitment;
}

/**
 * This backing's operation log out of a state one of its **own** operators
 * really committed, or undefined where the state is not that.
 *
 * Three questions that always travel together: is this commitment signed by a
 * key that has served this backing (anyone can sign a valid commitment over any
 * state they like), is the served state the one it commits to, and does it carry
 * this backing at all. They were asked in three places — the redemption walk, a
 * receipt's standing, and a rewritten history — so they are asked here instead.
 *
 * **A key that has served, not the key E names.** After a handover the state of
 * record is the successor's, and a predecessor's committed state is still the
 * history it really committed — §C2's "a wallet verifies the chain rather than
 * the key it remembers". Membership rather than time, because a commitment
 * carries a sequence of its operator's own counting and not a venue index, so
 * "was this key in force then" is not a question its bytes can answer. What
 * decides which committed state is current is the operator in force now
 * (replayLatestState), and that does read the chain by index.
 *
 * Returns the sequence beside the log, because every caller that compares two
 * committed states needs to know which came first, and taking that from the
 * caller would let it choose.
 */
export function committedLogFor(
  backing: Backing,
  venue: Venue,
  served: ServedState,
): { readonly sequence: bigint; readonly opLog: readonly OpLogEntry[] } | undefined {
  try {
    if (!isAnOperator(backing, venue, served.commitment.operator)) return undefined;
    if (!stateProvesCommitment(served.snapshots, served.commitment)) return undefined;
    const snapshot = served.snapshots.find((s) => compareBytes(s.name, backing.name) === 0);
    if (snapshot === undefined) return undefined;
    return { sequence: served.commitment.sequence, opLog: snapshot.opLog };
  } catch {
    return undefined;
  }
}

function commitmentMessage(sequence: bigint, root: Uint8Array): Uint8Array {
  const w = new ByteWriter();
  w.context(COMMITMENT_CONTEXT);
  w.u64(sequence);
  w.key32(root, "root");
  return w.finish();
}

/**
 * Sign a root as this operator's next commitment. Does not copy `root`, where
 * signReceipt copies what it is handed: the difference is that the sequencer
 * retains the receipts it issues, while a commitment is retained only by the
 * venue, which copies on the way in. The returned object does alias `root`, so a
 * caller that mutates it before publishing invalidates its own commitment and
 * nobody else's.
 */
export function signCommitment(
  operatorSecret: Uint8Array,
  sequence: bigint,
  root: Uint8Array,
): Commitment {
  const operator = ed25519.getPublicKey(operatorSecret);
  const signature = ed25519.sign(commitmentMessage(sequence, root), operatorSecret);
  return { sequence, root, operator, signature };
}

/** A commitment is valid iff the operator signed exactly (sequence, root). */
export function verifyCommitment(commitment: Commitment): boolean {
  try {
    const message = commitmentMessage(commitment.sequence, commitment.root);
    return verifySignatureStrict(commitment.signature, message, commitment.operator);
  } catch {
    return false;
  }
}

/**
 * Two commitments are equivocation iff the same operator validly signed two
 * different roots at one sequence number — a provable fault against invariant
 * 22. Keyed on the operator's own sequence, not on the venue's clock: an
 * operator publishing two roots in one venue interval is ordinary batching,
 * while signing two roots as its Nth commitment is the fault.
 */
export function isEquivocation(a: Commitment, b: Commitment): boolean {
  // A verifier, and it was the one that did not say so: anyone may exhibit two
  // commitments they found at a venue, and these fields are read before
  // anything verifies them, so a malformed one crashed the proof instead of
  // failing it. The try is the mechanism the other fault predicates already use
  // (receiptCovers, isDoublePosition, equivocatingSigner), not a new layer.
  try {
    return (
      compareBytes(a.operator, b.operator) === 0 &&
      a.sequence === b.sequence &&
      compareBytes(a.root, b.root) !== 0 &&
      verifyCommitment(a) &&
      verifyCommitment(b)
    );
  } catch {
    return false;
  }
}
