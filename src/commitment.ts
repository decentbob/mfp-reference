// Commitments over ledger state (invariants 22, 23).
//
// At each interval a sequencer publishes a commitment: a signed hash over the
// state it serves. Invariant 23 (transparent subset): the commitment commits
// to "the issuance log, the spent set, running totals and the standing demand
// record" — here, per backing, its name, issued/burned totals, current
// balances, the full operation log (all seven kinds, presentation included) and
// the open demands. Invariant 22: every state a sequencer asserts must prove
// against its latest published commitment, so two commitments at the same index
// with different roots, both validly signed by the operator, are provable
// equivocation.
//
// The log and the demand record are both committed and neither is redundant:
// the record is the current state, the log is the history. A settled or
// withdrawn demand leaves the record, so only the log can still show that it
// happened — and only the record can show that it stands.
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
  copyBytes,
  EncodingError,
  MAX_QUANTITY_EXCLUSIVE,
} from "./bytes.js";
import { COMMITMENT_CONTEXT } from "./contexts.js";
import { verifySignatureStrict } from "./keys.js";
import type { BackingSnapshot, DemandRecord } from "./ledger.js";
import { opMessageOfEntry, type OpLogEntry } from "./oplog.js";
import { encodeDemandMessage } from "./presentation.js";

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

/**
 * A standing demand is committed as the holder's own signed demand, plus the
 * backer's answer. Committing a self-declared identity would commit nothing: an
 * operator could publish a genuine hash beside a different quantity and the
 * state would still verify. Committing the signed bytes commits the hash too,
 * since the hash is derived from them — and a verifier recomputes it, which is
 * the point.
 */
function writeDemand(w: ByteWriter, name: Uint8Array, record: DemandRecord): void {
  // An answer may not outlast the demand's own deadline — the range `accept`
  // enforces. This is not a second mechanism for that rule but the same rule
  // applied to the other input: served state may come from a hostile operator
  // rather than from this ledger, so the encoder is what defines which states
  // are canonical, exactly as it does for op-log positions. Unbounded, an
  // operator (frequently the backer, §C3) could serve a demand as answered with
  // no acceptance signature anywhere and isDishonoured — which reads the
  // committed record — would report the backer's failure as an answer forever.
  // Bounded, every servable record reports the dishonour past the demand's
  // deadline, because past it the answer cannot still be live.
  if (record.acceptedDeadline !== undefined && record.acceptedDeadline > record.deadline) {
    throw new EncodingError("accepted deadline outlasts the demand's own deadline");
  }
  w.lengthPrefixed(
    encodeDemandMessage(
      name,
      record.holder,
      record.quantity,
      record.instant,
      record.deadline,
      record.nonce,
    ),
  );
  // A presence byte, then the value only when present: unambiguous, because
  // the byte decides whether the next eight belong to this field.
  if (record.acceptedDeadline === undefined) {
    w.u8(0);
  } else {
    w.u8(1);
    w.u64(record.acceptedDeadline);
  }
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
  snapshot.opLog.forEach((entry, i) => writeOpEntry(w, snapshot.name, entry, i));
  // Invariant 23: the commitment commits to the standing demand record too,
  // so a holder can prove their claims are committed against payment.
  // Ordered by (holder, nonce): both are committed fields and the pair is
  // unique per demand, so the order is a function of the committed data rather
  // than of anything the operator declares separately.
  const demands = [...snapshot.demands].sort(
    (a, b) => compareBytes(a.holder, b.holder) || (a.nonce < b.nonce ? -1 : a.nonce > b.nonce ? 1 : 0),
  );
  for (let i = 1; i < demands.length; i++) {
    const previous = demands[i - 1] as DemandRecord;
    const current = demands[i] as DemandRecord;
    if (compareBytes(previous.holder, current.holder) === 0 && previous.nonce === current.nonce) {
      throw new EncodingError("duplicate demand in state");
    }
  }
  w.u32(demands.length);
  for (const record of demands) writeDemand(w, snapshot.name, record);
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
 * venue, which copies on the way in. Nothing here holds the caller's array.
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
  let message: Uint8Array;
  try {
    message = commitmentMessage(commitment.sequence, commitment.root);
  } catch {
    return false;
  }
  return verifySignatureStrict(commitment.signature, message, commitment.operator);
}

/**
 * Two commitments are equivocation iff the same operator validly signed two
 * different roots at one sequence number — a provable fault against invariant
 * 22. Keyed on the operator's own sequence, not on the venue's clock: an
 * operator publishing two roots in one venue interval is ordinary batching,
 * while signing two roots as its Nth commitment is the fault.
 */
export function isEquivocation(a: Commitment, b: Commitment): boolean {
  return (
    compareBytes(a.operator, b.operator) === 0 &&
    a.sequence === b.sequence &&
    compareBytes(a.root, b.root) !== 0 &&
    verifyCommitment(a) &&
    verifyCommitment(b)
  );
}
