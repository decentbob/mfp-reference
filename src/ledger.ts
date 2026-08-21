// The transparent claim layer (§C1): a per-backing public ledger of
// key-controlled balances, transfer by holder signature.
//
// The law, enforced structurally:
//   - nothing you owe grows without your signature: only `issue`, verified
//     against the registered backing's obligor key, raises the outstanding
//     count;
//   - nothing you hold leaves without your signature: `transfer` and `burn`
//     verify against the holding key itself. No other mutation path exists
//     (invariant 8) — there is deliberately no method that takes an operator's
//     or backer's authority over someone else's balance, and every accessor
//     returns a copy so a caller cannot reach in and mutate state.
//
// Conservation (invariant 10): outstanding = issued − burned, per backing,
// after every operation, and the sum of balances equals outstanding.
// Redemption is not a ledger concept: settling a demand moves the claims to the
// backer, who is then simply their holder, and only an explicit burn lowers the
// count.
//
// Every logged operation carries the signature that authorised it, so a served
// state can be checked for authenticity and not only for consistency (oplog.ts).
// The signature is stored beside the entry, not inside its canonical bytes.
//
// Every operation is atomic: all checks run before any mutation, so it either
// fully applies or throws with no state change. Every operation — the three that
// move value and the four of presentation — appends exactly one entry to the
// operation log and consumes exactly one nonce, both in `apply`, so there is
// one place where an operation becomes a fact. A signer's nonce is per
// (signer, backing).
//
// Operations whose outcome depends on time take the witnessed index they are
// judged against as an argument. Invariant 21 forbids a time a party asserts
// alone, so the ledger never reads a clock: the sequencer supplies the venue's
// latest index for an operation submitted to it, and the index the venue
// stamped a publication with for one adopted out of a §C2b gap.
//
// NOTE (later slices, see DECISIONS.md): op-log positions are the ledger's own
// per-backing append indices, which are the log's own bookkeeping and not a
// clock — the venue's witnessed index is that (venue.ts). The state below is
// the fold of the log and nothing else, kept incrementally here and replayed
// from scratch by a verifier through the same applyEntry. There are no
// commitments over it in this file; the sequencer adds those.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { makeBacking, verifyBackingSignature, type Backing } from "./backing.js";
import { compareBytes, copyBytes, MAX_QUANTITY_EXCLUSIVE } from "./bytes.js";
import { commitSatisfies } from "./presentation.js";
import { isValidPublicKey, verifySignatureStrict } from "./keys.js";
import {
  copyOp,
  copyOpEntry,
  opMessageOfEntry,
  unknownOpKind,
  type OpLogEntry,
  type PublishedOp,
} from "./oplog.js";
import type { AcceptanceOp, DemandOp, ReleaseOp, WithdrawalOp } from "./presentation.js";
import type { BurnOp, IssuanceOp, TransferOp } from "./messages.js";

/** The law refuses: bad signature, insufficient funds, unknown backing. */
export class LedgerError extends Error {}

/**
 * This nonce is not the signer's next. Distinguished so a caller can tell a
 * second spend at a used nonce from a funds or signature failure, without
 * re-deriving the expected nonce and re-checking it itself.
 */
export class NonceError extends LedgerError {}

/**
 * One backing's state, serialized for a verifier. This is what a commitment
 * commits to (invariant 23) and what a verifier is handed to check against a
 * root. Every field is a copy.
 */
export interface BackingSnapshot {
  readonly name: Uint8Array;
  /**
   * The whole operation log, which is the whole state: balances, running totals
   * and the standing demand record are all folds over it (oplog.ts, replayLog),
   * so serving it serves them. Committing them beside it would be three
   * mechanisms for what this one fixes — see commitment.ts.
   */
  readonly opLog: readonly OpLogEntry[];
}

/**
 * A standing demand: claims committed against payment until settlement or
 * withdrawal (§C3). Invariant 23 makes the standing demand record part of what
 * a commitment commits to, so it travels in the snapshot beside the totals.
 */
export interface DemandRecord {
  /** The demand's identity: the hash of its canonical encoding. */
  readonly hash: Uint8Array;
  readonly holder: Uint8Array;
  readonly quantity: bigint;
  /** Witnessed index the payout is evaluated at (invariant 24). */
  readonly instant: bigint;
  /** Witnessed index past which non-payment is a public fact. */
  readonly deadline: bigint;
  /** The holder's nonce, so a verifier can recompute the demand's hash. */
  readonly nonce: bigint;
  /** The backer's answer, once given. Absent means unanswered. */
  readonly acceptedDeadline: bigint | undefined;
}

/**
 * An acceptance holds the claims only until its own deadline (§C3): "An
 * acceptance carries its own deadline, or the backer holds a free option:
 * accept, keep the claims committed, wait for the payout to move." Release and
 * withdrawal are complements on this one predicate, so exactly one exit is open
 * at every index — and dishonour reads the same predicate rather than a second
 * notion of what counts as an answer.
 */
export function acceptanceIsLive(record: DemandRecord, atWitnessedIndex: bigint): boolean {
  return record.acceptedDeadline !== undefined && atWitnessedIndex <= record.acceptedDeadline;
}

/**
 * Dishonour is not a separate mechanism (§C3): it is the branch where the
 * acceptance never arrives. An acceptance that arrived and expired unpaid is
 * that same branch — read any other way, one free signature naming a deadline
 * nobody can release against launders the backer's failure forever, and §C3's
 * "claims still live past the deadline are the backer's visible failure" reports
 * nothing. Publicly checkable against the committed record and a witnessed
 * index, with nobody reporting anything.
 */
export function isDishonoured(record: DemandRecord, atWitnessedIndex: bigint): boolean {
  return !acceptanceIsLive(record, atWitnessedIndex) && atWitnessedIndex > record.deadline;
}

/**
 * The state a log folds to, and the ledger's own book — one shape, because they
 * are the same thing reached two ways.
 */
/**
 * One reliance leg reserved against a demand (§C3's prepare, invariant 13).
 *
 * It lives in the LEG's state, not the demanded backing's, because those units
 * are the leg's and every backing has to stay replayable on its own. What it
 * cannot see is the demand itself — that record is in another backing's state —
 * so this holds everything the leg needs to resolve without looking: whose units,
 * how many, and where they go if the demand settles.
 */
export interface LockRecord {
  /** The atomic attempt these units are reserved for, and this record's key. */
  readonly attemptId: Uint8Array;
  readonly holder: Uint8Array;
  /** The DEMANDED backing's obligor, signed by the holder in the lock. */
  readonly beneficiary: Uint8Array;
  readonly quantity: bigint;
  /** §C3's lock timeout: the witnessed index past which this attempt is over. */
  readonly timeout: bigint;
  /** The venue whose clock the timeout is read on, and where a commit must appear. */
  readonly decisionVenue: Uint8Array;
  /** The keys whose signatures on the commit convert this lock, the holder among them (C1: "all sign"). */
  readonly parties: readonly Uint8Array[];
  readonly nonce: bigint;
}

/**
 * §C3's lock predicate: "was a valid release witnessed **at or before** the lock
 * timeout?" At the timeout is inside; one past is not. Commit and release read
 * it, withdrawal reads its complement — three sites, one definition, so exactly
 * one exit is open at every index, as release and withdrawal are complements on
 * `acceptanceIsLive` for a demand. Creation asks a different question, that the
 * timeout be strictly ahead, and keeps its own inequality. Three hand-written
 * inequalities agreed until the withdrawal's was forgotten (24b, found in 24c).
 */
export function lockIsLive(lock: { readonly timeout: bigint }, atWitnessedIndex: bigint): boolean {
  return atWitnessedIndex <= lock.timeout;
}

export interface LedgerState {
  /** Units held, by holder key hex. A holder at zero is absent. */
  readonly balances: Map<string, bigint>;
  /** Open demands, by demand hash hex. Settlement and withdrawal remove them. */
  readonly demands: Map<string, DemandRecord>;
  /** Reliance legs reserved against a demand elsewhere, by demand hash hex. */
  readonly locks: Map<string, LockRecord>;
  /** The nonce each signer's next operation must carry, by signer key hex. */
  readonly nonces: Map<string, bigint>;
  issued: bigint;
  burned: bigint;
}

export function emptyState(): LedgerState {
  return {
    balances: new Map(),
    demands: new Map(),
    locks: new Map(),
    nonces: new Map(),
    issued: 0n,
    burned: 0n,
  };
}

/**
 * A state a caller can apply an entry to without disturbing the original —
 * "would this operation have been accepted here?" asked without answering it.
 * The demand records are copied because applyEntry replaces them wholesale on an
 * acceptance rather than mutating one, but a caller may still read them after.
 */
export function copyState(state: LedgerState): LedgerState {
  return {
    balances: new Map(state.balances),
    demands: new Map([...state.demands].map(([key, record]) => [key, copyDemand(record)])),
    locks: new Map([...state.locks].map(([key, record]) => [key, copyLock(record)])),
    nonces: new Map(state.nonces),
    issued: state.issued,
    burned: state.burned,
  };
}

function copyDemand(record: DemandRecord): DemandRecord {
  return { ...record, hash: copyBytes(record.hash), holder: copyBytes(record.holder) };
}

function copyLock(record: LockRecord): LockRecord {
  return {
    ...record,
    attemptId: copyBytes(record.attemptId),
    holder: copyBytes(record.holder),
    beneficiary: copyBytes(record.beneficiary),
    decisionVenue: copyBytes(record.decisionVenue),
    parties: record.parties.map(copyBytes),
  };
}

function heldBy(state: LedgerState, hex: string): bigint {
  return state.balances.get(hex) ?? 0n;
}

/**
 * Spendable units: held minus committed. §C3's commitment is enforced here —
 * claims under an open demand cannot leave by any ordinary path, so the holder
 * cannot present the same units and also spend them. Derived from the standing
 * demands rather than tracked beside them, so there is one source of truth.
 */
function spendable(state: LedgerState, key: Uint8Array): bigint {
  const hex = bytesToHex(key);
  let locked = 0n;
  for (const record of state.demands.values()) {
    if (compareBytes(record.holder, key) === 0) locked += record.quantity;
  }
  // A reliance leg committed to a demand elsewhere is spoken for exactly as a
  // demand's own units are: the whole point of the lock is that the holder
  // cannot present the set and spend its accompaniment.
  for (const record of state.locks.values()) {
    if (compareBytes(record.holder, key) === 0) locked += record.quantity;
  }
  return heldBy(state, hex) - locked;
}

function move(state: LedgerState, key: Uint8Array, delta: bigint): void {
  const hex = bytesToHex(key);
  const units = heldBy(state, hex) + delta;
  // Every caller checks first, but a mint-capable line must not rest on a
  // cross-method argument: refuse rather than persist a negative balance.
  if (units < 0n) throw new LedgerError("debit exceeds the holding");
  // Drop the entry at zero so a holder at zero is absent, in the ledger's book
  // and in a replay alike.
  if (units === 0n) state.balances.delete(hex);
  else state.balances.set(hex, units);
}

function standingDemand(state: LedgerState, hash: Uint8Array): DemandRecord {
  const record = state.demands.get(bytesToHex(hash));
  if (!record) throw new LedgerError("no such standing demand");
  return record;
}

/**
 * Who the law requires to have signed, from the terms and the operation alone —
 * or undefined where that is not enough. A release and a withdrawal name a
 * demand rather than a signer, so their signer is whoever filed that demand,
 * which is state.
 *
 * Exported because a fault proof needs the same rule (fault.ts): a caller who
 * could NAME the signer could choose who is at fault, so the signer is derived
 * by the law in both places, from one definition rather than two that agree
 * until they do not.
 */
export function signerFromTerms(backing: Backing, entry: PublishedOp): Uint8Array | undefined {
  switch (entry.kind) {
    case "issue":
    case "acceptance":
      return backing.obligor;
    case "transfer":
      return entry.from;
    case "burn":
    case "demand":
    case "lock":
      return entry.holder;
    case "release":
    case "withdrawal":
    // A commit's signer is the holder who locked, which is a record in state
    // rather than anything the terms name — signerOf reads it there.
    case "commit":
      return undefined;
  }
  // Exhaustive, and asserted rather than assumed: the return type admits
  // undefined, so a kind added to PublishedOp and forgotten here would compile
  // and then be refused at runtime for no visible reason. unknownOpKind makes
  // that a compile error at the place that has to decide — and refuses at
  // runtime rather than handing back the entry itself, which is what assigning
  // to a never-typed local and returning it did.
  return unknownOpKind(entry);
}

/**
 * Who the law requires to have signed, reading the state where it must. Only a
 * release and a withdrawal need it, and they are narrowed by kind rather than
 * cast: a cast would compile for an eighth operation kind that had no demand to
 * read, and `standingDemand` would then throw a TypeError where every caller of
 * applyEntry expects a LedgerError.
 */
function signerOf(state: LedgerState, backing: Backing, entry: PublishedOp): Uint8Array {
  if (entry.kind === "release" || entry.kind === "withdrawal") {
    // In this backing's own state one of the two exists, never both: a demand
    // where this IS the demanded backing, a lock where it is one of its legs.
    const lock = state.locks.get(bytesToHex(entry.demandHash));
    if (lock !== undefined) {
      // A withdrawal frees the locker's own units: the locker signs. A release
      // converts them to the party the lock names: that party signs — the
      // holder of a bundle or a leg (parties [holder]), the demand holder for a
      // backer's paying lock (§C3: "void only on the holder's release"). A lock
      // naming several parties converts only on the witnessed object, where every
      // signature is: one release is one signature, and "all sign" is the rule.
      if (entry.kind === "withdrawal") return copyBytes(lock.holder);
      if (lock.parties.length !== 1) {
        throw new LedgerError("a lock naming several parties settles only on the witnessed object");
      }
      return copyBytes(lock.parties[0] as Uint8Array);
    }
    return standingDemand(state, entry.demandHash).holder;
  }
  const fromTerms = signerFromTerms(backing, entry);
  if (fromTerms === undefined) throw new LedgerError("no signer for this operation");
  return fromTerms;
}

const SIGNATURE_REFUSAL: Record<PublishedOp["kind"], string> = {
  issue: "issuance signature invalid: only the obligor issues",
  transfer: "transfer signature invalid: only the holder moves a holding",
  burn: "burn signature invalid: only the holder burns a holding",
  demand: "demand signature invalid: only the holder presents a holding",
  acceptance: "acceptance signature invalid: only the obligor answers",
  release: "release signature invalid: only the holder releases",
  withdrawal: "withdrawal signature invalid: only the holder withdraws",
  lock: "lock signature invalid: only the holder reserves their own units",
  commit: "commit signature invalid: only the holder who locked may commit",
};

const ACCEPTANCE_WINDOW =
  "acceptance deadline must be no earlier than now and no later than the demand's deadline";

/**
 * Apply one operation to a state, or refuse it. **The law, in one place.**
 *
 * The ledger applies entries as they arrive; a verifier folds a served log
 * through this same function (replayLog). Written twice they drift, and they
 * did: the acceptance-deadline range and invariant 27's "settlement takes two
 * signatures" were each enforced on one side only, and each was found after it
 * had shipped. One function is what stops that.
 *
 * `clock` is the current witnessed index, or **undefined where there is none**.
 * The rules that read it are exactly the rules a served log cannot answer — the
 * log does not record the index each operation was accepted at — and they are
 * the only ones marked TIME below. Everything else holds either way, so a
 * replay is as strict as the ledger apart from a boundary that is visible in one
 * place.
 *
 * Atomic: every check runs before any mutation, so it either fully applies or
 * throws having changed nothing. Throws LedgerError, or NonceError for a nonce.
 */
export function applyEntry(
  state: LedgerState,
  backing: Backing,
  entry: PublishedOp,
  clock: bigint | undefined,
): void {
  // **The commit is signed by every party the LOCK names**, and carries no nonce.
  // One object has to be valid in every log of an exchange at once, and a nonce
  // is per (signer, backing) — so there is no single signer and no single value
  // it could carry. What a nonce buys is bought otherwise: a repeat is a no-op
  // because the lock it settles is gone, and it can only reach an attempt its
  // own parties named in a lock. See presentation.ts.
  if (entry.kind === "commit") {
    const lock = state.locks.get(bytesToHex(entry.attemptId));
    if (lock === undefined) throw new LedgerError("no lock on this backing for that attempt");
    if (!commitSatisfies(entry, lock.parties)) {
      throw new LedgerError("the commit is not signed by every party to this lock");
    }
  }
  const signer = entry.kind === "commit" ? undefined : signerOf(state, backing, entry);
  let expected: bigint | undefined;
  if (entry.kind !== "commit" && signer !== undefined) {
    const signerHex = bytesToHex(signer);
    expected = state.nonces.get(signerHex) ?? 0n;
    if (entry.nonce !== expected) {
      throw new NonceError(
        entry.nonce < expected
          ? "nonce already spent on a different operation"
          : "nonce is ahead of the signer's next",
      );
    }
  }
  // The canonical bytes throw EncodingError on a malformed field — a quantity
  // out of range is the encoder's refusal, not the law's. A valid signature
  // over them also proves the signer key is a valid non-small-order point,
  // since verification is strict, so no separate key check is needed for a
  // signer. Keys that sign nothing still need one.
  const message = opMessageOfEntry(backing.name, entry);
  if (signer !== undefined && entry.kind !== "commit" && !verifySignatureStrict(entry.signature, message, signer)) {
    throw new LedgerError(SIGNATURE_REFUSAL[entry.kind]);
  }

  switch (entry.kind) {
    case "issue": {
      if (!isValidPublicKey(entry.recipient)) {
        throw new LedgerError("recipient key is not a valid Ed25519 point");
      }
      if (state.issued + entry.quantity >= MAX_QUANTITY_EXCLUSIVE) {
        throw new LedgerError("issuance would push outstanding beyond the quantity bound");
      }
      if (heldBy(state, bytesToHex(entry.recipient)) + entry.quantity >= MAX_QUANTITY_EXCLUSIVE) {
        throw new LedgerError("issuance would push a balance beyond the quantity bound");
      }
      move(state, entry.recipient, entry.quantity);
      state.issued += entry.quantity;
      break;
    }
    case "transfer": {
      if (!isValidPublicKey(entry.to)) {
        throw new LedgerError("to key is not a valid Ed25519 point");
      }
      if (spendable(state, entry.from) < entry.quantity) {
        throw new LedgerError("insufficient balance");
      }
      if (heldBy(state, bytesToHex(entry.to)) + entry.quantity >= MAX_QUANTITY_EXCLUSIVE) {
        throw new LedgerError("transfer would push a balance beyond the quantity bound");
      }
      move(state, entry.from, -entry.quantity);
      move(state, entry.to, entry.quantity);
      break;
    }
    case "burn": {
      if (spendable(state, entry.holder) < entry.quantity) {
        throw new LedgerError("insufficient balance");
      }
      move(state, entry.holder, -entry.quantity);
      state.burned += entry.quantity;
      break;
    }
    case "demand": {
      // The legs are NOT checked here, and cannot be: invariant 13 asks for q·cᵢ
      // units of each target, and those live in other backings' states which
      // this function cannot see. Each leg is reserved by a lock in its own log,
      // and the sequencer takes the demand and every lock as one set or none —
      // §C3's "one atomically signed decision".
      // TIME. Invariant 24: the instant is "no later than the latest witnessed
      // index at signing", so a payout is never evaluated at an index nobody has
      // witnessed. The acceptance repeats this exact value, which carries the
      // same guarantee into the backer's signature.
      if (clock !== undefined && entry.instant > clock) {
        throw new LedgerError("demand instant is later than the latest witnessed index");
      }
      if (spendable(state, entry.holder) < entry.quantity) {
        throw new LedgerError("insufficient balance");
      }
      const hash = sha256(message);
      // The other door of the same rule: the hash is the demand's alone here.
      if (state.locks.has(bytesToHex(hash))) {
        throw new LedgerError("a lock already stands under this demand's hash on this backing");
      }
      state.demands.set(bytesToHex(hash), {
        hash,
        holder: copyBytes(entry.holder),
        quantity: entry.quantity,
        instant: entry.instant,
        deadline: entry.deadline,
        nonce: entry.nonce,
        acceptedDeadline: undefined,
      });
      break;
    }
    case "lock": {
      // §C3's prepare, for a leg: reserve without consuming. It says nothing
      // about the demand it names, because the demand is another backing's
      // record — what makes the pair coherent is that one operator applies both
      // or neither, and a verifier holding the served state can read both.
      if (state.locks.has(bytesToHex(entry.attemptId))) {
        throw new LedgerError("this attempt already has a lock on this backing");
      }
      // A lock and a demand never share a hash on one backing. signerOf resolves
      // a release or withdrawal lock-first, so a stranger's one-unit lock under a
      // standing demand's hash would hijack the head's own exits (found reviewing
      // 24c). Legs live on OTHER backings; on the demanded one the hash is the
      // demand's alone.
      if (state.demands.has(bytesToHex(entry.attemptId))) {
        throw new LedgerError("a lock may not name a standing demand's hash on the demanded backing");
      }
      if (spendable(state, entry.holder) < entry.quantity) {
        throw new LedgerError("insufficient balance");
      }
      // TIME. A lock whose timeout has already passed is an attempt that is over
      // before it starts, and would reserve units nothing could ever settle.
      if (clock !== undefined && entry.timeout <= clock) {
        throw new LedgerError("lock timeout is not ahead of the witnessed index");
      }
      state.locks.set(bytesToHex(entry.attemptId), {
        attemptId: copyBytes(entry.attemptId),
        holder: copyBytes(entry.holder),
        beneficiary: copyBytes(entry.beneficiary),
        quantity: entry.quantity,
        timeout: entry.timeout,
        decisionVenue: copyBytes(entry.decisionVenue),
        parties: entry.parties.map(copyBytes),
        nonce: entry.nonce,
      });
      break;
    }
    case "commit": {
      // §C3's commit, applied to this backing's own half of an attempt. The
      // lock is guaranteed to exist: signerOf refused already if it did not.
      const lock = state.locks.get(bytesToHex(entry.attemptId)) as LockRecord;
      // TIME, and the predicate every sequencer in the bundle evaluates against
      // the same object: "was a valid release witnessed at or before the lock
      // timeout?" The clock passed here is the index the VENUE witnessed the
      // commit at, never the index this operator happens to be applying it —
      // which is the rule adoption already follows for a gap publication.
      if (clock !== undefined && !lockIsLive(lock, clock)) {
        throw new LedgerError("the commit was witnessed past the lock timeout");
      }
      if (heldBy(state, bytesToHex(lock.beneficiary)) + lock.quantity >= MAX_QUANTITY_EXCLUSIVE) {
        throw new LedgerError("settlement would push a balance beyond the quantity bound");
      }
      if (heldBy(state, bytesToHex(lock.holder)) < lock.quantity) {
        throw new LedgerError("debit exceeds the holding");
      }
      // Drop the lock first, for the reason a demand is dropped first: the
      // settling transfer must not be blocked by its own reservation.
      state.locks.delete(bytesToHex(entry.attemptId));
      move(state, lock.holder, -lock.quantity);
      move(state, lock.beneficiary, lock.quantity);
      break;
    }
    case "acceptance": {
      const record = standingDemand(state, entry.demandHash);
      // TIME. An answer must be live when signed.
      if (clock !== undefined && entry.deadline < clock) throw new LedgerError(ACCEPTANCE_WINDOW);
      // And it may not outlast the window the holder chose: "The window is the
      // holder's... A backer would be setting the standard by which its own
      // failure is measured." Past the demand's deadline no legal acceptance
      // deadline is left, so a holder who has earned the right to walk away
      // cannot have it taken back.
      if (entry.deadline > record.deadline) throw new LedgerError(ACCEPTANCE_WINDOW);
      // TIME. A live answer already stands; once it expires the backer may
      // answer again, bounded by the demand's own deadline.
      if (clock !== undefined && acceptanceIsLive(record, clock)) {
        throw new LedgerError("a live acceptance already stands");
      }
      if (entry.instant !== record.instant) {
        throw new LedgerError("acceptance does not agree the demand's instant");
      }
      state.demands.set(bytesToHex(record.hash), { ...record, acceptedDeadline: entry.deadline });
      break;
    }
    case "release": {
      // **On a leg, the same act with a different record.** §C3 settles the
      // whole set on one release, so each backing in it resolves its own part:
      // the demanded backing moves the claims, each leg moves the accompaniment
      // to the beneficiary the holder signed into the lock.
      //
      // A leg cannot check the acceptance — that record is in the demanded
      // backing's state — so the pairing is the sequencer's to apply atomically
      // and a verifier's to read across the served state. What the leg does
      // enforce is the whole of what its own units need: the holder signed this
      // release, and the beneficiary was fixed when the units were committed.
      const leg = state.locks.get(bytesToHex(entry.demandHash));
      if (leg !== undefined) {
        // TIME, and the whole of §C3's abort: "every sequencer evaluates one
        // predicate against the same object: was a valid release witnessed at
        // or before the lock timeout?" At the timeout is inside; one past is
        // not. Past it the set can no longer settle, so the only exit left is
        // withdrawal — which needs nobody's cooperation, and is what "expired
        // locks unlock unilaterally" comes to here.
        //
        // A refusal and never a balance, which is what keeps a replay exact: the
        // clock is undefined on a replay, so a lock that freed its own units on
        // expiry would make an operator's correct history unreplayable.
        if (clock !== undefined && !lockIsLive(leg, clock)) {
          throw new LedgerError("the lock timeout has passed: the set can no longer settle on this lock");
        }
        if (heldBy(state, bytesToHex(leg.beneficiary)) + leg.quantity >= MAX_QUANTITY_EXCLUSIVE) {
          throw new LedgerError("settlement would push a balance beyond the quantity bound");
        }
        if (heldBy(state, bytesToHex(leg.holder)) < leg.quantity) {
          throw new LedgerError("debit exceeds the holding");
        }
        // Drop the lock first, for the reason the demand is dropped first: the
        // settling transfer must not be blocked by its own reservation.
        state.locks.delete(bytesToHex(entry.demandHash));
        move(state, leg.holder, -leg.quantity);
        move(state, leg.beneficiary, leg.quantity);
        break;
      }
      const record = standingDemand(state, entry.demandHash);
      // Invariant 27: settlement takes two signatures, the backer's acceptance
      // and the holder's release. Never answered, and answered-then-expired,
      // are one refusal: no answer is on the table, and the holder's exit in
      // both cases is withdrawal rather than settling on terms that have moved.
      // Only the second half needs a clock.
      if (record.acceptedDeadline === undefined) {
        throw new LedgerError("no live acceptance to release against");
      }
      // TIME.
      if (clock !== undefined && !acceptanceIsLive(record, clock)) {
        throw new LedgerError("no live acceptance to release against");
      }
      const backer = backing.obligor;
      if (heldBy(state, bytesToHex(backer)) + record.quantity >= MAX_QUANTITY_EXCLUSIVE) {
        throw new LedgerError("settlement would push a balance beyond the quantity bound");
      }
      if (heldBy(state, bytesToHex(record.holder)) < record.quantity) {
        throw new LedgerError("debit exceeds the holding");
      }
      // Drop the demand first so the settling transfer is not blocked by its own
      // lock, then move exactly the quantity offered. Presentation destroys
      // nothing (invariant 10), so this is a transfer, not a burn.
      state.demands.delete(bytesToHex(record.hash));
      move(state, record.holder, -record.quantity);
      move(state, backer, record.quantity);
      break;
    }
    case "withdrawal": {
      // The other exit, on a leg, and the complement of the commit on one
      // predicate: §C3's "**expired** locks unlock unilaterally". TIME, a refusal
      // and never a balance, like every rule here. Why a live lock cannot be
      // taken back, and why the far side needs the sequencer too: 24c in
      // DECISIONS.md.
      const leg = state.locks.get(bytesToHex(entry.demandHash));
      if (leg !== undefined) {
        if (clock !== undefined && lockIsLive(leg, clock)) {
          throw new LedgerError("the lock has not expired: the attempt settles or times out");
        }
        state.locks.delete(bytesToHex(entry.demandHash));
        break;
      }
      const record = standingDemand(state, entry.demandHash);
      // TIME. A live acceptance holds the claims: the holder has an answer to
      // release against. Once it expires they are the holder's again, or a
      // single free signature from the backer would sterilise them.
      if (clock !== undefined && acceptanceIsLive(record, clock)) {
        throw new LedgerError("a live acceptance stands: release it or wait for it to expire");
      }
      state.demands.delete(bytesToHex(record.hash));
      break;
    }
  }
  // Advanced for every kind that consumed one, which is every kind but the
  // commit — see above for the one reason it has none.
  if (expected !== undefined && signer !== undefined) state.nonces.set(bytesToHex(signer), expected + 1n);
}

/**
 * Fold a served operation log into the state it leaves, or undefined if it is
 * not a history that could have happened — an unsigned or twice-used signature,
 * a settlement of a demand that was not standing or never answered, a spend of
 * units an open demand has committed.
 *
 * A verifier, so it never throws: the log comes from an operator with a motive.
 * It applies the law with no clock, which is the one place a replay is weaker
 * than the ledger, and applyEntry marks exactly where.
 */
export function replayLog(
  backing: Backing,
  entries: readonly OpLogEntry[],
): LedgerState | undefined {
  const state = emptyState();
  try {
    for (const entry of entries) applyEntry(state, backing, entry, undefined);
  } catch {
    return undefined;
  }
  return state;
}

interface BackingState {
  readonly backing: Backing;
  readonly state: LedgerState;
  readonly opLog: OpLogEntry[];
}

export class TransparentLedger {
  private readonly states = new Map<string, BackingState>();

  /**
   * A backing enters the ledger only with a valid signature by its obligor
   * over its own name (invariant 2). Re-registering the same backing is a
   * no-op: by invariant 1, same name means same terms.
   */
  register(backing: Backing, signature: Uint8Array): void {
    if (!verifyBackingSignature(backing, signature)) {
      throw new LedgerError("backing signature invalid");
    }
    if (this.states.has(backing.nameHex)) return;
    // Store the ledger's OWN copy. Object.freeze does not freeze the bytes
    // inside a Uint8Array, and issuance reads authority from the registered
    // obligor — so keeping the caller's object would leave a live write path
    // to the key that authorises issuance. makeBacking re-copies every field
    // and yields the same name (invariant 1).
    this.states.set(backing.nameHex, {
      backing: makeBacking(backing),
      state: emptyState(),
      opLog: [],
    });
  }

  /**
   * Every backing's state, serialized for a verifier (invariant 23) — which is
   * its log, since everything else is a fold over it. The ledger owns its state,
   * so it owns the serialization: no Backing object leaves, so no caller can
   * reach the obligor key that authorises issuance.
   */
  snapshotAll(): BackingSnapshot[] {
    return [...this.states.values()].map((state) => ({
      name: copyBytes(state.backing.name),
      opLog: state.opLog.map(copyOpEntry),
    }));
  }

  has(backing: Backing): boolean {
    return this.states.has(backing.nameHex);
  }

  /**
   * Apply one signed operation under the law and log it, at the witnessed index
   * it is judged against (undefined where no rule reads one). **The one door**:
   * the named methods below are adapters onto it, and §C2b's adoption of an
   * operation published at the venue comes through it too, carrying the index
   * the venue stamped that publication with.
   *
   * Public without weakening invariant 8: a caller may name any operation it
   * likes, and applyEntry still demands the signature of the party the law
   * names. What that invariant forbids is a path that moves claims WITHOUT one.
   */
  apply(backing: Backing, op: PublishedOp, atWitnessedIndex: bigint | undefined): OpLogEntry {
    const held = this.stateOf(backing);
    const entry = { ...copyOp(op), position: held.opLog.length };
    applyEntry(held.state, held.backing, entry, atWitnessedIndex);
    held.opLog.push(entry);
    return copyOpEntry(entry);
  }

  /**
   * Apply a set of operations across several backings, **all or nothing**.
   *
   * §C3's single-phase presentation is "one atomically signed decision": a
   * demand and the locks on its reliance legs are one act, and applying part of
   * it would leave a demand whose accompaniment is not committed, or units
   * reserved for a demand that was refused. The ledger is atomic per operation
   * by design; this is the second place after takeOver that applies many, and
   * for the same reason it establishes the whole set first.
   *
   * Established on copies, then applied for real. Each backing appears at most
   * once — a backing cannot be its own reliance target, since its name is a hash
   * over R — so no entry in the set can invalidate another's dry run.
   */
  applyAll(
    ops: readonly { readonly backing: Backing; readonly op: PublishedOp }[],
    atWitnessedIndex: bigint | undefined,
  ): OpLogEntry[] {
    for (const { backing, op } of ops) {
      const held = this.stateOf(backing);
      applyEntry(copyState(held.state), held.backing, op, atWitnessedIndex);
    }
    return ops.map(({ backing, op }) => this.apply(backing, op, atWitnessedIndex));
  }

  /** Issuance: backer-signed, raises issued and the recipient's balance. */
  issue(op: IssuanceOp, signature: Uint8Array): OpLogEntry {
    const { recipient, quantity, nonce } = op;
    return this.apply(op.backing, { kind: "issue", recipient, quantity, nonce, signature }, undefined);
  }

  /** Transfer: holder-signed, moves units, touches no total. */
  transfer(op: TransferOp, signature: Uint8Array): OpLogEntry {
    const { from, to, quantity, nonce } = op;
    return this.apply(op.backing, { kind: "transfer", from, to, quantity, nonce, signature }, undefined);
  }

  /** Burn: holder-signed, the only operation that lowers outstanding. */
  burn(op: BurnOp, signature: Uint8Array): OpLogEntry {
    const { holder, quantity, nonce } = op;
    return this.apply(op.backing, { kind: "burn", holder, quantity, nonce, signature }, undefined);
  }

  /**
   * Present claims for payment (§C3). The demand commits the quantity: it can
   * no longer be transferred or burned, but it is not surrendered — settlement
   * needs the backer's acceptance and the holder's own release.
   */
  demand(op: DemandOp, signature: Uint8Array, atWitnessedIndex: bigint): OpLogEntry {
    const { holder, quantity, instant, deadline, nonce } = op;
    const entry = { kind: "demand", holder, quantity, instant, deadline, nonce, signature } as const;
    return this.apply(op.backing, entry, atWitnessedIndex);
  }

  /**
   * Answer a demand (§C3). Backer-signed, and it must agree the demand's own
   * evaluation instant — two signatures over one value (invariant 24). It
   * carries its own deadline, or the backer would hold a free option: accept,
   * keep the claims committed, and wait for the payout to move.
   */
  accept(op: AcceptanceOp, signature: Uint8Array, atWitnessedIndex: bigint): OpLogEntry {
    const { demandHash, instant, deadline, nonce } = op;
    const entry = { kind: "acceptance", demandHash, instant, deadline, nonce, signature } as const;
    return this.apply(op.backing, entry, atWitnessedIndex);
  }

  /**
   * Settle an accepted demand (invariant 27). Takes two signatures: the
   * backer's acceptance, already logged, and the holder's release here. A
   * backer must never void unilaterally, or non-payment would be recorded as
   * settlement.
   */
  release(op: ReleaseOp, signature: Uint8Array, atWitnessedIndex: bigint): OpLogEntry {
    const { demandHash, nonce } = op;
    const entry = { kind: "release", demandHash, nonce, signature } as const;
    return this.apply(op.backing, entry, atWitnessedIndex);
  }

  /**
   * End a demand no live acceptance answers (§C3). Unilateral and
   * holder-signed: the protection against a backer that stalls, which it cannot
   * wait out.
   */
  withdraw(op: WithdrawalOp, signature: Uint8Array, atWitnessedIndex: bigint): OpLogEntry {
    const { demandHash, nonce } = op;
    const entry = { kind: "withdrawal", demandHash, nonce, signature } as const;
    return this.apply(op.backing, entry, atWitnessedIndex);
  }

  /**
   * Whether this backing holds a reliance lock against that demand — that is,
   * whether it is a LEG of the demand rather than the backing demanded.
   *
   * The law cannot tell the two apart: a release names a demand hash, and this
   * state resolves whichever record it has for it. Which backing heads a set is
   * the shape of the set, and that is the sequencer's to know.
   */
  hasLock(backing: Backing, attemptId: Uint8Array): boolean {
    return this.stateOf(backing).state.locks.has(bytesToHex(attemptId));
  }

  /** The standing demand record (invariant 23), as copies. */
  openDemands(backing: Backing): DemandRecord[] {
    return [...this.stateOf(backing).state.demands.values()].map(copyDemand);
  }

  /** One standing demand, as a copy, or undefined if none stands under that hash. */
  demandOf(backing: Backing, hash: Uint8Array): DemandRecord | undefined {
    const record = this.stateOf(backing).state.demands.get(bytesToHex(hash));
    return record === undefined ? undefined : copyDemand(record);
  }

  /** One standing lock, as a copy, or undefined if none stands under that attempt. */
  lockOf(backing: Backing, attemptId: Uint8Array): LockRecord | undefined {
    const record = this.stateOf(backing).state.locks.get(bytesToHex(attemptId));
    return record === undefined ? undefined : copyLock(record);
  }

  /** Units this holder can still spend: held minus committed by open demands. */
  availableBalance(backing: Backing, holder: Uint8Array): bigint {
    return spendable(this.stateOf(backing).state, holder);
  }

  issued(backing: Backing): bigint {
    return this.stateOf(backing).state.issued;
  }

  burned(backing: Backing): bigint {
    return this.stateOf(backing).state.burned;
  }

  outstanding(backing: Backing): bigint {
    const { state } = this.stateOf(backing);
    return state.issued - state.burned;
  }

  balance(backing: Backing, holder: Uint8Array): bigint {
    return heldBy(this.stateOf(backing).state, bytesToHex(holder));
  }

  /** A copy of current holders and balances (spent-to-zero holders are absent). */
  balancesOf(backing: Backing): Map<string, bigint> {
    return new Map(this.stateOf(backing).state.balances);
  }

  /** A copy of the full operation log, all seven kinds. */
  opLog(backing: Backing): OpLogEntry[] {
    return this.stateOf(backing).opLog.map(copyOpEntry);
  }

  /** The nonce this signer's next operation on this backing must carry. */
  nextNonce(signer: Uint8Array, backing: Backing): bigint {
    return this.stateOf(backing).state.nonces.get(bytesToHex(signer)) ?? 0n;
  }

  /**
   * A holder's view of their own holdings, keyed by backing name — the shape
   * presentability (invariant 13) reads. Unknown backings hold zero.
   */
  holdingView(holder: Uint8Array): (name: Uint8Array) => bigint {
    const holderHex = bytesToHex(holder);
    return (name: Uint8Array) =>
      this.states.get(bytesToHex(name))?.state.balances.get(holderHex) ?? 0n;
  }

  private stateOf(backing: Backing): BackingState {
    const held = this.states.get(backing.nameHex);
    if (!held) throw new LedgerError("backing not registered");
    return held;
  }
}
