// What can be proven, against whom, on one screen.
//
// The system's posture everywhere is that misbehaviour is made **provable**
// rather than prevented. Invariant 22 makes two roots signed at one sequence an
// operator's provable fault (`isEquivocation`, commitment.ts). §C2b grades
// silence on facts a stranger checks against the published record. §C3 makes
// dishonour "publicly checkable... with nobody reporting anything". Nothing here
// stops a party misbehaving; it makes the misbehaviour undeniable afterwards,
// and §15 prices the key's history accordingly.
//
// That posture had one gap: it covered the operator and never the holder.
//
// §C2b's challenge window is where the gap bites. A claimant who signed her
// holding away and then redeems the last witnessed snapshot has signed **two
// operations at one point in her own nonce sequence**, and the protocol cannot
// tell which of them her dark operator accepted — the evidence for that went
// dark with it. So it cannot always pay the right party. What it can always do
// is name the fault, and these are the predicates that do it:
//
//   - `equivocatingSigner` — one key authorised two operations at one nonce.
//     The holder's fault, and the one that was missing.
//   - `isDoubleAcceptance` — an operator co-signed both halves of that. Under
//     §C2's backer-run default the operator key is the backer's, so this names
//     the party that owes the money.
//   - `isDoublePosition` — an operator co-signed two operations into one log
//     position, so one of its receipts is a lie about its own log.
//   - `isRewrittenHistory` — an operator committed a log that takes back one it
//     had already committed. An append-only log may grow and may not shrink, and
//     no committed entry may change. This is what restoring from stale data and
//     carrying on produces, and it is the fault ACROSS sequences where
//     isEquivocation is the fault at one.
//
// A fourth reading lives beside the receipt rather than here, because most of
// its answers are ordinary rather than faults: `receiptStatus` (receipt.ts)
// tells a payee whether a committed log holds their operation, has not reached
// it yet, holds something else, or carries nothing for the backing at all. Only
// "holds something else" is this file's business; naming it again there would be
// a second name for one thing.
//
// The two operator faults also catch a **botched failover**: two live servers
// holding one operator key, with no leader election between them, produce
// exactly these artefacts. The protocol cannot distinguish that from malice and
// does not try, which is the same standard it already applies to a self-framing
// commitment equivocation — see CLAUDE.md on the one-writer obligation, and on
// why a threshold construction prevents this rather than merely recording it.
//
// **The signer is derived, never asserted.** A caller who could name the signer
// could choose who is at fault, so the signer comes from the law's own rule
// (`signerFromTerms`, ledger.ts) and the signature has to verify under it. The
// price is that a release or a withdrawal cannot be proved by this pair alone:
// the law reads their signer from the demand they name, which is not in the
// operation. They need that demand too, which is a different function's job.
//
// Verifiers, all of them: the bytes come from whoever is exhibiting them, so
// anything malformed is a fault that is not proven rather than a throw.

import { type Backing } from "./backing.js";
import { compareBytes, copyBytes } from "./bytes.js";
import { verifySignatureStrict } from "./keys.js";
import { signerFromTerms } from "./ledger.js";
import { opMessageOfEntry, type PublishedOp } from "./oplog.js";
import { committedLogFor, type ServedState } from "./commitment.js";
import { receiptCovers, isOperatorReceipt, type Receipt } from "./receipt.js";
import { successionOf, type Succession } from "./replacement.js";
import type { Venue } from "./venue.js";

/** An operation and the operator co-signature that accepted it. */
export interface AcceptedOp {
  readonly op: PublishedOp;
  readonly receipt: Receipt;
}

/**
 * The key proved to have authorised two operations at one point in its own
 * nonce sequence, or undefined if these two do not prove it.
 *
 * A nonce is per (signer, backing) and the law consumes exactly one per
 * operation, so two different operations validly signed by one key at one nonce
 * is a history that cannot exist. Only one of them can ever have been applied,
 * and the signer knew that when it signed the second.
 *
 * It returns the key rather than a boolean because the key is the point: it is
 * derived here, so the caller does not otherwise have it, and naming the party
 * is what the proof is for.
 *
 * Not a fault: the identical operation twice. Invariant 26 exists so that a
 * repeat is safe, so equivocation is two DIFFERENT operations, never one sent
 * twice — which is why the canonical messages are compared rather than the
 * objects.
 */
export function equivocatingSigner(
  backing: Backing,
  a: PublishedOp,
  b: PublishedOp,
): Uint8Array | undefined {
  try {
    if (a.nonce !== b.nonce) return undefined;
    const signer = signerFromTerms(backing, a);
    if (signer === undefined) return undefined;
    if (compareBytes(signer, signerFromTerms(backing, b) ?? new Uint8Array(0)) !== 0) {
      return undefined;
    }
    const messageA = opMessageOfEntry(backing.name, a);
    const messageB = opMessageOfEntry(backing.name, b);
    if (compareBytes(messageA, messageB) === 0) return undefined;
    if (!verifySignatureStrict(a.signature, messageA, signer)) return undefined;
    if (!verifySignatureStrict(b.signature, messageB, signer)) return undefined;
    return copyBytes(signer);
  } catch {
    return undefined;
  }
}

/**
 * Whether one operator co-signed both halves of a signer's equivocation: two
 * operations that one nonce cannot hold, each carrying that operator's receipt.
 *
 * An honest operator refuses the second — "it co-signs, and refuses a second
 * spend by declining to sign" (§C2) — so accepting both is its own fault
 * whatever its reason, and the reasons are collusion with the claimant, or two
 * of its own servers running without a leader.
 *
 * A boolean, where `equivocatingSigner` returns a key: the operator at fault is
 * already in the receipts the caller passed in, so there is nothing to hand back
 * that it does not have.
 */
export function isDoubleAcceptance(
  backing: Backing,
  venue: Venue,
  a: AcceptedOp,
  b: AcceptedOp,
): boolean {
  try {
    if (equivocatingSigner(backing, a.op, b.op) === undefined) return false;
    // Both halves by ONE operator, and one that served this backing. Two
    // different operators of the chain accepting one nonce each is the handover
    // going wrong rather than either of them equivocating, and naming one of
    // them for it would be naming the wrong party.
    if (compareBytes(a.receipt.operator, b.receipt.operator) !== 0) return false;
    if (!isOperatorReceipt(backing, venue, a.receipt)) return false;
    if (!isOperatorReceipt(backing, venue, b.receipt)) return false;
    // Each receipt has to cover the operation it is exhibited with, ON THIS
    // BACKING, or an accuser pins any operator's signature to any operation it
    // likes — including a receipt the operator issued perfectly correctly
    // somewhere else, since one operator serves many backings and an operation
    // object carries no backing name.
    return (
      receiptCovers(backing.name, a.op, a.receipt) &&
      receiptCovers(backing.name, b.op, b.receipt)
    );
  } catch {
    return false;
  }
}

/**
 * Whether one operator co-signed two different operations into one position of
 * one backing's log. Positions are the log's own append indices, so a position
 * holds one operation and one of these receipts misdescribes the operator's own
 * log — which is what a receipt is for ("witnessed order: a receipt binds an
 * operation to its committed position", §C2).
 *
 * Needs no operations at all: the receipts alone carry backing, position and
 * operation hash, and the operator signed over all three. The backing is passed
 * so that the claim is about THIS backing's declared operator rather than about
 * whichever key the receipts happen to name.
 */
export function isDoublePosition(
  backing: Backing,
  venue: Venue,
  a: Receipt,
  b: Receipt,
): boolean {
  try {
    return (
      compareBytes(a.operator, b.operator) === 0 &&
      isOperatorReceipt(backing, venue, a) &&
      isOperatorReceipt(backing, venue, b) &&
      a.position === b.position &&
      compareBytes(a.opHash, b.opHash) !== 0
    );
  } catch {
    return false;
  }
}

/**
 * Whether one operator committed a history that takes back a history it had
 * already committed. An operation log is append-only, so a later commitment must
 * have the earlier one's log as a **prefix**: it may grow and it may not shrink,
 * and no entry already committed may change.
 *
 * This is the artefact an operator produces by restoring from stale data and
 * carrying on — it commits an old log at a new sequence, so the log shrinks —
 * and equally the artefact of a quiet rewrite, where the log grows but an
 * earlier entry is not what it was. Neither is reachable by isEquivocation,
 * which is two roots at ONE sequence; this is the fault across sequences.
 *
 * **Which state came first is derived, never taken from the argument order.** A
 * caller who could label them could choose which log is the rewrite, so the two
 * arguments are symmetric. Within one operator that order is its own commitment
 * sequence; across a handover it is the chain, because a sequence is an
 * operator's own count and says nothing about anyone else's. Two states at one
 * sequence of one operator answer false: that is isEquivocation's fault, and
 * naming it twice would let one artefact be reported as two.
 *
 * **It reaches across a handover, and has to.** §C2 gives a successor force only
 * over a state "it serves in full", so a successor committing a shorter log than
 * the predecessor's is the same fault by the party the chain just handed the
 * backing to. Restricting this to one operator's own history would have made
 * exactly the handover unwatched.
 *
 * Compared by canonical message rather than by object, because the message is
 * what the commitment commits to — the signature beside an entry is served, not
 * committed (oplog.ts).
 */
/**
 * Whether this operator was still in force for the backing when it committed the
 * state at `sequence` — the question that decides whether dropping the backing
 * was a fault or obedience.
 *
 * **It must be stable forever, and asking who is in force NOW is not.** A fault
 * a stranger can check today and not tomorrow is no fault proof at all: the
 * remedy for a dropped backing IS replacement, so reading the current operator
 * would erase the proof at the exact moment the holder used it, and let an
 * operator launder its record by arranging its own succession (§15 prices a
 * key's history, so that is worth something).
 *
 * So it is answered from the venue's own record, both halves of which are fixed
 * once witnessed. A commitment carries no venue index — a sequence is the
 * operator's own count (slice 13) — but the venue refuses a sequence that does
 * not extend, so **publication order is sequence order**, and the last
 * commitment this operator got witnessed before its successor took force pins
 * the boundary. At or below that sequence is before the handover.
 *
 * A state never published at all cannot manufacture an accusation either: its
 * sequence is above that boundary, or it collides with a published one, and a
 * collision is isEquivocation's to name.
 *
 * **One case it deliberately misses, and it misses it safely.** A key can appear
 * in the chain twice — the rule-holder may re-appoint a former operator, and only
 * succeeding ITSELF is refused — and this reads that key's first term only. A
 * drop during a second term therefore answers false. That is the direction this
 * file always takes when it cannot tell: say nothing rather than accuse. Closing
 * it means per-term sequence windows, which is a lot of arithmetic for a case
 * that costs a missed fault rather than a wrong one. See DECISIONS.md.
 */
function droppedWhileInForce(
  chain: readonly Succession[],
  venue: Venue,
  operator: Uint8Array,
  sequence: bigint,
): boolean {
  const link = chain.findIndex((step) => compareBytes(step.operator, operator) === 0);
  if (link < 0) return false;
  const successor = chain[link + 1];
  // Nobody after it in the chain, so it is in force and has no excuse.
  if (successor === undefined) return true;
  const before = venue.latestFor(operator, successor.from - 1n);
  return before !== undefined && sequence <= before.sequence;
}

export function isRewrittenHistory(
  backing: Backing,
  venue: Venue,
  a: ServedState,
  b: ServedState,
): boolean {
  try {
    const first = committedLogFor(backing, venue, a);
    const second = committedLogFor(backing, venue, b);
    if (first === undefined || second === undefined) return false;

    const chain = successionOf(backing, venue);
    const rank = (operator: Uint8Array) =>
      chain.findIndex((link) => compareBytes(link.operator, operator) === 0);
    const rankA = rank(a.commitment.operator);
    const rankB = rank(b.commitment.operator);
    if (rankA < 0 || rankB < 0) return false;

    if (rankA === rankB && first.sequence === second.sequence) return false;
    const secondIsEarlier =
      rankA !== rankB ? rankB < rankA : second.sequence < first.sequence;
    const earlier = secondIsEarlier ? second : first;
    const later = secondIsEarlier ? first : second;
    // Kept in step with the swap, because whether a DROP is a fault turns on who
    // signed it. A log comparison does not care.
    const laterOperator = secondIsEarlier ? a.commitment.operator : b.commitment.operator;

    // **A backing that vanishes is a log that shrank to nothing**, so it is this
    // fault rather than a second one beside it. The other direction is not: an
    // operator that had not yet registered the backing committed states without
    // it, and growing from nothing is growth. Both states dropping it says only
    // that neither ever carried it here.
    if (later.kind === "dropped") {
      if (earlier.kind !== "log") return false;
      // **But only an operator still in force has no excuse for dropping it.**
      // §C2: "From the effective index the old attester's co-signatures stop
      // counting" — a replaced operator is SUPPOSED to stop carrying the
      // backing, and it goes on serving its other ones, so its later commitments
      // drop this one as a matter of obedience. Naming that a fault accuses a
      // retired party for doing what the handover told it to, which is the shape
      // slice 9 found twice and slice 14 once more.
      return droppedWhileInForce(chain, venue, laterOperator, later.sequence);
    }
    if (earlier.kind === "dropped") return false;
    if (later.opLog.length < earlier.opLog.length) return true;
    for (let i = 0; i < earlier.opLog.length; i++) {
      const before = opMessageOfEntry(backing.name, earlier.opLog[i] as PublishedOp);
      const after = opMessageOfEntry(backing.name, later.opLog[i] as PublishedOp);
      if (compareBytes(before, after) !== 0) return true;
    }
    return false;
  } catch {
    return false;
  }
}
