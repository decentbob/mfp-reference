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
import { receiptCovers, verifyReceipt, type Receipt } from "./receipt.js";

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
export function isDoubleAcceptance(backing: Backing, a: AcceptedOp, b: AcceptedOp): boolean {
  try {
    if (equivocatingSigner(backing, a.op, b.op) === undefined) return false;
    if (!isTheOperator(backing, a.receipt)) return false;
    if (!isTheOperator(backing, b.receipt)) return false;
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
export function isDoublePosition(backing: Backing, a: Receipt, b: Receipt): boolean {
  try {
    return (
      isTheOperator(backing, a) &&
      isTheOperator(backing, b) &&
      a.position === b.position &&
      compareBytes(a.opHash, b.opHash) !== 0
    );
  } catch {
    return false;
  }
}

/**
 * Whether this receipt is a valid co-signature by the key **E names as this
 * backing's operator**, over this backing.
 *
 * Both halves matter and neither is enough. Without the backing name, a receipt
 * the operator issued perfectly correctly on another backing covers an
 * operation here, since an operation carries no name of its own. Without the
 * operator key, a stranger signs both halves of somebody's real equivocation
 * and it reads as a fault by the operator of this backing — which is what a
 * caller takes these predicates to mean, and under §C2's backer-run default
 * names the party that owes the money.
 */
function isTheOperator(backing: Backing, receipt: Receipt): boolean {
  return (
    compareBytes(receipt.backingName, backing.name) === 0 &&
    compareBytes(receipt.operator, backing.evidence.operator) === 0 &&
    verifyReceipt(receipt)
  );
}
