// Succession (§C2): who serves a backing, once the key E names no longer does.
//
// "**A replacement is itself a witnessed object.** It is signed by whoever
// **E**'s rule names, the backer by default, states the role, the successor and
// the effective index, and is published always at the successor venue and at the
// old one while it serves. Each replacement names its predecessor, so the chain
// from the original terms is walkable. Its effective index is no earlier than
// the index at which it is itself witnessed, and it takes effect only from the
// first index at which it has published its own commitment over a spent set it
// serves in full. Until then the predecessor's last commitment governs, no new
// co-signatures issue, and accrual against the incumbent continues... From the
// effective index the old attester's co-signatures stop counting, which is why a
// wallet verifies the chain rather than the key it remembers."
//
// **E's operator is the genesis value, not a mutable field.** It sits inside the
// name and invariant 1 forbids an edit, so a replacement does not change it — it
// supersedes it, on a record anyone can walk. That is what makes "the chain from
// the original terms is walkable" the literal mechanism rather than a metaphor,
// and it is why the venue and the operator can "move only under its replacement
// rule" while both stay inside the hash.
//
// The chain is **hash-linked**: each replacement names its predecessor by the
// hash of that predecessor's own canonical message, and the first link names the
// backing itself. A fork cannot be spliced in unseen, and walking backwards from
// any link reaches the original terms or nothing.
//
// Canonical message, signed by the key E's replacement clause names:
//
//   context "mfp/replacement/v1"
//     || 32-byte backing name
//     || u8 role (0x01 operator)
//     || 32-byte successor
//     || 32-byte predecessor (the backing name at the first link)
//     || u64 effective index
//
// **One role is defined, and the field is still written.** Only the operator can
// be replaced here; the venue is the clock every deadline is read against, and
// moving it is a second clock, which is the conflation slice 5 removed. Writing
// the role anyway is what stops a replacement of the operator being read later
// as a replacement of something else.
//
// Everything below is a verifier: the bytes come from whoever publishes them.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { type Backing } from "./backing.js";
import { ByteWriter, compareBytes, copyBytes } from "./bytes.js";
import { REPLACEMENT_CONTEXT } from "./contexts.js";
import { verifySignatureStrict } from "./keys.js";
import type { Venue } from "./venue.js";

/** The only role this slice can replace. */
export const ROLE_OPERATOR = 0x01;

export interface Replacement {
  /** Which role is being replaced. Only ROLE_OPERATOR is served here. */
  readonly role: number;
  /** The key taking over. */
  readonly successor: Uint8Array;
  /** The previous link: that replacement's own hash, or the backing name. */
  readonly predecessor: Uint8Array;
  /** The witnessed index from which the successor may take over. */
  readonly effective: bigint;
  /** The signature of the key E's replacement clause names. */
  readonly signature: Uint8Array;
}

/** A replacement together with the venue's own word on when it was witnessed. */
export interface WitnessedReplacement {
  readonly replacement: Replacement;
  readonly at: bigint;
}

/** A snapshot of a replacement's bytes, for the reason commitments are copied. */
export function copyReplacement(replacement: Replacement): Replacement {
  return {
    role: replacement.role,
    successor: copyBytes(replacement.successor),
    predecessor: copyBytes(replacement.predecessor),
    effective: replacement.effective,
    signature: copyBytes(replacement.signature),
  };
}

/** The bytes the replacement rule's key signs. Throws on a malformed field. */
export function replacementMessage(backingName: Uint8Array, replacement: Replacement): Uint8Array {
  const w = new ByteWriter();
  w.context(REPLACEMENT_CONTEXT);
  w.key32(backingName, "backing name");
  w.u8(replacement.role);
  w.key32(replacement.successor, "successor key");
  w.key32(replacement.predecessor, "predecessor");
  w.u64(replacement.effective);
  return w.finish();
}

/** A replacement's identity, and the value its successor names as predecessor. */
export function replacementHash(backingName: Uint8Array, replacement: Replacement): Uint8Array {
  return sha256(replacementMessage(backingName, replacement));
}

/**
 * Whether this is a well-formed replacement of this backing's operator, signed
 * by the key E's replacement clause names.
 *
 * A backing whose E declares no replacement clause cannot be replaced at all
 * (§C2b: "Whether a sequencer can be replaced at all is answered in E"), so
 * every replacement of it answers false however well it is signed.
 */
export function isSignedReplacement(backing: Backing, replacement: Replacement): boolean {
  try {
    const rule = backing.evidence.replacementRule;
    if (rule === undefined) return false;
    if (replacement.role !== ROLE_OPERATOR) return false;
    const message = replacementMessage(backing.name, replacement);
    return verifySignatureStrict(replacement.signature, message, rule);
  } catch {
    return false;
  }
}

/** One link of a walked chain: who takes over, and the index they take over at. */
export interface Succession {
  readonly operator: Uint8Array;
  /** The index from which this operator is in force. */
  readonly from: bigint;
}

/**
 * The chain of operators this backing has had, in force order, starting with the
 * key E names.
 *
 * Walked forward from the backing itself, taking at each step the earliest
 * witnessed replacement that names the current link as its predecessor. **Earliest
 * witnessed wins**, which is the rule two requests at one nonce already follow
 * (§C2, witnessing pins order): two replacements naming one predecessor are the
 * rule-holder signing two successors, and the one it published first is the one
 * it chose first. Nothing freezes, and the rule-holder is entitled to choose.
 *
 * A link takes force at the LATER of two indices, which is §C2's own two-stage
 * rule: the effective index it declares, and the first index at which the
 * successor published a commitment of its own. "Until then the predecessor's
 * last commitment governs."
 *
 * What is not checked, and cannot be from the venue alone: that the successor's
 * commitment is "over a spent set it serves in full". A commitment is a root, so
 * whether it carries this backing at all is unreadable without the served state
 * — the same limit as the dropped-backing hole recorded in slice 11, and it
 * wants the same answer, a predicate that takes a served state. What IS checked
 * is that the commitment came at or after the handover was witnessed, so it is
 * at least one the successor could have made for this backing; without that
 * bound the second stage means nothing at all for a successor that already
 * operates something else.
 */
export function successionOf(backing: Backing, venue: Venue): Succession[] {
  const chain: Succession[] = [{ operator: copyBytes(backing.evidence.operator), from: 0n }];
  try {
    if (backing.evidence.replacementRule === undefined) return chain;
    const witnessed = venue
      .replacementsFor(backing.name)
      .filter((w) => isSignedReplacement(backing, w.replacement))
      // A replacement cannot take force before it was witnessed (§C2), and one
      // declaring an earlier index is refused rather than corrected: the
      // rule-holder does not get to backdate a handover.
      .filter((w) => w.replacement.effective >= w.at);

    const seen = new Set<string>([bytesToHex(backing.name)]);
    let link = backing.name;
    for (;;) {
      const next = witnessed
        .filter((w) => compareBytes(w.replacement.predecessor, link) === 0)
        .sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0))[0];
      if (next === undefined) return chain;

      const hash = replacementHash(backing.name, next.replacement);
      // A hash cycle cannot be built (invariant 5's reasoning), so this guards a
      // malformed record rather than a real cycle — and it guarantees the walk
      // terminates on any input at all, which a verifier needs.
      if (seen.has(bytesToHex(hash))) return chain;
      seen.add(bytesToHex(hash));

      const incumbent = chain[chain.length - 1] as Succession;
      const successor = next.replacement.successor;
      // A handover to the incumbent is not one. Refusing it keeps the chain
      // strictly a sequence of changes, so "the old attester's co-signatures
      // stop counting" never means its own.
      if (compareBytes(successor, incumbent.operator) === 0) return chain;

      // At or after the handover was witnessed: a commitment made before anyone
      // named this successor cannot be the one §C2 asks for.
      const committed = venue.firstCommitmentFor(successor, next.at);
      if (committed === undefined) return chain;
      const from = next.replacement.effective > committed ? next.replacement.effective : committed;
      // In force no earlier than the incumbent was: a chain that went backwards
      // would have two operators in force at one index.
      if (from < incumbent.from) return chain;

      chain.push({ operator: copyBytes(successor), from });
      link = hash;
    }
  } catch {
    return chain;
  }
}

/**
 * The operator in force at this index — the key a wallet must check against
 * rather than the one it remembers (§C2).
 */
export function operatorAt(backing: Backing, venue: Venue, index: bigint): Uint8Array {
  return operatorIn(successionOf(backing, venue), index);
}

/**
 * The same question asked of a chain already walked.
 *
 * Walking it verifies a signature per published replacement, and anyone may
 * publish one for free — so a caller reading the chain at many indices walks it
 * once and asks here, rather than paying that per index. The recovery walk does
 * exactly that: it reads the operator at every operation published against the
 * backing, and both counts are the adversary's to grow.
 */
export function operatorIn(chain: readonly Succession[], index: bigint): Uint8Array {
  let inForce = chain[0] as Succession;
  for (const link of chain) if (link.from <= index) inForce = link;
  return copyBytes(inForce.operator);
}

/**
 * Every key that has served this backing, in force order.
 *
 * Membership rather than time, because the acts a receipt attests to carry no
 * index: a receipt names an operation and a position, never when it was signed.
 * So a retired operator's co-signature over an operation its own log really held
 * stays evidence of what it accepted while it served. What stops it counting for
 * anything current is that the state of record is the operator in force now, and
 * a receipt is read against that log (receiptStatus).
 */
export function operatorsOf(backing: Backing, venue: Venue): Uint8Array[] {
  return successionOf(backing, venue).map((link) => copyBytes(link.operator));
}

/** Whether this key is one of the operators this backing has had. */
export function isAnOperator(backing: Backing, venue: Venue, key: Uint8Array): boolean {
  try {
    return operatorsOf(backing, venue).some((operator) => compareBytes(operator, key) === 0);
  } catch {
    return false;
  }
}
