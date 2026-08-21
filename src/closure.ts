// Closure (invariant 16, §8b).
//
// "The full chain under a requirement is its **closure**. Closures are written
// with a `closure(S)` macro, expanded before hashing, and counts add up where
// paths meet. If *b* relies on *x* and *y*, and each of those relies on *z* at
// 1, then closure({x:1, y:1}) = {x:1, y:1, z:2}. Two units of *z*, because
// presenting at *x* alone would leave *y* without the *z* it needs.
// Multiplicities grow like a matrix power, so wallets cap closure size."
//
// **A macro for writing terms, not a rule about them.** §8b: "Anyone can compute
// closed(b), whether R(b) equals its own closure. An unclosed requirement is
// readable: the backer takes in a set it cannot fully unwind, usually because it
// means to sell it." So an unclosed R is a legal setting rather than a mistake,
// and `makeBacking` stores what it is handed. "Expanded before hashing" means a
// backer who writes closure(S) gets the flat expansion into its terms and the
// name commits to that — never that a later reader re-expands what was written,
// which would make a name a function of who is reading it.
//
// **It needs the targets' own terms**, which are hashes here, so it takes a
// resolver. §C0b is what makes one available: "Published means retrievable by a
// stranger: terms, logs, totals, commitments..." — the same availability the
// trail already assumes.
//
// **The resolver is the untrusted part.** It is asked for a name and can hand
// back anything, so every answer is checked against the name asked for. That
// check is also what makes the walk terminate, and it is why invariant 5 still
// holds — "do not write cycle detection. A reliance cycle would need a hash
// cycle; it cannot be built." With the answer checked, a loop would need one, so
// there is nothing to detect. A resolver that tries is refused for lying, not
// for looping.

import { backingName, type Backing, type RelianceEntry } from "./backing.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { compareBytes, copyBytes, EncodingError, validateQuantity } from "./bytes.js";

/**
 * A wallet's own store of terms, by name. Undefined where it does not hold them
 * — the same shape as presentability's HoldingView, and untrusted in the same
 * way: what it returns is checked, never taken on its word.
 */
export type Terms = (name: Uint8Array) => Backing | undefined;

/** The same cap makeBacking applies to a stored R, applied to the result. */
const MAX_CLOSURE_ENTRIES = 4096;
const NAME_LENGTH = 32;

/**
 * The closure of a reliance set: every backing anywhere under it, with counts
 * multiplied along each path and summed where paths meet, flat, sorted by name
 * and deduplicated.
 *
 * **This is what a backer writes into its terms**, so it throws rather than
 * answering on anything it cannot establish: a name that cannot be resolved, a
 * resolver that answers with the wrong backing, a count that will not fit a
 * quantity, or a result past the cap. A name minted over a guess would claim to
 * be a closure and not be one, and invariant 1 makes that permanent.
 *
 * Deterministic in its output for a given set of terms: the walk order does not
 * reach the bytes, because counts are accumulated into a map and the result is
 * sorted by target. The same terms give the same name on every machine.
 */
export function closureOf(
  terms: Terms,
  entries: readonly RelianceEntry[],
): RelianceEntry[] {
  // What the set asks for directly. A floor, not a contribution: see below.
  const declared = new Map<string, bigint>();
  const pending: Uint8Array[] = [];
  for (const entry of entries) {
    if (entry.target.length !== NAME_LENGTH) {
      throw new EncodingError(`reliance target must be ${NAME_LENGTH} bytes`);
    }
    validateQuantity(entry.count, "reliance count");
    const key = bytesToHex(entry.target);
    const running = (declared.get(key) ?? 0n) + entry.count;
    validateQuantity(running, "reliance count");
    declared.set(key, running);
    pending.push(entry.target);
  }

  // Every backing anywhere under the set, with each of the resolver's answers
  // checked against the name it was asked for.
  const nodes = new Map<string, Backing>();
  while (pending.length > 0) {
    const target = pending.pop() as Uint8Array;
    const key = bytesToHex(target);
    if (nodes.has(key)) continue;
    const backing = terms(target);
    if (backing === undefined) throw new EncodingError(`closure needs terms for ${key}`);
    // Recomputed from the fields rather than read off the object, so a hand-made
    // Backing cannot assert a name it does not have. This is also what makes the
    // walk terminate: with the answer pinned to the question, a loop would need
    // a hash cycle, and invariant 5 says one cannot be built — so there is
    // nothing here detecting cycles, only a resolver being held to its word.
    if (compareBytes(backingName(backing), target) !== 0) {
      throw new EncodingError("terms answered with a different backing");
    }
    nodes.set(key, backing);
    if (nodes.size > MAX_CLOSURE_ENTRIES) throw new EncodingError("closure too large");
    for (const under of backing.reliance) pending.push(under.target);
  }

  // Settle each backing only once every backing that requires it has been
  // settled, which a DAG always allows. A count is then final when it is read.
  const waiting = new Map<string, number>();
  for (const key of nodes.keys()) waiting.set(key, 0);
  for (const backing of nodes.values()) {
    for (const under of backing.reliance) {
      const key = bytesToHex(under.target);
      waiting.set(key, (waiting.get(key) as number) + 1);
    }
  }

  const required = new Map<string, bigint>();
  const settled = new Map<string, bigint>();
  const ready = [...waiting].filter(([, n]) => n === 0).map(([key]) => key);
  while (ready.length > 0) {
    const key = ready.pop() as string;
    const floor = declared.get(key) ?? 0n;
    const needed = required.get(key) ?? 0n;
    const count = needed > floor ? needed : floor;
    settled.set(key, count);

    for (const under of (nodes.get(key) as Backing).reliance) {
      const child = bytesToHex(under.target);
      const total = (required.get(child) ?? 0n) + count * under.count;
      validateQuantity(total, "reliance count");
      required.set(child, total);
      const left = (waiting.get(child) as number) - 1;
      waiting.set(child, left);
      if (left === 0) ready.push(child);
    }
  }

  // **An assertion at the writer, not the cycle detection invariant 5 forbids.**
  // It decides nothing about cycles and takes no branch on one; it refuses to
  // emit a closure it did not finish computing, for the reason ByteWriter
  // asserts a field's width at the one place that writes it. A name minted over
  // a partial expansion would be permanent (invariant 1), and the only way to
  // reach here is a resolver answering for a name it was not asked for — which
  // is already refused above.
  if (settled.size !== nodes.size) throw new EncodingError("closure did not complete");

  return [...settled]
    .map(([key, count]) => ({ target: copyBytes((nodes.get(key) as Backing).name), count }))
    .sort((a, b) => compareBytes(a.target, b.target));
}

/**
 * §8b's `closed(b)`, and it has **three** answers rather than two.
 *
 *   - `closed`     R is already its own closure: the set fully unwinds.
 *   - `unclosed`   it is not, which §8b makes a readable setting rather than a
 *                  fault — "the backer takes in a set it cannot fully unwind,
 *                  usually because it means to sell it".
 *   - `unreadable` this reader does not hold the terms under it, so it has not
 *                  established either.
 *
 * **The third exists because the other two are facts about the backer.** A
 * boolean would report "I do not have the terms" as "the backer means to sell
 * it", which is a verdict built out of not having looked — the same merge slice
 * 18 removed from committedLogFor and slice 20 removed from every reader of a
 * venue. §8b says "anyone can compute closed(b)", and a reader holding half the
 * graph is exactly who cannot.
 *
 * It answers rather than throwing, where closureOf throws: a builder minting a
 * name must not proceed on a guess, and a reader asking a question is entitled
 * to be told the question is unanswerable here.
 */
export type Closedness = "closed" | "unclosed" | "unreadable";

export function closureStatus(terms: Terms, backing: Backing): Closedness {
  let closed: RelianceEntry[];
  try {
    closed = closureOf(terms, backing.reliance);
  } catch {
    return "unreadable";
  }
  if (closed.length !== backing.reliance.length) return "unclosed";
  const matches = closed.every((entry, i) => {
    const declared = backing.reliance[i] as RelianceEntry;
    return compareBytes(entry.target, declared.target) === 0 && entry.count === declared.count;
  });
  return matches ? "closed" : "unclosed";
}
