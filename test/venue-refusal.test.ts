import { readdirSync, readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking } from "../src/backing.js";
import { committedLogFor, signCommitment, stateRoot, type ServedState } from "../src/commitment.js";
import { isDoubleAcceptance, isDoublePosition, isRewrittenHistory } from "../src/fault.js";
import { encodeTransferMessage } from "../src/messages.js";
import { isOperatorReceipt, receiptStatus, type Receipt } from "../src/receipt.js";
import {
  committedOutstanding,
  gapLegsFor,
  quietFor,
  isNonServing,
  isOverdue,
  isSilent,
  provesHolding,
  redemptionIsOpen,
  replayServedState,
  snapshotRedemptions,
  standingOutstanding,
  stateIsAuthentic,
  unservedRequests,
} from "../src/recovery.js";
import {
  isAnOperator,
  isNamedSuccessor,
  operatorAt,
  operatorsOf,
  successionOf,
} from "../src/replacement.js";
import { accompanimentOf } from "../src/presentability.js";
import { revokedAt } from "../src/revocation.js";
import { LocalVenue, VenueError, type Venue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// **A venue that declines to answer is never a verdict.**
//
// A real venue holds a partial view. ErgoVenue syncs for named backings and
// refuses anything else, because absence of data must not read as a fact: a
// backing it never fetched has no commitments, and no commitments reads as
// silence since genesis. That guard is slice 17's, and it is only worth having
// if it survives the readers above it.
//
// It kept not surviving. Slice 19 found revokedAt turning the refusal into
// "not revoked" — a clean bill of health for a stolen key — and then found
// successionOf turning it into the GENESIS chain, so a replaced operator read as
// still in force and a punctual successor graded silent. Fixing those two moved
// the swallow one layer up rather than removing it: isAnOperator caught it next
// and answered false, so an honest operator's real committed state read as
// inauthentic and every receipt against it read "unrelated".
//
// The rule is one line — a VenueError is a refusal, not malformed input — and
// what this file does is hold every verifier that takes a Venue to it, in one
// list, so that a reader can see the whole surface and a new verifier that
// forgets is a failing test rather than a discovery three slices later.

/** A view synced for nothing: every record read refuses, exactly as ErgoVenue's do. */
class RefusesEverything extends LocalVenue {
  override publishedOpsFor(): never {
    throw new VenueError("this view was not synced for that backing");
  }
  override replacementsFor(): never {
    throw new VenueError("this view was not synced for that backing");
  }
  override revocationsFor(): never {
    throw new VenueError("this view was not synced for that obligor key");
  }
  override latestFor(): never {
    throw new VenueError("this view was not synced for that operator");
  }
  override witnessedAtFor(): never {
    throw new VenueError("this view was not synced for that operator");
  }
  override firstCommitmentFor(): never {
    throw new VenueError("this view was not synced for that operator");
  }
}

/** A backing that declares every clause, so no predicate returns early. */
function fixtures() {
  const real = new LocalVenue();
  const backing = makeBacking({
    obligor: KEYS.backer,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: {
      setting: "transparent",
      operator: KEYS.operator,
      silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
      witnessing: { venue: real.id, interval: 5n },
      replacementRule: KEYS.backer,
      nonService: { duration: 5n, count: 1, window: 100n },
    },
  });
  // Real, well-formed evidence, so nothing below fails for a second reason.
  const snapshots = [{ name: backing.name, opLog: [] }];
  const served: ServedState = {
    snapshots,
    commitment: signCommitment(SECRETS.operator, 0n, stateRoot(snapshots)),
  };
  const other: ServedState = {
    snapshots,
    commitment: signCommitment(SECRETS.operator, 1n, stateRoot(snapshots)),
  };
  const receipt: Receipt = {
    backingName: backing.name,
    opHash: new Uint8Array(32).fill(7),
    position: 0n,
    operator: KEYS.operator,
    signature: new Uint8Array(64),
  };
  // Two DIFFERENT operations at one nonce, or equivocatingSigner answers before
  // isDoubleAcceptance ever reaches the venue — which is what the first draft of
  // this fixture did, and it passed for that reason rather than the right one.
  const transfer = (quantity: bigint) => ({
    kind: "transfer" as const,
    from: KEYS.alice,
    to: KEYS.bob,
    quantity,
    nonce: 0n,
    signature: ed25519.sign(
      encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, quantity, 0n),
      SECRETS.alice,
    ),
  });
  const op = transfer(10n);
  const op2 = transfer(20n);
  const refusing: Venue = new RefusesEverything(real.id);
  return { refusing, backing, served, other, receipt, op, op2 };
}

/**
 * Every exported verifier that reads a venue. Adding one here is the point: a
 * new predicate that swallows a refusal fails this test rather than being found
 * by a holder who was told their operator is at fault.
 */
function surface() {
  const { refusing, backing, served, other, receipt, op, op2 } = fixtures();
  const accepted = { op, receipt };
  const accepted2 = { op: op2, receipt };
  return [
    ["committedLogFor", () => committedLogFor(backing, refusing, served)],
    ["isOperatorReceipt", () => isOperatorReceipt(backing, refusing, receipt)],
    ["receiptStatus", () => receiptStatus(backing, refusing, receipt, served)],
    ["isDoubleAcceptance", () => isDoubleAcceptance(backing, refusing, accepted, accepted2)],
    ["isDoublePosition", () => isDoublePosition(backing, refusing, receipt, receipt)],
    ["isRewrittenHistory", () => isRewrittenHistory(backing, refusing, served, other)],
    ["isAnOperator", () => isAnOperator(backing, refusing, KEYS.operator)],
    ["isNamedSuccessor", () => isNamedSuccessor(backing, refusing, KEYS.carol)],
    ["operatorsOf", () => operatorsOf(backing, refusing)],
    ["operatorAt", () => operatorAt(backing, refusing, 0n)],
    ["revokedAt", () => revokedAt(refusing, backing)],
    ["isSilent", () => isSilent(refusing, backing)],
    ["isOverdue", () => isOverdue(refusing, backing)],
    ["unservedRequests", () => unservedRequests(refusing, backing, served)],
    ["isNonServing", () => isNonServing(refusing, backing, served)],
    ["stateIsAuthentic", () => stateIsAuthentic(backing, refusing, served)],
    ["provesHolding", () => provesHolding(refusing, backing, served, KEYS.alice, 1n)],
    ["committedOutstanding", () => committedOutstanding(backing, refusing, served)],
    ["standingOutstanding", () => standingOutstanding(backing, refusing, served)],
    ["redemptionIsOpen", () => redemptionIsOpen(refusing, backing, served, KEYS.alice, 1n)],
    ["snapshotRedemptions", () => snapshotRedemptions(refusing, backing, served)],
    ["successionOf", () => successionOf(backing, refusing)],
    ["gapLegsFor", () => gapLegsFor(refusing, backing)],
    ["quietFor", () => quietFor(refusing, KEYS.operator)],
    ["replayServedState", () => replayServedState(backing, refusing, served)],
    [
      "accompanimentOf",
      () => accompanimentOf(backing, refusing, () => backing, served, new Uint8Array(32)),
    ],
  ] as const;
}

/**
 * The exceptions, named rather than omitted: these take a Venue and read nothing
 * a partial view could be missing, so there is no refusal for them to swallow.
 */
const NEVER_REFUSES = new Set(["venueIsDeclared"]);

/**
 * Every exported function in `src` whose signature takes a Venue, read out of
 * the source rather than remembered.
 *
 * A hand-kept list is the thing this whole slice exists to stop trusting: the
 * first draft of the list below missed three of twenty-four, which is the same
 * failure the rule itself keeps having. contexts.ts asserts its tags are
 * prefix-free rather than assuming it; this asserts the surface is covered.
 */
function exportedVenueReaders(): string[] {
  const dir = new URL("../src/", import.meta.url);
  const names: string[] = [];
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".ts")) continue;
    const source = readFileSync(new URL(file, dir), "utf8");
    for (const match of source.matchAll(/export function (\w+)\(([^)]*)\)/gs)) {
      // The TYPE, not the word: a parameter merely named `decisionVenue` is not
      // a venue read, and matching the substring reported one as a gap in the
      // surface. A guard that cries wolf gets an exception added to it, which is
      // how it stops being a guard.
      if (/:\s*Venue\b/.test(match[2] as string)) names.push(match[1] as string);
    }
  }
  return names;
}

describe("a venue that declines to answer is never a verdict", () => {
  for (const [name, call] of surface()) {
    it(`${name} refuses rather than answering`, () => {
      expect(call).toThrow(VenueError);
    });
  }
});

describe("and the list is the whole surface, checked rather than trusted", () => {
  it("covers every exported function that takes a Venue", () => {
    const covered = new Set<string>([...surface().map(([name]) => name), ...NEVER_REFUSES]);
    const missing = exportedVenueReaders().filter((name) => !covered.has(name));
    expect(missing).toEqual([]);
  });

  it("reads a surface at all, so a broken matcher cannot pass vacuously", () => {
    expect(exportedVenueReaders().length).toBeGreaterThan(20);
  });
});

describe("and the refusal is the only thing that escapes", () => {
  it("malformed input still gets an answer rather than a throw", () => {
    // The other half, and the reason these catches exist at all: everything
    // here reads bytes an adversary supplied, so a wrong length or a missing
    // field is a failed check. Only the venue's own refusal is different.
    const real = new LocalVenue();
    const backing = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
        witnessing: { venue: real.id, interval: 5n },
      },
    });
    const junk = undefined as unknown as ServedState;
    expect(committedLogFor(backing, real, junk)).toBeUndefined();
    expect(stateIsAuthentic(backing, real, junk)).toBe(false);
    expect(provesHolding(real, backing, junk, KEYS.alice, 1n)).toBe(false);
    expect(receiptStatus(backing, real, undefined as unknown as Receipt, junk)).toBe("unrelated");
    expect(isAnOperator(backing, real, new Uint8Array(3))).toBe(false);
  });

  it("a real venue answers all of them, so the guard costs nothing when synced", () => {
    const real = new LocalVenue();
    const backing = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
        witnessing: { venue: real.id, interval: 5n },
      },
    });
    expect(isSilent(real, backing)).toBe(false);
    expect(isAnOperator(backing, real, KEYS.operator)).toBe(true);
    expect(revokedAt(real, backing)).toBeUndefined();
  });
});
