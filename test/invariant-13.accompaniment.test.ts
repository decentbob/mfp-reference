import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { signCommitment, stateRoot, type ServedState } from "../src/commitment.js";
import { closureStatus, type Terms } from "../src/closure.js";
import { encodeIssuanceMessage } from "../src/messages.js";
import { accompanimentOf } from "../src/presentability.js";
import {
  demandHash,
  encodeDemand,
  encodeLock,
  type DemandOp,
  type LockOp,
} from "../src/presentation.js";
import { type PublishedOp } from "../src/oplog.js";
import { Sequencer } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// The gap slice 22 pinned as OPEN, and the party it costs.
//
// Invariant 13 says a holding is presentable at *b* for *q* only with *q·cᵢ*
// units of each leg. Slice 22 enforces that when the demand is filed — but the
// law is per backing, so a served log carrying a demand whose legs were never
// locked replays perfectly well, and stateIsAuthentic, which folds one backing,
// says yes.
//
// The party who loses by it is the backer: it would answer a demand and take in
// a claim it cannot unwind. And the backer signs the acceptance, so it is the
// one who can check first — which is what this is for. It reads across the
// served state, where every backing the operator serves already is, plus the
// legs' own terms, which are hashes in R and so need a resolver (§C0b: published
// means retrievable).
//
// Three answers, not two, for the reason every predicate here has three:
// "I could not read the legs" must not come back as "the backer took in a set it
// cannot unwind".

function setup() {
  const venue = new LocalVenue();
  const mk = (thing: string, reliance: { target: Uint8Array; count: bigint }[] = []) =>
    makeBacking({
      obligor: KEYS.backer,
      payout: { thing, quantumExponent: -2, perUnit: 100n },
      reliance,
      evidence: { setting: "transparent", operator: KEYS.operator },
    });
  const gold = mk("GOLD");
  const eur = mk("EUR", [{ target: gold.name, count: 2n }]);
  const sequencer = new Sequencer(SECRETS.operator, venue);
  for (const backing of [gold, eur]) {
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
    for (const holder of [KEYS.alice, KEYS.bob]) {
      const nonce = sequencer.nextNonce(KEYS.backer, backing);
      sequencer.submitIssue(
        { backing, recipient: holder, quantity: 200n, nonce },
        ed25519.sign(encodeIssuanceMessage(backing.name, holder, 200n, nonce), SECRETS.backer),
      );
    }
  }
  const terms: Terms = (name) =>
    [gold, eur].find((b) => Buffer.from(b.name).equals(Buffer.from(name)));
  return { venue, sequencer, eur, gold, terms };
}

function served(sequencer: Sequencer): ServedState {
  return { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
}

/**
 * A state this operator really committed, with entries the sequencer would have
 * refused appended by hand.
 *
 * Built rather than submitted, because what is being checked is a SERVED state,
 * and that comes from an operator with a motive. A test-only door on Sequencer
 * would be the privileged path invariant 8 says must not exist.
 */
function commitWith(
  venue: LocalVenue,
  sequencer: Sequencer,
  additions: readonly { backing: Backing; op: PublishedOp }[],
): ServedState {
  const snapshots = sequencer.snapshot().map((snapshot) => {
    const extra = additions.filter((a) =>
      Buffer.from(a.backing.name).equals(Buffer.from(snapshot.name)),
    );
    return {
      name: snapshot.name,
      opLog: [
        ...snapshot.opLog,
        ...extra.map((a, i) => ({ ...a.op, position: snapshot.opLog.length + i })),
      ],
    };
  });
  const commitment = signCommitment(
    SECRETS.operator,
    venue.nextSequenceFor(KEYS.operator),
    stateRoot(snapshots),
  );
  venue.publish(commitment);
  return { snapshots, commitment };
}

/** Alice's demand on eur, as the operation a log would carry. */
function bareDemand(sequencer: Sequencer, eur: Backing, quantity: bigint) {
  const demand: DemandOp = {
    backing: eur,
    holder: KEYS.alice,
    quantity,
    instant: 0n,
    deadline: 100n,
    nonce: sequencer.nextNonce(KEYS.alice, eur),
  };
  const op: PublishedOp = {
    kind: "demand",
    holder: demand.holder,
    quantity: demand.quantity,
    instant: demand.instant,
    deadline: demand.deadline,
    nonce: demand.nonce,
    signature: ed25519.sign(encodeDemand(demand), SECRETS.alice),
  };
  return { hash: demandHash(demand), op };
}

/** A lock as the operation a leg log would carry, signed by `secret`. */
function bareLock(
  gold: Backing,
  lock: Omit<LockOp, "backing">,
  secret: Uint8Array = SECRETS.alice,
): PublishedOp {
  const full: LockOp = { ...lock, backing: gold };
  return {
    kind: "lock",
    demandHash: full.demandHash,
    holder: full.holder,
    beneficiary: full.beneficiary,
    quantity: full.quantity,
    nonce: full.nonce,
    signature: ed25519.sign(encodeLock(full), secret),
  };
}

/** File a demand for `quantity` of eur, locking its leg. */
function file(sequencer: Sequencer, eur: Backing, gold: Backing, quantity: bigint) {
  const demand: DemandOp = {
    backing: eur,
    holder: KEYS.alice,
    quantity,
    instant: 0n,
    deadline: 100n,
    nonce: sequencer.nextNonce(KEYS.alice, eur),
  };
  const hash = demandHash(demand);
  const signature = ed25519.sign(encodeDemand(demand), SECRETS.alice);
  const lock: LockOp = {
    backing: gold,
    demandHash: hash,
    holder: KEYS.alice,
    beneficiary: KEYS.backer,
    quantity: quantity * 2n,
    nonce: sequencer.nextNonce(KEYS.alice, gold),
  };
  sequencer.submitDemand(demand, signature, [
    { op: lock, signature: ed25519.sign(encodeLock(lock), SECRETS.alice) },
  ]);
  return { hash, demand };
}

describe("invariant 13: whether a standing demand is accompanied", () => {
  it("says accompanied where every leg is locked for q·cᵢ", () => {
    const { venue, sequencer, eur, gold, terms } = setup();
    const { hash } = file(sequencer, eur, gold, 40n);
    expect(accompanimentOf(eur, venue, terms, served(sequencer), hash)).toBe("accompanied");
  });

  it("says unaccompanied where the legs were never locked", () => {
    // The OPEN case from slice 22, now readable. The log still replays — the law
    // is per backing and cannot see GOLD — so this is what a backer asks before
    // it signs an acceptance.
    const { venue, sequencer, eur, terms } = setup();
    const { hash, op } = bareDemand(sequencer, eur, 40n);
    const state = commitWith(venue, sequencer, [{ backing: eur, op }]);
    expect(accompanimentOf(eur, venue, terms, state, hash)).toBe("unaccompanied");
  });

  it("a backing with no reliance is accompanied by nothing, which is enough", () => {
    const { venue, sequencer, gold, terms } = setup();
    const op: DemandOp = {
      backing: gold,
      holder: KEYS.alice,
      quantity: 10n,
      instant: 0n,
      deadline: 100n,
      nonce: sequencer.nextNonce(KEYS.alice, gold),
    };
    sequencer.submitDemand(op, ed25519.sign(encodeDemand(op), SECRETS.alice));
    expect(accompanimentOf(gold, venue, terms, served(sequencer), demandHash(op))).toBe(
      "accompanied",
    );
  });

  it("says unreadable where this reader lacks the legs' terms", () => {
    // Not "unaccompanied": a reader holding half the graph has established
    // nothing, and reporting that as a fact about the backer is the merge this
    // codebase keeps removing.
    const { venue, sequencer, eur, gold } = setup();
    const { hash } = file(sequencer, eur, gold, 40n);
    const partial: Terms = (name) =>
      Buffer.from(eur.name).equals(Buffer.from(name)) ? eur : undefined;
    expect(accompanimentOf(eur, venue, partial, served(sequencer), hash)).toBe("unreadable");
  });

  it("and unreadable for a demand that is not standing in this state", () => {
    const { venue, sequencer, eur, terms } = setup();
    expect(
      accompanimentOf(eur, venue, terms, served(sequencer), new Uint8Array(32).fill(9)),
    ).toBe("unreadable");
  });

  it("refuses a resolver that answers with a different backing", () => {
    const { venue, sequencer, eur, gold, terms } = setup();
    const { hash } = file(sequencer, eur, gold, 40n);
    const liar: Terms = (name) =>
      Buffer.from(eur.name).equals(Buffer.from(name)) ? eur : eur;
    expect(accompanimentOf(eur, venue, liar, served(sequencer), hash)).toBe("unreadable");
    expect(accompanimentOf(eur, venue, terms, served(sequencer), hash)).toBe("accompanied");
  });
});

describe("invariant 13: a lock that does not match its demand is not accompaniment", () => {
  it("catches a lock for too few units", () => {
    const { venue, sequencer, eur, gold, terms } = setup();
    const { hash, op } = bareDemand(sequencer, eur, 40n);
    const short = bareLock(gold, {
      demandHash: hash,
      holder: KEYS.alice,
      beneficiary: KEYS.backer,
      quantity: 79n,
      nonce: sequencer.nextNonce(KEYS.alice, gold),
    });
    const state = commitWith(venue, sequencer, [
      { backing: eur, op },
      { backing: gold, op: short },
    ]);
    expect(accompanimentOf(eur, venue, terms, state, hash)).toBe("unaccompanied");
  });

  it("catches a lock paying anyone but the demanded backing's obligor", () => {
    const { venue, sequencer, eur, gold, terms } = setup();
    const { hash, op } = bareDemand(sequencer, eur, 40n);
    const elsewhere = bareLock(gold, {
      demandHash: hash,
      holder: KEYS.alice,
      beneficiary: KEYS.mallory,
      quantity: 80n,
      nonce: sequencer.nextNonce(KEYS.alice, gold),
    });
    const state = commitWith(venue, sequencer, [
      { backing: eur, op },
      { backing: gold, op: elsewhere },
    ]);
    expect(accompanimentOf(eur, venue, terms, state, hash)).toBe("unaccompanied");
  });

  it("and one committing somebody else's units", () => {
    // Bob holds GOLD of his own, so the lock is a lawful entry and the leg
    // replays — which is what makes this "unaccompanied" rather than
    // "unreadable". A lock by somebody with no units is not a history at all.
    const { venue, sequencer, eur, gold, terms } = setup();
    const { hash, op } = bareDemand(sequencer, eur, 40n);
    const bobs = bareLock(
      gold,
      {
        demandHash: hash,
        holder: KEYS.bob,
        beneficiary: KEYS.backer,
        quantity: 80n,
        nonce: sequencer.nextNonce(KEYS.bob, gold),
      },
      SECRETS.bob,
    );
    const state = commitWith(venue, sequencer, [
      { backing: eur, op },
      { backing: gold, op: bobs },
    ]);
    expect(accompanimentOf(eur, venue, terms, state, hash)).toBe("unaccompanied");
  });
});

describe("one level, no traversal — and what covers the rest", () => {
  it("checks R(b) only, so a leg's own reliance is the leg's problem", () => {
    // Invariant 13 is one level by construction: "a reliance target's own
    // reliance is that target's presentation problem". So this must NOT walk
    // down — a future reader tempted to make it traverse would be changing the
    // invariant, not fixing a gap.
    //
    // What covers the rest is closure, one layer earlier: R(b) written as
    // closure(S) already names everything under it, and closureStatus tells a
    // holder whether it was. The two are complementary — closureStatus says the
    // TERMS are fully unwindable, accompanimentOf says this DEMAND honours them
    // — and neither does the other's job.
    const venue = new LocalVenue();
    const mk = (thing: string, reliance: { target: Uint8Array; count: bigint }[] = []) =>
      makeBacking({
        obligor: KEYS.backer,
        payout: { thing, quantumExponent: -2, perUnit: 100n },
        reliance,
        evidence: { setting: "transparent", operator: KEYS.operator },
      });
    const iron = mk("IRON");
    const gold = mk("GOLD", [{ target: iron.name, count: 1n }]);
    // R(EUR) names GOLD and not IRON: an unclosed requirement, which §8b makes
    // readable rather than invalid.
    const eur = mk("EUR", [{ target: gold.name, count: 2n }]);
    const sequencer = new Sequencer(SECRETS.operator, venue);
    for (const backing of [iron, gold, eur]) {
      sequencer.register(backing, signBacking(SECRETS.backer, backing));
      const nonce = sequencer.nextNonce(KEYS.backer, backing);
      sequencer.submitIssue(
        { backing, recipient: KEYS.alice, quantity: 500n, nonce },
        ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 500n, nonce), SECRETS.backer),
      );
    }
    const terms: Terms = (name) =>
      [iron, gold, eur].find((b) => Buffer.from(b.name).equals(Buffer.from(name)));

    const demand: DemandOp = {
      backing: eur,
      holder: KEYS.alice,
      quantity: 10n,
      instant: 0n,
      deadline: 100n,
      nonce: sequencer.nextNonce(KEYS.alice, eur),
    };
    const hash = demandHash(demand);
    const lock: LockOp = {
      backing: gold,
      demandHash: hash,
      holder: KEYS.alice,
      beneficiary: KEYS.backer,
      quantity: 20n,
      nonce: sequencer.nextNonce(KEYS.alice, gold),
    };
    sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice), [
      { op: lock, signature: ed25519.sign(encodeLock(lock), SECRETS.alice) },
    ]);

    // R(EUR) is honoured in full, and no IRON is reserved, and both are correct.
    expect(accompanimentOf(eur, venue, terms, served(sequencer), hash)).toBe("accompanied");
    // The gap is in the TERMS, and that is the question closure answers.
    expect(closureStatus(terms, eur)).toBe("unclosed");
    expect(closureStatus(terms, gold)).toBe("closed");
  });
});
