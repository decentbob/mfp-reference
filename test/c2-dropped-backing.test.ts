import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { compareBytes } from "../src/bytes.js";
import {
  committedLogFor,
  signCommitment,
  stateRoot,
  type ServedState,
} from "../src/commitment.js";
import { isRewrittenHistory } from "../src/fault.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import { type PublishedOp } from "../src/oplog.js";
import { receiptStatus } from "../src/receipt.js";
import { isNonServing, isSilent, provesHolding, unservedRequests } from "../src/recovery.js";
import { replacementMessage, ROLE_OPERATOR, type Replacement } from "../src/replacement.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// **An operator that drops one backing from its committed state.**
//
// §C2 has a shared operator batching: "The fee is per backing per interval,
// which forces batching. A shared operator publishes one transaction over a root
// of its backings' commitments." So a commitment omitting one backing is not a
// commitment FOR that backing — and a stranger reading the venue sees only a
// root, so it cannot tell.
//
// Slice 11 found the hole and recorded it; slices 13 and 14 both re-flagged it
// and deferred. What nobody had run was the whole of it, and it is worse than
// recorded: the aggravated grade is blind (the operator publishes), the rewrite
// fault is silent (the log did not shrink, it vanished), a receipt reads
// "unrelated", and no holding proves. The non-service grade DOES fire — but only
// against the last state that carried the backing — and the remedy it opens,
// §C2's replacement rule, could not be taken: takeOver refused the incumbent's
// latest (no log for the backing) and refused the last state carrying it (not
// the incumbent's latest). The grade fired, named the remedy, and the remedy
// could not be executed.
//
// The cause is one layer down. committedLogFor asks three questions that always
// travel together and merged two different answers into one `undefined`: "this
// is not your operator's state", and "this IS your operator's state, and it
// carries no log for your backing". The second is the accusation, reported as
// the first, and every caller inherited the blindness.

const SILENCE = { noCommitmentDuration: 20n, challengeWindow: 5n };
const NON_SERVICE = { duration: 10n, count: 2, window: 100n };

function setup(replaceable = true) {
  const venue = new LocalVenue();
  const make = (thing: string) =>
    makeBacking({
      obligor: KEYS.backer,
      payout: { thing, quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: SILENCE,
        witnessing: { venue: venue.id, interval: 5n },
        nonService: NON_SERVICE,
        ...(replaceable ? { replacementRule: KEYS.backer } : {}),
      },
    });
  // Two backings under one operator, which is §C5's recommended topology and
  // the whole reason the hole exists: dropping one leaves the other to keep the
  // operator looking punctual.
  const eur = make("EUR");
  const usd = make("USD");
  const sequencer = new Sequencer(SECRETS.operator, venue);
  for (const backing of [eur, usd]) {
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
    sequencer.submitIssue(
      { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
    );
  }
  return { venue, sequencer, eur, usd };
}

/** The state as the operator serves it now, committed and published. */
function commitAll(sequencer: Sequencer): ServedState {
  return { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
}

/**
 * Commit everything EXCEPT `dropped`, and publish it. This is the whole attack:
 * a well-formed commitment, validly signed, over a state that simply has no
 * entry for one of the backings this operator serves.
 */
function commitWithout(
  venue: LocalVenue,
  sequencer: Sequencer,
  dropped: Backing,
): ServedState {
  const snapshots = sequencer
    .snapshot()
    .filter((s) => compareBytes(s.name, dropped.name) !== 0);
  const commitment = signCommitment(
    SECRETS.operator,
    venue.nextSequenceFor(KEYS.operator),
    stateRoot(snapshots),
  );
  venue.publish(commitment);
  return { snapshots, commitment };
}

/** Keep committing everything but `dropped`, on schedule, for `rounds` intervals. */
function keepCommittingWithout(
  venue: LocalVenue,
  sequencer: Sequencer,
  dropped: Backing,
  rounds: number,
): ServedState {
  let last!: ServedState;
  for (let i = 0; i < rounds; i++) {
    venue.advance(5n);
    last = commitWithout(venue, sequencer, dropped);
  }
  return last;
}

/** Alice's signed request to move `quantity` to Bob at her nonce `nonce`. */
function request(backing: Backing, quantity: bigint, nonce: bigint): PublishedOp {
  return {
    kind: "transfer",
    from: KEYS.alice,
    to: KEYS.bob,
    quantity,
    nonce,
    signature: ed25519.sign(
      encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, quantity, nonce),
      SECRETS.alice,
    ),
  };
}

function replacementBy(
  backing: Backing,
  ruleSecret: Uint8Array,
  successor: Uint8Array,
  effective: bigint,
): Replacement {
  const unsigned = {
    role: ROLE_OPERATOR,
    successor,
    predecessor: backing.name,
    effective,
    signature: new Uint8Array(64),
  };
  return {
    ...unsigned,
    signature: ed25519.sign(replacementMessage(backing.name, unsigned), ruleSecret),
  };
}

describe("§C2: a committed state that carries no log for this backing", () => {
  it("is told apart from a state that is not this operator's at all", () => {
    // The whole slice in one assertion. Three questions, three answers — where
    // before there were three questions and two.
    const { venue, sequencer, eur, usd } = setup();
    const carried = commitAll(sequencer);
    const dropped = commitWithout(venue, sequencer, eur);

    expect(committedLogFor(eur, venue, carried)?.kind).toBe("log");
    expect(committedLogFor(eur, venue, dropped)?.kind).toBe("dropped");
    // Still carries USD, so the same state answers differently per backing.
    expect(committedLogFor(usd, venue, dropped)?.kind).toBe("log");

    const stranger = {
      snapshots: dropped.snapshots,
      commitment: signCommitment(SECRETS.mallory, 1n, stateRoot(dropped.snapshots)),
    };
    expect(committedLogFor(eur, venue, stranger)).toBeUndefined();
  });

  it("carries the sequence on both answers, because ordering needs it", () => {
    const { venue, sequencer, eur } = setup();
    const carried = commitAll(sequencer);
    const dropped = commitWithout(venue, sequencer, eur);
    expect(committedLogFor(eur, venue, carried)?.sequence).toBe(carried.commitment.sequence);
    expect(committedLogFor(eur, venue, dropped)?.sequence).toBe(dropped.commitment.sequence);
  });
});

describe("§C2b: what the venue alone still cannot see", () => {
  it("the aggravated grade stays blind, and that is the spec's own letter", () => {
    // §C2b: "No commitment past a second declared duration". The operator IS
    // committing — punctually — so on the spec's letter it is not silent. This
    // is pinned rather than fixed: whether a commitment omitting a backing
    // counts as a commitment for that backing's grade is unreadable from a root,
    // which is a question for the paper. See DECISIONS.md.
    const { venue, sequencer, eur } = setup();
    commitAll(sequencer);
    keepCommittingWithout(venue, sequencer, eur, 20);
    expect(isSilent(venue, eur)).toBe(false);
  });

  it("no holding proves against a state that dropped the backing", () => {
    const { venue, sequencer, eur } = setup();
    commitAll(sequencer);
    const dropped = keepCommittingWithout(venue, sequencer, eur, 20);
    expect(provesHolding(venue, eur, dropped, KEYS.alice, 100n)).toBe(false);
  });
});

describe("§C2: the log that vanished is the log that shrank", () => {
  it("a backing dropped from a later state is a rewritten history", () => {
    // The fault isRewrittenHistory was already for: "an append-only log may grow
    // and may not shrink". Dropping is shrinking to nothing, so it is the same
    // fault and needs no second predicate.
    const { venue, sequencer, eur } = setup();
    const carried = commitAll(sequencer);
    const dropped = commitWithout(venue, sequencer, eur);
    expect(isRewrittenHistory(eur, venue, carried, dropped)).toBe(true);
    // Symmetric in its arguments: which came first is read from the sequence.
    expect(isRewrittenHistory(eur, venue, dropped, carried)).toBe(true);
  });

  it("a backing appearing in a later state is not a rewrite", () => {
    // An operator that had not yet registered the backing committed states
    // without it. Growing from nothing is growth, and naming it a fault would
    // accuse every operator of its own first commitment.
    const { venue, sequencer, eur } = setup();
    const before = commitWithout(venue, sequencer, eur);
    venue.advance(1n);
    const after = commitAll(sequencer);
    expect(isRewrittenHistory(eur, venue, before, after)).toBe(false);
  });

  it("two states that both drop it are not a rewrite", () => {
    const { venue, sequencer, eur } = setup();
    const first = commitWithout(venue, sequencer, eur);
    venue.advance(1n);
    const second = commitWithout(venue, sequencer, eur);
    expect(isRewrittenHistory(eur, venue, first, second)).toBe(false);
  });

  it("does not accuse a RETIRED operator, which is supposed to stop carrying it", () => {
    // Found reviewing the implementation, and it is the recurring shape: the fix
    // bounded one direction and left the adjacent one open. §C2: "From the
    // effective index the old attester's co-signatures stop counting" — a
    // replaced operator goes on serving its OTHER backings, so its later
    // commitments drop this one as a matter of obedience. Naming that a fault
    // accuses a retired party for doing what the handover told it to.
    const { venue, sequencer, eur, usd } = setup();
    const beforeHandover = commitAll(sequencer);
    venue.advance(1n);
    const effective = venue.witnessedIndex() + 1n;
    venue.publishReplacement(eur.name, replacementBy(eur, SECRETS.backer, KEYS.carol, effective));
    venue.advance(2n);
    const heir = new Sequencer(SECRETS.carol, venue);
    heir.register(eur, signBacking(SECRETS.backer, eur));
    heir.takeOver(eur, beforeHandover);
    heir.commit();

    // The retired predecessor carries on with USD alone, exactly as it should.
    venue.advance(5n);
    const usdOnly = sequencer.snapshot().filter((s) => compareBytes(s.name, usd.name) === 0);
    const afterHandover = {
      snapshots: usdOnly,
      commitment: signCommitment(
        SECRETS.operator,
        venue.nextSequenceFor(KEYS.operator),
        stateRoot(usdOnly),
      ),
    };
    venue.publish(afterHandover.commitment);

    expect(isRewrittenHistory(eur, venue, beforeHandover, afterHandover)).toBe(false);
  });

  it("still accuses the operator in force, replacement rule or not", () => {
    // The other side of the same guard: a successor that takes the backing on
    // and then drops it is the fault, because it IS in force.
    const { venue, sequencer, eur } = setup();
    const beforeHandover = commitAll(sequencer);
    venue.advance(1n);
    const effective = venue.witnessedIndex() + 1n;
    venue.publishReplacement(eur.name, replacementBy(eur, SECRETS.backer, KEYS.carol, effective));
    venue.advance(2n);
    const heir = new Sequencer(SECRETS.carol, venue);
    heir.register(eur, signBacking(SECRETS.backer, eur));
    heir.takeOver(eur, beforeHandover);
    const inForce = { snapshots: heir.snapshot(), commitment: heir.commit() };

    const dropped = {
      snapshots: [],
      commitment: signCommitment(
        SECRETS.carol,
        venue.nextSequenceFor(KEYS.carol),
        stateRoot([]),
      ),
    };
    venue.publish(dropped.commitment);
    expect(isRewrittenHistory(eur, venue, inForce, dropped)).toBe(true);
  });

  it("and the proof survives the remedy, which is the point of a proof", () => {
    // Found regression-reviewing the fix above, and it was worse than the bug it
    // fixed. Reading "is this operator in force NOW" made the fault evaporate at
    // the exact moment the holder used it: the remedy for a dropped backing IS
    // replacement, so proving it, getting a successor appointed, and then asking
    // again answered false — and an operator could launder its record by
    // arranging its own succession. A fault proof is checkable by a stranger
    // forever or it is not one.
    const { venue, sequencer, eur } = setup();
    const carried = commitAll(sequencer);
    const dropped = keepCommittingWithout(venue, sequencer, eur, 3);
    expect(isRewrittenHistory(eur, venue, carried, dropped)).toBe(true);

    // Now the remedy runs: a successor is appointed and takes force.
    const effective = venue.witnessedIndex() + 1n;
    venue.publishReplacement(eur.name, replacementBy(eur, SECRETS.backer, KEYS.carol, effective));
    venue.advance(2n);
    const heir = new Sequencer(SECRETS.carol, venue);
    heir.register(eur, signBacking(SECRETS.backer, eur));
    heir.takeOver(eur, carried, dropped);
    heir.commit();

    expect(isRewrittenHistory(eur, venue, carried, dropped)).toBe(true);
  });

  it("does not accuse this operator on a stranger's state", () => {
    const { venue, sequencer, eur } = setup();
    const carried = commitAll(sequencer);
    const snapshots = carried.snapshots.filter(
      (s) => compareBytes(s.name, eur.name) !== 0,
    );
    const stranger = {
      snapshots,
      commitment: signCommitment(SECRETS.mallory, 99n, stateRoot(snapshots)),
    };
    expect(isRewrittenHistory(eur, venue, carried, stranger)).toBe(false);
  });
});

describe("§C2: a receipt read against a state that dropped the backing", () => {
  it("says dropped rather than unrelated", () => {
    // "unrelated" means "not this backing's operator's receipt, or not its
    // state", and here it is both. Answering it exonerates in the one direction
    // that matters — the holder reads it as having asked the wrong question.
    const { venue, sequencer, eur } = setup();
    const receipt = sequencer.submitTransfer(
      { backing: eur, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n },
      ed25519.sign(
        encodeTransferMessage(eur.name, KEYS.alice, KEYS.bob, 40n, 0n),
        SECRETS.alice,
      ),
    );
    const carried = commitAll(sequencer);
    const dropped = commitWithout(venue, sequencer, eur);

    expect(receiptStatus(eur, venue, receipt, carried)).toBe("witnessed");
    expect(receiptStatus(eur, venue, receipt, dropped)).toBe("dropped");
  });

  it("is not an accusation, because a receipt cannot be placed in time", () => {
    // A receipt names an operation and a position and never when it was signed
    // (slice 13), so a state committed BEFORE the backing existed drops it
    // perfectly innocently. "dropped" says what the state is, not what the
    // operator did — the fault is isRewrittenHistory's to name, and it needs two
    // states to order them.
    const { venue, sequencer, eur } = setup();
    const early = commitWithout(venue, sequencer, eur);
    venue.advance(1n);
    const receipt = sequencer.submitTransfer(
      { backing: eur, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n },
      ed25519.sign(
        encodeTransferMessage(eur.name, KEYS.alice, KEYS.bob, 40n, 0n),
        SECRETS.alice,
      ),
    );
    expect(receiptStatus(eur, venue, receipt, early)).toBe("dropped");
    expect(isRewrittenHistory(eur, venue, early, commitAll(sequencer))).toBe(false);
  });

  it("still says unrelated for a state that is not this operator's", () => {
    const { venue, sequencer, eur } = setup();
    const receipt = sequencer.submitTransfer(
      { backing: eur, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n },
      ed25519.sign(
        encodeTransferMessage(eur.name, KEYS.alice, KEYS.bob, 40n, 0n),
        SECRETS.alice,
      ),
    );
    const carried = commitAll(sequencer);
    const snapshots = carried.snapshots.filter(
      (s) => compareBytes(s.name, eur.name) !== 0,
    );
    const stranger = {
      snapshots,
      commitment: signCommitment(SECRETS.mallory, 1n, stateRoot(snapshots)),
    };
    expect(receiptStatus(eur, venue, receipt, stranger)).toBe("unrelated");
  });
});

describe("§C2b: the grade that does fire, and the state it must be asked against", () => {
  it("fires against the last state that carried the backing", () => {
    // Slice 16's test file asserted this in prose. Nothing ran it.
    const { venue, sequencer, eur } = setup();
    const lastGood = commitAll(sequencer);
    keepCommittingWithout(venue, sequencer, eur, 20);

    venue.publishOp(eur.name, request(eur, 10n, 0n));
    venue.publishOp(eur.name, request(eur, 20n, 1n));
    venue.advance(NON_SERVICE.duration + 1n);

    expect(unservedRequests(venue, eur, lastGood)).toHaveLength(2);
    expect(isNonServing(venue, eur, lastGood)).toBe(true);
  });

  it("counts nothing against a state that dropped it, and cannot", () => {
    // There is no committed log to fold the requests onto. The count is honest;
    // what was missing is that a holder handed the operator's LATEST state gets
    // this answer and must know to reach for the last one that carried it.
    const { venue, sequencer, eur } = setup();
    commitAll(sequencer);
    const dropped = keepCommittingWithout(venue, sequencer, eur, 20);
    venue.publishOp(eur.name, request(eur, 10n, 0n));
    venue.publishOp(eur.name, request(eur, 20n, 1n));
    venue.advance(NON_SERVICE.duration + 1n);

    expect(unservedRequests(venue, eur, dropped)).toHaveLength(0);
    expect(isNonServing(venue, eur, dropped)).toBe(false);
  });
});

describe("§C2: the remedy, and the successor that can now take it", () => {
  /** Fire the grade, appoint a successor, and hand back what it needs. */
  function toHandover(replaceable = true) {
    const { venue, sequencer, eur, usd } = setup(replaceable);
    const lastGood = commitAll(sequencer);
    const droppedLatest = keepCommittingWithout(venue, sequencer, eur, 20);
    venue.publishOp(eur.name, request(eur, 10n, 0n));
    venue.publishOp(eur.name, request(eur, 20n, 1n));
    venue.advance(NON_SERVICE.duration + 1n);
    return { venue, sequencer, eur, usd, lastGood, droppedLatest };
  }

  function appoint(venue: LocalVenue, eur: Backing) {
    const effective = venue.witnessedIndex() + 1n;
    venue.publishReplacement(eur.name, replacementBy(eur, SECRETS.backer, KEYS.carol, effective));
    venue.advance(2n);
    const heir = new Sequencer(SECRETS.carol, venue);
    heir.register(eur, signBacking(SECRETS.backer, eur));
    return heir;
  }

  it("takes on the last state that carried it, on evidence the latest drops it", () => {
    const { venue, eur, lastGood, droppedLatest } = toHandover();
    const heir = appoint(venue, eur);
    heir.takeOver(eur, lastGood, droppedLatest);
    expect(heir.opLog(eur)).toHaveLength(lastGood.snapshots[0]!.opLog.length);
  });

  it("and once it commits, holdings prove again — the hole closes", () => {
    // The whole point of the slice. §C2b's remedy for the non-service grade is
    // E's replacement rule, not snapshot redemption: the aggravated grade never
    // fired here, so there is no snapshot path to open. What restores the holder
    // is a successor serving.
    const { venue, eur, lastGood, droppedLatest } = toHandover();
    const heir = appoint(venue, eur);
    heir.takeOver(eur, lastGood, droppedLatest);
    const served = { snapshots: heir.snapshot(), commitment: heir.commit() };
    expect(provesHolding(venue, eur, served, KEYS.alice, 100n)).toBe(true);
  });

  it("refuses an earlier state with no evidence at all — slice 14's rule is intact", () => {
    const { venue, eur, lastGood } = toHandover();
    const heir = appoint(venue, eur);
    expect(() => heir.takeOver(eur, lastGood)).toThrow(SequencerError);
  });

  it("refuses evidence that is not the incumbent's latest commitment", () => {
    const { venue, sequencer, eur, lastGood } = toHandover();
    const heir = appoint(venue, eur);
    // A state the incumbent really committed, and really drops the backing, but
    // superseded — so it says nothing about what the incumbent serves now.
    const stale = commitWithout(venue, sequencer, eur);
    const older = { snapshots: stale.snapshots, commitment: stale.commitment };
    venue.advance(1n);
    commitWithout(venue, sequencer, eur);
    expect(() => heir.takeOver(eur, lastGood, older)).toThrow(SequencerError);
  });

  it("refuses evidence that still carries the backing", () => {
    // If the incumbent's latest carries it, there is nothing to license taking
    // an earlier state: take the latest, exactly as before.
    const { venue, sequencer, eur } = setup();
    const first = commitAll(sequencer);
    venue.advance(1n);
    sequencer.submitTransfer(
      { backing: eur, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n },
      ed25519.sign(
        encodeTransferMessage(eur.name, KEYS.alice, KEYS.bob, 40n, 0n),
        SECRETS.alice,
      ),
    );
    const latest = commitAll(sequencer);
    const heir = appoint(venue, eur);
    expect(() => heir.takeOver(eur, first, latest)).toThrow(SequencerError);
  });

  it("refuses a state that never carried the backing either", () => {
    const { venue, eur, droppedLatest } = toHandover();
    const heir = appoint(venue, eur);
    expect(() => heir.takeOver(eur, droppedLatest, droppedLatest)).toThrow(SequencerError);
  });

  it("still refuses a state that is not the incumbent's", () => {
    const { venue, eur, lastGood, droppedLatest } = toHandover();
    const heir = appoint(venue, eur);
    const snapshots = lastGood.snapshots;
    const forged = {
      snapshots,
      commitment: signCommitment(SECRETS.mallory, 1n, stateRoot(snapshots)),
    };
    expect(() => heir.takeOver(eur, forged, droppedLatest)).toThrow(SequencerError);
  });

  it("a successor that takes too old a state is caught by the same fault", () => {
    // The bound, and it is the honest one: which state was the LAST to carry the
    // backing is not readable from a root, so a successor could take an earlier
    // one. That is not licensed, it is provable — by anyone holding the later
    // state, against the successor, exactly as slice 14 extended the predicate
    // across a handover.
    const { venue, sequencer, eur } = setup();
    const first = commitAll(sequencer);
    venue.advance(1n);
    sequencer.submitTransfer(
      { backing: eur, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n },
      ed25519.sign(
        encodeTransferMessage(eur.name, KEYS.alice, KEYS.bob, 40n, 0n),
        SECRETS.alice,
      ),
    );
    const second = commitAll(sequencer);
    const droppedLatest = keepCommittingWithout(venue, sequencer, eur, 5);

    const heir = appoint(venue, eur);
    heir.takeOver(eur, first, droppedLatest);
    const successorState = { snapshots: heir.snapshot(), commitment: heir.commit() };
    expect(isRewrittenHistory(eur, venue, second, successorState)).toBe(true);
  });

  it("OPEN: a backing whose E names no replacement rule has no exit", () => {
    // Pinning a hole, not a property. The non-service grade fires and opens a
    // rule that does not exist; the aggravated grade never fires because the
    // operator publishes; so the claims freeze permanently.
    //
    // It is arguably the setting the holder read — §C2b makes replaceability
    // "answered in E" — but a holder reading "silence clause: yes" would
    // reasonably expect an exit, and this is the case where there is none. The
    // fix is not code here: it is whether §C2b's aggravated grade is read per
    // backing, which is unreadable from a root and is a question for the paper.
    const { venue, eur, lastGood } = toHandover(false);
    expect(isNonServing(venue, eur, lastGood)).toBe(true);
    expect(isSilent(venue, eur)).toBe(false);
    const heir = new Sequencer(SECRETS.carol, venue);
    expect(() => heir.register(eur, signBacking(SECRETS.backer, eur))).toThrow(SequencerError);
  });
});
