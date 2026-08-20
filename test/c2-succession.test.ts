import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { signCommitment, stateRoot } from "../src/commitment.js";
import {
  isAnOperator,
  operatorAt,
  operatorsOf,
  replacementHash,
  replacementMessage,
  ROLE_OPERATOR,
  type Replacement,
} from "../src/replacement.js";
import { isRewrittenHistory } from "../src/fault.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import { receiptStatus } from "../src/receipt.js";
import { isOverdue, isSilent, stateIsAuthentic } from "../src/recovery.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { Venue, VenueError } from "../src/venue.js";
import { KEYS, pub, SECRETS } from "./support.js";

// §C2, succession: "A replacement is itself a witnessed object. It is signed by
// whoever E's rule names, the backer by default, states the role, the successor
// and the effective index... Each replacement names its predecessor, so the
// chain from the original terms is walkable. Its effective index is no earlier
// than the index at which it is itself witnessed, and it takes effect only from
// the first index at which it has published its own commitment... Until then the
// predecessor's last commitment governs... From the effective index the old
// attester's co-signatures stop counting, which is why a wallet verifies the
// chain rather than the key it remembers."
//
// E's operator sits inside the name and invariant 1 forbids an edit, so a
// replacement does not change it — it supersedes it on a record anyone can walk.
// That is how the venue and the operator "move only under its replacement rule"
// while both stay inside the hash.
//
// **What this slice does NOT do:** let the successor serve. Registering,
// co-signing and adopting the predecessor's log are the successor's side of the
// handover, and they need the tail the predecessor left. The chain is declared,
// walkable, and read by the verifiers that ask who is in force; Sequencer still
// serves only the key E names. See DECISIONS.md.

const SILENCE = { noCommitmentDuration: 10n, challengeWindow: 5n };
const SUCCESSOR_SECRET = new Uint8Array(32).fill(0x0b);
const SUCCESSOR = pub(SUCCESSOR_SECRET);
const THIRD_SECRET = new Uint8Array(32).fill(0x0c);
const THIRD = pub(THIRD_SECRET);

/** A backing whose replacement rule is the backer's own key — §C2's default. */
function setup(replaceable = true) {
  const venue = new Venue();
  const backing = makeBacking({
    obligor: KEYS.backer,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: {
      setting: "transparent",
      operator: KEYS.operator,
      silence: SILENCE,
      ...(replaceable ? { replacementRule: KEYS.backer } : {}),
    },
  });
  return { venue, backing };
}

function replacementBy(
  backing: Backing,
  ruleSecret: Uint8Array,
  successor: Uint8Array,
  predecessor: Uint8Array,
  effective: bigint,
): Replacement {
  const unsigned = {
    role: ROLE_OPERATOR,
    successor,
    predecessor,
    effective,
    signature: new Uint8Array(64),
  };
  const signature = ed25519.sign(replacementMessage(backing.name, unsigned), ruleSecret);
  return { ...unsigned, signature };
}

/** Put a commitment from `secret` at the venue — what gives a successor force. */
function commitAs(venue: Venue, secret: Uint8Array): void {
  const operator = ed25519.getPublicKey(secret);
  venue.publish(signCommitment(secret, venue.nextSequenceFor(operator), stateRoot([])));
}

function at(venue: Venue, index: bigint): void {
  const now = venue.witnessedIndex();
  if (index > now) venue.advance(index - now);
}

describe("§C2: the chain from the original terms is walkable", () => {
  it("starts at the key E names, and stays there with no replacement", () => {
    const { venue, backing } = setup();
    expect(operatorsOf(backing, venue)).toHaveLength(1);
    expect(operatorAt(backing, venue, 0n)).toEqual(KEYS.operator);
    expect(operatorAt(backing, venue, 10_000n)).toEqual(KEYS.operator);
  });

  it("hands over at the later of the effective index and the successor's first commitment", () => {
    // §C2's two-stage rule. Declaring an index does not hand anything over; the
    // successor must have published a commitment of its own.
    const { venue, backing } = setup();
    at(venue, 5n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 10n));
    at(venue, 10n);
    // Effective index reached, but the successor has committed nothing.
    expect(operatorAt(backing, venue, 10n)).toEqual(KEYS.operator);
    at(venue, 20n);
    commitAs(venue, SUCCESSOR_SECRET);
    expect(operatorAt(backing, venue, 19n)).toEqual(KEYS.operator);
    expect(operatorAt(backing, venue, 20n)).toEqual(SUCCESSOR);
  });

  it("ignores a successor commitment made before anyone named it", () => {
    // Otherwise the second stage means nothing for a successor that already
    // operates something else: it would arrive already in force.
    const { venue, backing } = setup();
    commitAs(venue, SUCCESSOR_SECRET);
    at(venue, 5n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 10n));
    at(venue, 10n);
    expect(operatorAt(backing, venue, 10n)).toEqual(KEYS.operator);
    // A fresh one, after the handover was witnessed, is the one §C2 asks for.
    commitAs(venue, SUCCESSOR_SECRET);
    expect(operatorAt(backing, venue, 10n)).toEqual(SUCCESSOR);
  });

  it("walks a chain of two handovers", () => {
    const { venue, backing } = setup();
    const first = replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 5n);
    at(venue, 5n);
    venue.publishReplacement(backing.name, first);
    commitAs(venue, SUCCESSOR_SECRET);
    at(venue, 20n);
    venue.publishReplacement(
      backing.name,
      replacementBy(backing, SECRETS.backer, THIRD, replacementHash(backing.name, first), 20n),
    );
    commitAs(venue, THIRD_SECRET);

    expect(operatorsOf(backing, venue)).toHaveLength(3);
    expect(operatorAt(backing, venue, 4n)).toEqual(KEYS.operator);
    expect(operatorAt(backing, venue, 19n)).toEqual(SUCCESSOR);
    expect(operatorAt(backing, venue, 20n)).toEqual(THIRD);
    expect(isAnOperator(backing, venue, KEYS.operator)).toBe(true);
    expect(isAnOperator(backing, venue, THIRD)).toBe(true);
    expect(isAnOperator(backing, venue, KEYS.mallory)).toBe(false);
  });
});

describe("§C2: a replacement counts only on the terms E set", () => {
  it("counts nothing where E declares no replacement rule", () => {
    // §C2b: "Whether a sequencer can be replaced at all is answered in E."
    const { venue, backing } = setup(false);
    const replaceable = setup(true).backing;
    // Signed correctly for the OTHER backing's rule, and published here.
    venue.publishReplacement(
      backing.name,
      replacementBy(replaceable, SECRETS.backer, SUCCESSOR, replaceable.name, 0n),
    );
    commitAs(venue, SUCCESSOR_SECRET);
    at(venue, 10n);
    expect(operatorAt(backing, venue, 10n)).toEqual(KEYS.operator);
  });

  it("ignores a replacement signed by anyone but the rule's key", () => {
    const { venue, backing } = setup();
    venue.publishReplacement(
      backing.name,
      replacementBy(backing, SECRETS.mallory, SUCCESSOR, backing.name, 0n),
    );
    commitAs(venue, SUCCESSOR_SECRET);
    at(venue, 10n);
    expect(operatorAt(backing, venue, 10n)).toEqual(KEYS.operator);
  });

  it("ignores a replacement that names the wrong predecessor", () => {
    // The chain is hash-linked, so a link that attaches to nothing is not a
    // link. Walking backwards from any replacement reaches the original terms
    // or nothing at all.
    const { venue, backing } = setup();
    venue.publishReplacement(
      backing.name,
      replacementBy(backing, SECRETS.backer, SUCCESSOR, new Uint8Array(32).fill(0xee), 0n),
    );
    commitAs(venue, SUCCESSOR_SECRET);
    at(venue, 10n);
    expect(operatorAt(backing, venue, 10n)).toEqual(KEYS.operator);
  });

  it("refuses a replacement effective before it was itself witnessed", () => {
    // §C2: "Its effective index is no earlier than the index at which it is
    // itself witnessed." The rule-holder does not get to backdate a handover,
    // which would put two operators in force at one past index.
    const { venue, backing } = setup();
    at(venue, 50n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 49n));
    commitAs(venue, SUCCESSOR_SECRET);
    at(venue, 60n);
    expect(operatorAt(backing, venue, 60n)).toEqual(KEYS.operator);
  });

  it("refuses a handover to the incumbent itself", () => {
    const { venue, backing } = setup();
    at(venue, 5n);
    venue.publishReplacement(
      backing.name,
      replacementBy(backing, SECRETS.backer, KEYS.operator, backing.name, 5n),
    );
    commitAs(venue, SECRETS.operator);
    at(venue, 10n);
    expect(operatorsOf(backing, venue)).toHaveLength(1);
  });

  it("takes the earliest witnessed where the rule-holder signed two successors", () => {
    // Two replacements naming one predecessor are the rule-holder choosing
    // twice, and the one it published first is the one it chose first —
    // witnessing pins order (§C2), the rule two requests at one nonce follow.
    const { venue, backing } = setup();
    at(venue, 5n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 5n));
    at(venue, 6n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, THIRD, backing.name, 6n));
    commitAs(venue, SUCCESSOR_SECRET);
    commitAs(venue, THIRD_SECRET);
    at(venue, 20n);
    expect(operatorAt(backing, venue, 20n)).toEqual(SUCCESSOR);
  });
});

describe("§C2: the grade follows the incumbent", () => {
  it("measures silence on the operator in force, not the key E names", () => {
    const { venue, backing } = setup();
    at(venue, 5n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 5n));
    commitAs(venue, SUCCESSOR_SECRET);
    // The genesis operator has published nothing at all and would be silent;
    // the successor just committed, so the backing is not.
    expect(operatorAt(backing, venue, venue.witnessedIndex())).toEqual(SUCCESSOR);
    expect(isSilent(venue, backing)).toBe(false);
    expect(isOverdue(venue, backing)).toBe(false);
  });

  it("grades the successor once IT goes quiet", () => {
    const { venue, backing } = setup();
    at(venue, 5n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 5n));
    commitAs(venue, SUCCESSOR_SECRET);
    at(venue, 5n + SILENCE.noCommitmentDuration + 1n);
    expect(isSilent(venue, backing)).toBe(true);
  });
});

describe("§C2: the venue records a replacement and judges nothing", () => {
  it("refuses a replacement whose bytes do not encode", () => {
    const { venue, backing } = setup();
    expect(() =>
      venue.publishReplacement(backing.name, {
        role: ROLE_OPERATOR,
        successor: new Uint8Array(31),
        predecessor: backing.name,
        effective: 0n,
        signature: new Uint8Array(64),
      }),
    ).toThrow(VenueError);
    expect(venue.replacementsFor(backing.name)).toHaveLength(0);
  });

  it("hands out copies, in and out", () => {
    // Its own copy of the key, because this test mutates what it hands over and
    // SUCCESSOR is shared across the file.
    const { venue, backing } = setup();
    const published = replacementBy(backing, SECRETS.backer, Uint8Array.from(SUCCESSOR), backing.name, 0n);
    venue.publishReplacement(backing.name, published);
    published.successor.fill(0xff);
    const first = venue.replacementsFor(backing.name)[0]!.replacement;
    expect(first.successor).toEqual(SUCCESSOR);
    first.successor.fill(0xff);
    expect(venue.replacementsFor(backing.name)[0]!.replacement.successor).toEqual(SUCCESSOR);
  });

  it("leaves a successor that has never committed out of the chain", () => {
    const { venue, backing } = setup();
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 0n));
    // Published, signed by the rule, effective now — and still not in force,
    // because §C2 gives it force only from its own first commitment.
    expect(venue.replacementsFor(backing.name)).toHaveLength(1);
    expect(operatorAt(backing, venue, 0n)).toEqual(KEYS.operator);
    expect(isAnOperator(backing, venue, SUCCESSOR)).toBe(false);
  });
});

describe("§C2: a successor serves, and only once it is in force", () => {
  /** The incumbent, holding Alice's 100 with 40 already moved to Bob. */
  function incumbentServing(venue: Venue, backing: Backing) {
    const server = new Sequencer(SECRETS.operator, venue);
    server.register(backing, signBacking(SECRETS.backer, backing));
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    const issued = server.submitIssue(
      issue,
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
    );
    server.submitTransfer(
      { backing, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n },
      ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 40n, 0n), SECRETS.alice),
    );
    return { server, issued, served: { snapshots: server.snapshot(), commitment: server.commit() } };
  }

  function handedOver() {
    const { venue, backing } = setup();
    const incumbent = incumbentServing(venue, backing);
    at(venue, 5n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 5n));
    const successor = new Sequencer(SUCCESSOR_SECRET, venue);
    successor.register(backing, signBacking(SECRETS.backer, backing));
    return { venue, backing, incumbent, successor };
  }

  it("lets a named successor serve before it is in force, and refuses its receipts", () => {
    // §C2's two stages have a gap somebody has to live in: force comes from the
    // successor's own first commitment, and it cannot commit a state it was
    // never allowed to take on. So it may serve, and "no new co-signatures
    // issue" until it is in force.
    const { venue, backing, incumbent, successor } = handedOver();
    expect(operatorAt(backing, venue, venue.witnessedIndex())).toEqual(KEYS.operator);
    successor.takeOver(backing, incumbent.served);
    expect(() =>
      successor.submitTransfer(
        { backing, from: KEYS.alice, to: KEYS.carol, quantity: 10n, nonce: 1n },
        ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.carol, 10n, 1n), SECRETS.alice),
      ),
    ).toThrow(SequencerError);
  });

  it("takes force on its own first commitment, carrying the state it took over", () => {
    const { venue, backing, incumbent, successor } = handedOver();
    successor.takeOver(backing, incumbent.served);
    successor.commit();

    expect(operatorAt(backing, venue, venue.witnessedIndex())).toEqual(SUCCESSOR);
    expect(successor.balance(backing, KEYS.alice)).toBe(60n);
    expect(successor.balance(backing, KEYS.bob)).toBe(40n);
    expect(successor.outstanding(backing)).toBe(100n);
    // And it serves: the next operation is the claimant's next nonce, on the
    // state the predecessor left.
    const receipt = successor.submitTransfer(
      { backing, from: KEYS.alice, to: KEYS.carol, quantity: 10n, nonce: 1n },
      ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.carol, 10n, 1n), SECRETS.alice),
    );
    expect(receipt.position).toBe(2n);
  });

  it("stops the predecessor co-signing once the handover has happened", () => {
    // "From the effective index the old attester's co-signatures stop counting."
    // Refused at the source as well as discounted by a reader.
    const { venue, backing, incumbent, successor } = handedOver();
    successor.takeOver(backing, incumbent.served);
    successor.commit();
    expect(operatorAt(backing, venue, venue.witnessedIndex())).toEqual(SUCCESSOR);
    expect(() =>
      incumbent.server.submitTransfer(
        { backing, from: KEYS.alice, to: KEYS.carol, quantity: 10n, nonce: 1n },
        ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.carol, 10n, 1n), SECRETS.alice),
      ),
    ).toThrow(SequencerError);
  });

  it("keeps the predecessor's receipts good against both committed states", () => {
    // A receipt records an operation and a position and never when it was
    // signed, so a retired operator's co-signature over an operation its own log
    // really held stays evidence of what it accepted. And the successor's log
    // holds the same entries at the same positions, because it took them on.
    const { venue, backing, incumbent, successor } = handedOver();
    successor.takeOver(backing, incumbent.served);
    successor.commit();
    const theirs = { snapshots: successor.snapshot(), commitment: venue.latestFor(SUCCESSOR)! };

    expect(receiptStatus(backing, venue, incumbent.issued, incumbent.served)).toBe("witnessed");
    expect(receiptStatus(backing, venue, incumbent.issued, theirs)).toBe("witnessed");
    expect(stateIsAuthentic(backing, venue, theirs)).toBe(true);
  });

  it("reads an honest handover as no rewritten history", () => {
    // The successor's log starts where the predecessor's committed state left
    // off, so comparing across a handover must not report a takeover as a
    // rewrite — which is why the predicate is about one operator's own history.
    const { venue, backing, incumbent, successor } = handedOver();
    successor.takeOver(backing, incumbent.served);
    successor.commit();
    const theirs = { snapshots: successor.snapshot(), commitment: venue.latestFor(SUCCESSOR)! };
    expect(isRewrittenHistory(backing, venue, incumbent.served, theirs)).toBe(false);
  });

  it("refuses a takeover of anything but the incumbent's latest committed state", () => {
    const { venue, backing, incumbent, successor } = handedOver();
    // A state nobody committed.
    expect(() =>
      successor.takeOver(backing, {
        snapshots: incumbent.served.snapshots,
        commitment: signCommitment(SECRETS.mallory, 0n, stateRoot(incumbent.served.snapshots)),
      }),
    ).toThrow(SequencerError);
    // And once in force, there is nothing left to take over.
    successor.takeOver(backing, incumbent.served);
    successor.commit();
    expect(() => successor.takeOver(backing, incumbent.served)).toThrow(SequencerError);
  });

  it("refuses a sequencer that is neither in force nor named", () => {
    const { venue, backing } = setup();
    const stranger = new Sequencer(THIRD_SECRET, venue);
    expect(() => stranger.register(backing, signBacking(SECRETS.backer, backing))).toThrow(
      SequencerError,
    );
  });
});

describe("§C2: a successor that does not serve the state in full", () => {
  it("is a rewritten history, even though the log is not its own", () => {
    // §C2 gives a successor force only over a state "it serves in full". A
    // successor committing a shorter log than the predecessor's is the same
    // fault by the party the chain just handed the backing to — so the
    // predicate has to reach across a handover, and the chain is what orders
    // the two states, since a sequence is an operator's own count.
    const { venue, backing } = setup();
    const incumbent = new Sequencer(SECRETS.operator, venue);
    incumbent.register(backing, signBacking(SECRETS.backer, backing));
    incumbent.submitIssue(
      { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
    );
    const served = { snapshots: incumbent.snapshot(), commitment: incumbent.commit() };

    at(venue, 5n);
    venue.publishReplacement(backing.name, replacementBy(backing, SECRETS.backer, SUCCESSOR, backing.name, 5n));
    // The successor commits an EMPTY log for this backing rather than the one
    // it was handed, and takes force on it.
    const dropped = [{ name: backing.name, opLog: [] }];
    const theirs = {
      snapshots: dropped,
      commitment: signCommitment(SUCCESSOR_SECRET, 0n, stateRoot(dropped)),
    };
    venue.publish(theirs.commitment);

    expect(operatorAt(backing, venue, venue.witnessedIndex())).toEqual(SUCCESSOR);
    expect(isRewrittenHistory(backing, venue, served, theirs)).toBe(true);
    expect(isRewrittenHistory(backing, venue, theirs, served)).toBe(true);
  });
});
