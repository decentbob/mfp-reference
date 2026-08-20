import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, type Backing } from "../src/backing.js";
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
import { isOverdue, isSilent } from "../src/recovery.js";
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
