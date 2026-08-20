import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { EncodingError } from "../src/bytes.js";
import { signCommitment, stateRoot, type ServedState } from "../src/commitment.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import { type OpLogEntry, type PublishedOp } from "../src/oplog.js";
import {
  committedOutstanding,
  provesHolding,
  stateIsAuthentic,
  standingOutstanding,
} from "../src/recovery.js";
import {
  decodeRevocation,
  encodeRevocation,
  isSignedRevocation,
  revokedAt,
  signRevocation,
} from "../src/revocation.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { LocalVenue, VenueError } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// §C2b's first paragraph, and the one failure branch that had no implementation.
//
//   "If a backer's key is stolen, the damage is unbounded and permanent, since K
//   alone authorises issuance and nothing expires. So K may publish a
//   revocation: witnessed, and prospective, so existing claims keep their terms
//   and no further issuance is valid."
//
//   "It is per venue, and effective for each backing at its witnessed index on
//   that backing's declared venue, published by K to every venue its backings
//   name. The boundary is the index rather than the signing clock, so issuance
//   witnessed before the revocation stands, anything witnessed after is void,
//   and a thief's unwitnessed batch dies with it."
//
// **It is a stop-loss, not a remedy.** A thief issues fast and a backer notices
// slowly, so by the time the revocation is witnessed the fraudulent supply is
// already committed and stands. The paper says so: "the damage is unbounded and
// permanent", and "a thief's purpose is to issue, so it revokes only on the way
// out". What prevention looks like is a threshold K — §C2b: "That is the
// strongest argument for a threshold K" — which is invisible here, since t-of-n
// aggregated to one Ed25519 key leaves the name, E and strict verification
// untouched. The same shape as CLAUDE.md's one-writer rule for the operator.
//
// **Where the boundary lives.** An issuance is witnessed when a commitment
// carrying it is witnessed, and a log entry records no index of its own — so the
// rule is read between two committed states rather than per entry: once the
// revocation is witnessed at R, the outstanding that stands is the one in the
// last commitment witnessed strictly before R.
//
// **What is NOT done, and it is the whole of decision 3.** Nothing is unwound
// and no holder is told their units are void. Which units descend from a void
// issuance is provenance, ruled out in CLAUDE.md rather than deferred, and
// impossible under blinding anyway. So the code publishes ONE number about the
// BACKING — how far its committed supply exceeds what stands — and never a
// verdict about anyone's holding. Allocation was settled in P before anyone
// accepted (§18: "the excluded ingredient is discretion after the fact"), and
// invariant 19 forbids a payout that reads holder identity at all.

const SILENCE = { noCommitmentDuration: 20n, challengeWindow: 5n };

function setup(declareVenue = true) {
  const venue = new LocalVenue();
  const backing = makeBacking({
    obligor: KEYS.backer,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: {
      setting: "transparent",
      operator: KEYS.operator,
      silence: SILENCE,
      ...(declareVenue ? { witnessing: { venue: venue.id, interval: 5n } } : {}),
    },
  });
  const sequencer = new Sequencer(SECRETS.operator, venue);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  return { venue, sequencer, backing };
}

/** The obligor issues `quantity` to Alice at its next nonce. */
function issue(sequencer: Sequencer, backing: Backing, quantity: bigint) {
  const nonce = sequencer.nextNonce(KEYS.backer, backing);
  return sequencer.submitIssue(
    { backing, recipient: KEYS.alice, quantity, nonce },
    ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, quantity, nonce), SECRETS.backer),
  );
}

function commitAll(sequencer: Sequencer): ServedState {
  return { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
}

describe("§C2b: a revocation is K's own signature over K", () => {
  it("round-trips as a record, both ways", () => {
    // Slice 15's rule for anything a venue holds: decode(encode(x)) is x, so
    // nothing is lost, and encode(decode(bytes)) is bytes, so a record has
    // exactly one spelling.
    const revocation = signRevocation(SECRETS.backer);
    const bytes = encodeRevocation(revocation);
    const back = decodeRevocation(bytes);
    expect(back.obligor).toEqual(revocation.obligor);
    expect(back.signature).toEqual(revocation.signature);
    expect(encodeRevocation(back)).toEqual(bytes);
  });

  it("carries no sequence, no venue and no expiry, because it cannot be undone", () => {
    // "Revocation is the one act no later signature can repair", so there is
    // nothing to order and nothing to relay wrongly: two revocations by one key
    // are byte-identical, and anyone may copy one to another venue, which is
    // what "published by K to every venue its backings name" wants.
    expect(encodeRevocation(signRevocation(SECRETS.backer))).toEqual(
      encodeRevocation(signRevocation(SECRETS.backer)),
    );
    expect(encodeRevocation(signRevocation(SECRETS.backer))).toHaveLength(32 + 64);
  });

  it("is valid only under the key it revokes", () => {
    expect(isSignedRevocation(signRevocation(SECRETS.backer))).toBe(true);
    const forged = {
      obligor: KEYS.backer,
      signature: signRevocation(SECRETS.mallory).signature,
    };
    expect(isSignedRevocation(forged)).toBe(false);
  });

  it("answers on hostile input rather than throwing", () => {
    // A verifier: the bytes come from whoever exhibits them.
    expect(isSignedRevocation({ obligor: new Uint8Array(3), signature: new Uint8Array(64) })).toBe(
      false,
    );
    expect(isSignedRevocation(undefined as never)).toBe(false);
    expect(() => decodeRevocation(new Uint8Array(10))).toThrow(EncodingError);
    expect(() => decodeRevocation(new Uint8Array(97))).toThrow(EncodingError);
  });
});

describe("§C2b: when a revocation takes effect", () => {
  it("is not revoked until one is witnessed", () => {
    const { venue, backing } = setup();
    expect(revokedAt(venue, backing)).toBeUndefined();
  });

  it("takes effect at the index the venue witnessed it", () => {
    const { venue, backing } = setup();
    venue.advance(7n);
    venue.publishRevocation(signRevocation(SECRETS.backer));
    expect(revokedAt(venue, backing)).toBe(7n);
  });

  it("the earliest witnessed wins, because the act cannot be undone", () => {
    const { venue, backing } = setup();
    venue.advance(4n);
    venue.publishRevocation(signRevocation(SECRETS.backer));
    venue.advance(10n);
    venue.publishRevocation(signRevocation(SECRETS.backer));
    expect(revokedAt(venue, backing)).toBe(4n);
  });

  it("refuses a revocation that is not signed by the key it names", () => {
    const { venue, backing } = setup();
    expect(() =>
      venue.publishRevocation({
        obligor: KEYS.backer,
        signature: signRevocation(SECRETS.mallory).signature,
      }),
    ).toThrow(VenueError);
    expect(revokedAt(venue, backing)).toBeUndefined();
  });

  it("says nothing about a backing whose declared venue this is not", () => {
    // A grade is read on the backing's declared venue (§C2b), and a revocation
    // is "effective for each backing at its witnessed index on that backing's
    // declared venue". The same rule, so the same guard.
    const { venue } = setup();
    const elsewhere = new LocalVenue(new Uint8Array(32).fill(9));
    const backing = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: SILENCE,
        witnessing: { venue: elsewhere.id, interval: 5n },
      },
    });
    venue.publishRevocation(signRevocation(SECRETS.backer));
    expect(revokedAt(venue, backing)).toBeUndefined();
  });

  it("revokes the KEY, so every backing that key obligates is revoked at once", () => {
    // The record names K and no backing, because "published by K to every venue
    // its backings name" is about a key and one K backs many backings. It is the
    // one venue record that does not name a backing, deliberately.
    const { venue, backing } = setup();
    const other = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "USD", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: SILENCE,
        witnessing: { venue: venue.id, interval: 5n },
      },
    });
    const untouched = makeBacking({
      obligor: KEYS.backer2,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: SILENCE,
        witnessing: { venue: venue.id, interval: 5n },
      },
    });
    venue.advance(3n);
    venue.publishRevocation(signRevocation(SECRETS.backer));
    expect(revokedAt(venue, backing)).toBe(3n);
    expect(revokedAt(venue, other)).toBe(3n);
    expect(revokedAt(venue, untouched)).toBeUndefined();
  });
});

describe("§C2b: prospective — existing claims keep their terms", () => {
  it("the operator refuses further issuance", () => {
    const { venue, sequencer, backing } = setup();
    issue(sequencer, backing, 100n);
    venue.publishRevocation(signRevocation(SECRETS.backer));
    expect(() => issue(sequencer, backing, 50n)).toThrow(SequencerError);
  });

  it("but transfers, burns and presentation of existing claims go on", () => {
    // "existing claims keep their terms" — only issuance is void. Reaching
    // further would freeze the holders the revocation exists to protect.
    const { venue, sequencer, backing } = setup();
    issue(sequencer, backing, 100n);
    venue.publishRevocation(signRevocation(SECRETS.backer));

    const nonce = sequencer.nextNonce(KEYS.alice, backing);
    expect(() =>
      sequencer.submitTransfer(
        { backing, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce },
        ed25519.sign(
          encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 40n, nonce),
          SECRETS.alice,
        ),
      ),
    ).not.toThrow();
    expect(sequencer.balance(backing, KEYS.bob)).toBe(40n);
  });

  it("and a revoked backing can still be taken on by an operator", () => {
    // Registering is not issuing. An operator that could not serve a revoked
    // backing would strand every holder of it.
    const { venue, backing } = setup();
    venue.publishRevocation(signRevocation(SECRETS.backer));
    const fresh = new Sequencer(SECRETS.operator, venue);
    expect(() => fresh.register(backing, signBacking(SECRETS.backer, backing))).not.toThrow();
  });

  it("the tie at the revocation's own index goes against the operator", () => {
    // §C2b's boundary rule, and the same tie slice 8 resolved: a publication is
    // judged against the record as it stood strictly before its own index, and
    // the tie must not go to the party watching. The operator watches.
    const { venue, sequencer, backing } = setup();
    venue.advance(5n);
    venue.publishRevocation(signRevocation(SECRETS.backer));
    expect(revokedAt(venue, backing)).toBe(5n);
    expect(() => issue(sequencer, backing, 10n)).toThrow(SequencerError);
  });
});

/**
 * A dishonest operator's log: whatever it has served, plus an issuance it should
 * have refused. Built by hand because `submitIssue` refuses it — which is the
 * point — and because a test-only door on Sequencer is exactly the privileged
 * path invariant 8 says must not exist.
 */
function withIssuance(
  log: readonly OpLogEntry[],
  backing: Backing,
  quantity: bigint,
  nonce: bigint,
): OpLogEntry[] {
  const op: PublishedOp = {
    kind: "issue",
    recipient: KEYS.alice,
    quantity,
    nonce,
    signature: ed25519.sign(
      encodeIssuanceMessage(backing.name, KEYS.alice, quantity, nonce),
      SECRETS.backer,
    ),
  };
  return [...log, { ...op, position: log.length }];
}

/** Commit a hand-built log as this operator's next commitment, and publish it. */
function publishState(
  venue: LocalVenue,
  backing: Backing,
  opLog: readonly OpLogEntry[],
): ServedState {
  const snapshots = [{ name: backing.name, opLog }];
  const commitment = signCommitment(
    SECRETS.operator,
    venue.nextSequenceFor(KEYS.operator),
    stateRoot(snapshots),
  );
  venue.publish(commitment);
  return { snapshots, commitment };
}

/** 100 issued and committed, then revoked, then 900 more issued past the boundary. */
function toTheft() {
  const { venue, sequencer, backing } = setup();
  issue(sequencer, backing, 100n);
  venue.advance(5n);
  const boundary = commitAll(sequencer);

  venue.advance(5n);
  venue.publishRevocation(signRevocation(SECRETS.backer));
  venue.advance(5n);

  const stolen = withIssuance(sequencer.opLog(backing), backing, 900n, 1n);
  const after = publishState(venue, backing, stolen);
  return { venue, sequencer, backing, boundary, after, stolen };
}

describe("§C2b: the boundary, and the one number it publishes", () => {
  it("the standing outstanding is the count at the last commitment before R", () => {
    const { venue, backing, boundary } = toTheft();
    expect(standingOutstanding(backing, venue, boundary)).toBe(100n);
  });

  it("and the committed outstanding shows how far the supply ran past it", () => {
    const { venue, backing, boundary, after } = toTheft();
    const standing = standingOutstanding(backing, venue, boundary) as bigint;
    const committed = committedOutstanding(backing, venue, after) as bigint;
    expect(committed).toBe(1000n);
    // The one number this slice publishes: the backing is short by this much.
    // Not whose units are void — that is provenance, and it is ruled out.
    expect(committed - standing).toBe(900n);
  });

  it("refuses a state that is not the last commitment before R", () => {
    // Otherwise a holder could pick any older state and understate the supply,
    // or the operator could pick a later one and hide the excess.
    const { venue, backing, after } = toTheft();
    expect(standingOutstanding(backing, venue, after)).toBeUndefined();
  });

  it("answers undefined where the backing is not revoked at all", () => {
    const { venue, sequencer, backing } = setup();
    issue(sequencer, backing, 100n);
    const served = commitAll(sequencer);
    expect(standingOutstanding(backing, venue, served)).toBeUndefined();
    expect(committedOutstanding(backing, venue, served)).toBe(100n);
  });

  it("a commitment witnessed exactly at R is not before R", () => {
    const { venue, sequencer, backing } = setup();
    issue(sequencer, backing, 100n);
    venue.advance(3n);
    const before = commitAll(sequencer);
    venue.advance(2n);
    venue.publishRevocation(signRevocation(SECRETS.backer));
    const at = commitAll(sequencer);
    expect(standingOutstanding(backing, venue, at)).toBeUndefined();
    expect(standingOutstanding(backing, venue, before)).toBe(100n);
  });
});

describe("§C2b: void, not a fault, and nothing is unwound", () => {
  it("the operator's committed history stays authentic", () => {
    // Decision 4. An honest operator can hold an accepted-but-uncommitted
    // issuance when the revocation lands, and committing it afterwards is not
    // misconduct — the issuance is void either way. Refusing the replay would
    // accuse the wrong party, and worse: replayLog returning undefined makes
    // stateIsAuthentic and provesHolding false for EVERY holder of the backing,
    // including ones whose units predate the theft by years.
    const { venue, backing, after } = toTheft();
    expect(stateIsAuthentic(backing, venue, after)).toBe(true);
  });

  it("and nothing is unwound: the void units sit in the balance like any other", () => {
    // Decision 3, operationally. No clawback (invariant 8), no re-fold, and no
    // per-holder verdict — there is no such answer to give. The shortfall is a
    // number about the BACKING, published beside the balances rather than
    // subtracted from any of them.
    const { venue, backing, after } = toTheft();
    expect(provesHolding(venue, backing, after, KEYS.alice, 1000n)).toBe(true);
  });

  it("invariant 19's payout reads the standing count, or a caught thief still dilutes", () => {
    // The gap this slice found in the paper. A payout declining in the backing's
    // own outstanding count (invariant 19) collapses as the count rises. If it
    // read the committed count, a thief who has already been caught and revoked
    // could keep issuing and drive every honest holder's payout toward zero, in
    // public, for free. The standing count is checkable, so it satisfies
    // invariant 19's "published" condition, and it does not move.
    const { venue, backing, boundary, stolen } = toTheft();
    expect(standingOutstanding(backing, venue, boundary)).toBe(100n);
    venue.advance(5n);
    publishState(venue, backing, withIssuance(stolen, backing, 10_000n, 2n));
    expect(standingOutstanding(backing, venue, boundary)).toBe(100n);
  });
});
