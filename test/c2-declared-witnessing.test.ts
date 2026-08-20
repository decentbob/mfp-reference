import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { signBacking, type Backing } from "../src/backing.js";
import { encodeIssuance } from "../src/messages.js";
import {
  encodeAcceptanceMessage,
  encodeDemandMessage,
  encodeReleaseMessage,
} from "../src/presentation.js";
import {
  isOverdue,
  isSilent,
  provesHolding,
  snapshotRedemptions,
  venueIsDeclared,
} from "../src/recovery.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// §C2: "At the declared interval each publishes a small commitment to a widely
// witnessed venue... Venue and attester are named in E and move only under its
// replacement rule." And the glossary's own field list has E declaring "who
// currently attests a claim unspent, the venue it commits to, **the witness
// interval**, the replacement rule, the claim-layer setting and its
// construction... and the silence clause".
//
// Ours declared the operator key and the silence clause, and neither of the
// other two. That cost two different things.
//
//   - **The venue.** §C2b makes a grade effective "for each backing at its
//     witnessed index on that backing's declared venue", and the whole reason a
//     grade works is that it is a fact a stranger checks against the published
//     record — something a backer concedes rather than argues. Measured against
//     whichever venue the caller happened to pass, it is a fact about who you
//     asked: two holders with two venues get two grades for one backing and
//     neither is wrong. That is a soundness gap, not a missing convenience.
//   - **The interval.** §C2: "Short intervals cost fees, long ones cost
//     exposure, and there is no third option, which is why the interval is a
//     signed field rather than operational discretion." A payment is final when
//     witnessed rather than co-signed (CLAUDE.md, and §C2's own "Finality means
//     witnessed rather than co-signed"), so a payee waiting for the next
//     commitment needs to know how long that is. Without it they can measure
//     how stale the last commitment is and cannot tell a fast operator running
//     late from a slow one running on time.
//
// Both go inside the name, so neither is the operator's to edit (invariant 1),
// and both are optional in the same way the silence clause is: a backing that
// declares no venue is graded against whichever record you hold, which is the
// backer's choice and the holder's to read before accepting.
//
// The finality rule §C2 pairs a venue with — "the depth or gadget under which an
// index counts as witnessed there" — is NOT declared here. This Venue has
// immediate finality and says so, so the rule has nothing to say yet, and a tag
// carries only what this slice enforces (the tag-0x02 rule). The venue is an
// opaque 32-byte identity for the same reason the operator key was one in slice
// 1: E names it, the code checks it matches, and what it MEANS is elsewhere.

const INTERVAL = 10n;
const SILENCE = { noCommitmentDuration: 50n, challengeWindow: 5n };
const VENUE = sha256(new TextEncoder().encode("venue/one"));
const OTHER_VENUE = sha256(new TextEncoder().encode("venue/two"));

/** A backing that declares a venue and an interval, served by a sequencer on it. */
function setup(
  venueId: Uint8Array = VENUE,
  witnessing: { venue: Uint8Array; interval: bigint } | undefined = {
    venue: VENUE,
    interval: INTERVAL,
  },
) {
  const venue = new Venue(venueId);
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], SILENCE, witnessing);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { venue, sequencer, backing };
}

/**
 * The whole §C2b payment path — claim, acceptance, release — published at `v`
 * at fixed indices, so two venues can be given byte-identical records and the
 * only difference between them is which one E names.
 */
function redeemAt(v: Venue, backing: Backing): void {
  const at = (i: bigint) => {
    const now = v.witnessedIndex();
    if (i > now) v.advance(i - now);
  };
  const claim = encodeDemandMessage(backing.name, KEYS.alice, 100n, 51n, 200n, 0n);
  at(51n);
  v.publishOp(backing.name, {
    kind: "demand",
    holder: KEYS.alice,
    quantity: 100n,
    instant: 51n,
    deadline: 200n,
    nonce: 0n,
    signature: ed25519.sign(claim, SECRETS.alice),
  });
  const hash = sha256(claim);
  at(52n);
  v.publishOp(backing.name, {
    kind: "acceptance",
    demandHash: hash,
    instant: 51n,
    deadline: 200n,
    nonce: 1n,
    signature: ed25519.sign(
      encodeAcceptanceMessage(backing.name, hash, 51n, 200n, 1n),
      SECRETS.backer,
    ),
  });
  at(53n);
  v.publishOp(backing.name, {
    kind: "release",
    demandHash: hash,
    nonce: 1n,
    signature: ed25519.sign(encodeReleaseMessage(backing.name, hash, 1n), SECRETS.alice),
  });
}

describe("§C2: the witness interval is declared, so lateness is a public fact", () => {
  it("is not overdue while the operator commits inside its own interval", () => {
    const { venue, sequencer, backing } = setup();
    sequencer.commit();
    venue.advance(INTERVAL);
    expect(isOverdue(venue, backing)).toBe(false);
  });

  it("is overdue one index past the interval, and not before", () => {
    // The boundary is the declared term itself: quiet for exactly the interval
    // is on time, one more is late.
    const { venue, sequencer, backing } = setup();
    sequencer.commit();
    venue.advance(INTERVAL);
    expect(isOverdue(venue, backing)).toBe(false);
    venue.advance(1n);
    expect(isOverdue(venue, backing)).toBe(true);
  });

  it("counts from the venue's genesis where the operator has never committed", () => {
    // Measured only from an existing commitment, never publishing at all would
    // be the way to look punctual forever — the same reason quietFor counts
    // from genesis.
    const { venue, backing } = setup();
    venue.advance(INTERVAL + 1n);
    expect(isOverdue(venue, backing)).toBe(true);
  });

  it("stops being overdue when the operator commits again", () => {
    const { venue, sequencer, backing } = setup();
    venue.advance(INTERVAL + 1n);
    expect(isOverdue(venue, backing)).toBe(true);
    sequencer.commit();
    expect(isOverdue(venue, backing)).toBe(false);
  });

  it("is never overdue where the backing declares no interval", () => {
    // Tag 0x01 and 0x02 declare no witnessing terms, and a backing that
    // promised no schedule cannot be late against one. The same shape as a
    // backing with no silence clause never being silent.
    const venue = new Venue();
    const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], SILENCE);
    venue.advance(10_000n);
    expect(isOverdue(venue, backing)).toBe(false);
  });

  it("is a fact and not a grade: overdue long before silent, and silent implies overdue", () => {
    // §C2b has two grades and this is neither. Lateness is what a payee reads
    // to decide whether to wait for finality; the aggravated grade is the
    // separate, much later fact that opens snapshot redemption.
    const { venue, sequencer, backing } = setup();
    sequencer.commit();
    venue.advance(INTERVAL + 1n);
    expect(isOverdue(venue, backing)).toBe(true);
    expect(isSilent(venue, backing)).toBe(false);
    venue.advance(SILENCE.noCommitmentDuration);
    expect(isOverdue(venue, backing)).toBe(true);
    expect(isSilent(venue, backing)).toBe(true);
  });

  it("polices no calibration: an interval longer than the silence duration is representable", () => {
    // The numbers are the backer's to choose and the holder's to read (§C2b,
    // and the slice-6 decision). A backing promising to commit every 100 while
    // being graded silent at 50 means what it says: permanently in the
    // aggravated grade. Incoherent, and not this code's to refuse.
    const venue = new Venue(VENUE);
    const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], SILENCE, {
      venue: VENUE,
      interval: SILENCE.noCommitmentDuration + 50n,
    });
    venue.advance(SILENCE.noCommitmentDuration + 1n);
    expect(isOverdue(venue, backing)).toBe(false);
    expect(isSilent(venue, backing)).toBe(true);
  });
});

describe("§C2b: a grade is read on the backing's OWN declared venue", () => {
  it("refuses to grade against a venue the backing does not declare", () => {
    // Without this the grade is a fact about who you asked. Alice holds a
    // commitment record from another venue where this operator looks punctual —
    // or looks dead — and either way it says nothing about this backing.
    const { backing } = setup();
    const stranger = new Venue(OTHER_VENUE);
    stranger.advance(10_000n);
    expect(isSilent(stranger, backing)).toBe(false);
    expect(isOverdue(stranger, backing)).toBe(false);
  });

  it("proves no holding against a venue the backing does not declare", () => {
    const { venue, sequencer, backing } = setup();
    const served = { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
    expect(provesHolding(venue, backing, served, KEYS.alice, 100n)).toBe(true);

    const stranger = new Venue(OTHER_VENUE);
    stranger.publish(served.commitment);
    expect(provesHolding(stranger, backing, served, KEYS.alice, 100n)).toBe(false);
  });

  it("resolves no redemption against a venue the backing does not declare", () => {
    // The same record, put in two places. On the venue E names it settles; on a
    // stranger's it resolves nothing — which is the point, since a redemption
    // pays real money against a grade, and the grade is the declared venue's to
    // give. Both venues carry identical publications, so an empty answer here
    // cannot come from an empty record.
    const { venue, sequencer, backing } = setup();
    const served = { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
    const stranger = new Venue(OTHER_VENUE);
    stranger.publish(served.commitment);
    for (const v of [venue, stranger]) redeemAt(v, backing);

    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(1);
    expect(snapshotRedemptions(stranger, backing, served)).toEqual([]);
  });

  it("refuses to serve a backing that declares a venue this sequencer is not on", () => {
    // The sequencer's own question, in its own voice: routing, not the law.
    // Same shape as "is this operator me".
    const venue = new Venue(OTHER_VENUE);
    const sequencer = new Sequencer(SECRETS.operator, venue);
    const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], SILENCE, {
      venue: VENUE,
      interval: INTERVAL,
    });
    expect(() => sequencer.register(backing, signBacking(SECRETS.backer, backing))).toThrow(
      SequencerError,
    );
  });

  it("serves and grades normally on the venue it does declare", () => {
    const { venue, sequencer, backing } = setup();
    sequencer.commit();
    expect(isSilent(venue, backing)).toBe(false);
    venue.advance(SILENCE.noCommitmentDuration + 1n);
    expect(isSilent(venue, backing)).toBe(true);
  });

  it("answers about the record, not about the operator", () => {
    // Found reviewing the implementation. A holder with the wrong venue's record
    // is told "not silent, not overdue" while the operator is in fact dark, and
    // that reads as reassurance when it is only a statement that this record
    // shows nothing. venueIsDeclared is the question to ask first, and it is
    // exported so a caller can. Pinned here so the meaning is asserted rather
    // than remembered.
    const { backing } = setup();
    const wrong = new Venue(OTHER_VENUE);
    wrong.advance(10_000n);
    expect(isSilent(wrong, backing)).toBe(false);
    expect(isOverdue(wrong, backing)).toBe(false);
    expect(venueIsDeclared(wrong, backing)).toBe(false);

    const right = new Venue(VENUE);
    right.advance(10_000n);
    expect(venueIsDeclared(right, backing)).toBe(true);
    expect(isSilent(right, backing)).toBe(true);
    expect(isOverdue(right, backing)).toBe(true);
  });

  it("grades a backing that declares no venue against whichever record you hold", () => {
    // Unchanged for tags 0x01 and 0x02, and it is a setting rather than an
    // oversight: a backer who wants the grade pinned declares a venue.
    const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], SILENCE);
    const anywhere = new Venue(OTHER_VENUE);
    anywhere.advance(SILENCE.noCommitmentDuration + 1n);
    expect(isSilent(anywhere, backing)).toBe(true);
  });
});
