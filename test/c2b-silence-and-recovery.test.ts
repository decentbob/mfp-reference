import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { signCommitment, stateProvesCommitment, type Commitment } from "../src/commitment.js";
import { encodeIssuance, encodeTransfer } from "../src/messages.js";
import { isSilent, provesHolding, quietFor, redemptionIsOpen } from "../src/recovery.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// §C2b: "When sequencers go dark, claims go illiquid rather than dead... after
// the declared silence, redemption against the last witnessed snapshot opens
// without co-signature, with the holder proving the claim unspent as of that
// snapshot."
//
// This slice builds the two facts that open it, and stops there; the payment
// path (the claim/acceptance/release legs and the challenge window) is the next
// slice. The facts are worth having on their own: both are checkable by any
// stranger against the published record, which is what makes the grade
// something a backer concedes rather than argues.
//
//   - the grade. "No commitment past a second declared duration, in any
//     setting: the aggravated grade." The duration is declared in E, so the
//     holder read the choice before accepting (invariant 1: no edit).
//   - the unspentness proof. Invariant 23 says "the spent set must support
//     non-membership proofs, since §C2b's recovery path proves a claim not
//     spent as of the last commitment, which a bare Merkle root cannot do."
//     Under transparent the whole served state is rehashed against the root —
//     the same way a receipt proves — so serving everything IS the proof, and
//     the Merkle machinery belongs with the constructions that cannot serve
//     everything. See DECISIONS.md.

const SILENCE = { noCommitmentDuration: 10n, challengeWindow: 5n };

// `null` means "declares no clause". A defaulted `undefined` would silently fall
// back to SILENCE and leave the no-clause path untested, which it did.
function setup(silence: typeof SILENCE | null = SILENCE) {
  const venue = new Venue();
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], silence ?? undefined);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { venue, sequencer, backing };
}

/** The served state and the commitment it proves against — what a holder is handed. */
function served(sequencer: Sequencer) {
  const snapshots = sequencer.snapshot();
  return { snapshots, commitment: sequencer.commit() };
}

describe("§C2b: silence is a public fact, measured on the venue's clock", () => {
  it("counts from the operator's last commitment", () => {
    const { venue, sequencer } = setup();
    venue.advance(3n);
    sequencer.commit();
    expect(quietFor(venue, sequencer.operator)).toBe(0n);
    venue.advance(7n);
    expect(quietFor(venue, sequencer.operator)).toBe(7n);
  });

  it("counts from the venue's genesis for an operator that never published", () => {
    // Otherwise never publishing at all would be the way to escape the grade.
    const { venue, sequencer } = setup();
    venue.advance(42n);
    expect(venue.witnessedAtFor(sequencer.operator)).toBeUndefined();
    expect(quietFor(venue, sequencer.operator)).toBe(42n);
  });

  it("is not silence while the operator commits inside its declared duration", () => {
    const { venue, sequencer, backing } = setup();
    sequencer.commit();
    venue.advance(10n);
    expect(isSilent(venue, backing)).toBe(false);
    // The duration is 10, so index 10 is the last quiet index that is not yet
    // the aggravated grade.
    venue.advance();
    expect(isSilent(venue, backing)).toBe(true);
  });

  it("resumes being not-silent when commitments resume", () => {
    // "runs from the first missed commitment until commitments resume".
    const { venue, sequencer, backing } = setup();
    sequencer.commit();
    venue.advance(20n);
    expect(isSilent(venue, backing)).toBe(true);
    sequencer.commit();
    expect(isSilent(venue, backing)).toBe(false);
  });

  it("a backing that declares no silence clause is never silent", () => {
    // Tag 0x01: the backer declared no clause, so claims can go illiquid
    // forever. A coherent setting, and the holder read it before accepting.
    const { venue, backing } = setup(null);
    venue.advance(1_000_000n);
    expect(backing.evidence.silence).toBeUndefined();
    expect(isSilent(venue, backing)).toBe(false);
  });

  it("two backings grade one silent operator by their own declared durations", () => {
    // The fact is the operator's; the threshold is each backing's own term.
    const venue = new Venue();
    const sequencer = new Sequencer(SECRETS.operator, venue);
    const patient = makeTransparentBacking(SECRETS.backer, "EUR", [], {
      noCommitmentDuration: 100n,
      challengeWindow: 5n,
    });
    const strict = makeTransparentBacking(SECRETS.backer2, "kWh", [], {
      noCommitmentDuration: 5n,
      challengeWindow: 5n,
    });
    sequencer.register(patient, signBacking(SECRETS.backer, patient));
    sequencer.register(strict, signBacking(SECRETS.backer2, strict));
    sequencer.commit();
    venue.advance(50n);
    expect(isSilent(venue, strict)).toBe(true);
    expect(isSilent(venue, patient)).toBe(false);
  });
});

describe("§C2b: the holder proves the claim unspent as of the last snapshot", () => {
  it("proves what the holder held, and no more", () => {
    const { venue, sequencer, backing } = setup();
    const state = served(sequencer);
    expect(provesHolding(venue, backing, state, KEYS.alice, 100n)).toBe(true);
    expect(provesHolding(venue, backing, state, KEYS.alice, 40n)).toBe(true);
    expect(provesHolding(venue, backing, state, KEYS.alice, 101n)).toBe(false);
    // Somebody who holds nothing proves nothing.
    expect(provesHolding(venue, backing, state, KEYS.mallory, 1n)).toBe(false);
    // A quantity is whole and positive (invariant 15).
    expect(provesHolding(venue, backing, state, KEYS.alice, 0n)).toBe(false);
    expect(provesHolding(venue, backing, state, KEYS.alice, -5n)).toBe(false);
  });

  it("refuses a stale snapshot in which the holder held more", () => {
    // The whole point: "redemption against the LAST witnessed snapshot". Without
    // this, a holder who has since spent the units redeems against the state
    // that still shows them.
    const { venue, sequencer, backing } = setup();
    const stale = served(sequencer);
    expect(provesHolding(venue, backing, stale, KEYS.alice, 100n)).toBe(true);

    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 90n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    const current = served(sequencer);

    expect(provesHolding(venue, backing, stale, KEYS.alice, 100n)).toBe(false);
    expect(provesHolding(venue, backing, current, KEYS.alice, 100n)).toBe(false);
    expect(provesHolding(venue, backing, current, KEYS.alice, 10n)).toBe(true);
    expect(provesHolding(venue, backing, current, KEYS.bob, 90n)).toBe(true);
  });

  it("refuses a commitment by anyone but the backing's own operator", () => {
    // A stranger can sign a valid commitment over any state it likes. It is not
    // the operator E names, so it proves nothing about this backing.
    const { venue, sequencer, backing } = setup();
    const state = served(sequencer);
    // The same root over the same honest state; only the signer differs.
    const impostor: Commitment = signCommitment(SECRETS.mallory, 0n, state.commitment.root);
    expect(stateProvesCommitment(state.snapshots, impostor)).toBe(true);
    expect(
      provesHolding(venue, backing, { ...state, commitment: impostor }, KEYS.alice, 100n),
    ).toBe(false);
  });

  it("refuses served state that does not prove against the commitment", () => {
    const { venue, sequencer, backing } = setup();
    const state = served(sequencer);
    const tampered = {
      ...state,
      snapshots: state.snapshots.map((s) => ({
        ...s,
        balances: s.balances.map(([key, units]) => [key, units + 1n] as const),
      })),
    };
    expect(provesHolding(venue, backing, tampered, KEYS.alice, 101n)).toBe(false);
  });

  it("refuses when the served state carries no snapshot for this backing", () => {
    const { venue, sequencer, backing } = setup();
    const state = served(sequencer);
    expect(provesHolding(venue, backing, { ...state, snapshots: [] }, KEYS.alice, 1n)).toBe(false);
  });

  it("returns false on hostile input rather than throwing", () => {
    const { venue, backing } = setup();
    const junk = {
      snapshots: [
        {
          name: new Uint8Array(31),
          issued: -1n,
          burned: 0n,
          balances: [],
          opLog: [],
          demands: [],
        },
      ],
      commitment: {
        sequence: -1n,
        root: new Uint8Array(3),
        operator: new Uint8Array(7),
        signature: new Uint8Array(2),
      },
    };
    expect(provesHolding(venue, backing, junk, new Uint8Array(0), 1n)).toBe(false);
    expect(redemptionIsOpen(venue, backing, junk, new Uint8Array(0), 1n)).toBe(false);
  });
});

describe("§C2b: redemption opens on both facts together", () => {
  it("needs the silence as well as the holding", () => {
    const { venue, sequencer, backing } = setup();
    const state = served(sequencer);
    // Held, but the operator is answering.
    expect(provesHolding(venue, backing, state, KEYS.alice, 100n)).toBe(true);
    expect(redemptionIsOpen(venue, backing, state, KEYS.alice, 100n)).toBe(false);

    venue.advance(11n);
    expect(isSilent(venue, backing)).toBe(true);
    expect(redemptionIsOpen(venue, backing, state, KEYS.alice, 100n)).toBe(true);
    // Still bounded by what the snapshot actually shows.
    expect(redemptionIsOpen(venue, backing, state, KEYS.alice, 101n)).toBe(false);
  });

  it("closes again when the operator comes back", () => {
    const { venue, sequencer, backing } = setup();
    const state = served(sequencer);
    venue.advance(11n);
    expect(redemptionIsOpen(venue, backing, state, KEYS.alice, 100n)).toBe(true);
    sequencer.commit();
    // The old snapshot is no longer the latest, and the operator is not silent.
    expect(redemptionIsOpen(venue, backing, state, KEYS.alice, 100n)).toBe(false);
  });

  it("never opens against a backing that declared no clause", () => {
    const { venue, sequencer, backing } = setup(null);
    const state = served(sequencer);
    venue.advance(1_000_000n);
    expect(provesHolding(venue, backing, state, KEYS.alice, 100n)).toBe(true);
    expect(redemptionIsOpen(venue, backing, state, KEYS.alice, 100n)).toBe(false);
  });
});

describe("E declares the silence clause, so it is inside the backing's name", () => {
  const base = {
    obligor: KEYS.backer,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
  } as const;

  const withClause = (silence: { noCommitmentDuration: bigint; challengeWindow: bigint }): Backing =>
    makeBacking({ ...base, evidence: { setting: "transparent", operator: KEYS.operator, silence } });

  it("a declared clause changes the name", () => {
    const bare = makeBacking({
      ...base,
      evidence: { setting: "transparent", operator: KEYS.operator },
    });
    const declared = withClause({ noCommitmentDuration: 10n, challengeWindow: 5n });
    expect(declared.nameHex).not.toBe(bare.nameHex);
  });

  it("different terms are different backings", () => {
    const a = withClause({ noCommitmentDuration: 10n, challengeWindow: 5n });
    const b = withClause({ noCommitmentDuration: 11n, challengeWindow: 5n });
    const c = withClause({ noCommitmentDuration: 10n, challengeWindow: 6n });
    expect(new Set([a.nameHex, b.nameHex, c.nameHex]).size).toBe(3);
  });

  it("the clause survives the round trip and is a copy", () => {
    const declared = withClause({ noCommitmentDuration: 10n, challengeWindow: 5n });
    expect(declared.evidence.silence).toEqual({
      noCommitmentDuration: 10n,
      challengeWindow: 5n,
    });
  });
});
