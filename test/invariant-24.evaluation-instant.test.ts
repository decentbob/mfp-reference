import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { signBacking } from "../src/backing.js";
import { LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeIssuance } from "../src/messages.js";
import { demandHash, encodeAcceptance, encodeDemand } from "../src/presentation.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import {
  advanceWitnessedIndex,
  KEYS,
  makeTransparentBacking,
  register,
  SECRETS,
} from "./support.js";

// Invariant 24: "One witnessed evaluation instant per presentation. The instant
// is named in the demand and agreed by the acceptance, two signatures over one
// object, on one declared venue, no later than the latest witnessed index at
// signing... Never a timestamp the holder signs alone."
//
// Slice 4 enforced only the agreement half, because the ledger has no clock and
// witnessed indices come from the operator's commitments at the venue. The
// sequencer now supplies the index from the venue, so the "no later than the
// latest witnessed index" half is enforced too.
//
// One check covers both signatures: the demand's instant is pinned to a
// witnessed index at filing, and the acceptance must repeat that exact value,
// so an acceptance cannot name an unwitnessed instant either.

function sequencerAt(index: bigint) {
  const venue = new Venue();
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  advanceWitnessedIndex(venue, index);
  return { sequencer, backing, venue };
}

describe("invariant 24: the instant is no later than the latest witnessed index", () => {
  it("an instant at the latest witnessed index is accepted", () => {
    const { sequencer, backing } = sequencerAt(5n);
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    expect(sequencer.submitDemand(op, ed25519.sign(encodeDemand(op), SECRETS.alice)).position).toBe(
      1n,
    );
  });

  it("an instant past the latest witnessed index is refused", () => {
    // A payout evaluated at an index nobody has witnessed is a time the holder
    // asserts alone, which is exactly what invariant 24 forbids.
    const { sequencer, backing } = sequencerAt(5n);
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 6n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    expect(() => sequencer.submitDemand(op, ed25519.sign(encodeDemand(op), SECRETS.alice))).toThrow(
      /instant is later than the latest witnessed index/,
    );
    expect(sequencer.openDemands(backing)).toHaveLength(0);
  });

  it("the same instant becomes fileable once the venue has moved on", () => {
    const { sequencer, backing, venue } = sequencerAt(5n);
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 6n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    const signature = ed25519.sign(encodeDemand(op), SECRETS.alice);
    expect(() => sequencer.submitDemand(op, signature)).toThrow(LedgerError);
    advanceWitnessedIndex(venue, 6n);
    expect(sequencer.submitDemand(op, signature).position).toBe(1n);
  });

  it("the ledger enforces it directly too, on the index it is handed", () => {
    const ledger = new TransparentLedger();
    const backing = register(ledger, SECRETS.backer);
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 9n,
      deadline: 20n,
      nonce: ledger.nextNonce(KEYS.alice, backing),
    };
    const signature = ed25519.sign(encodeDemand(op), SECRETS.alice);
    expect(() => ledger.demand(op, signature, 8n)).toThrow(LedgerError);
    expect(ledger.demand(op, signature, 9n).kind).toBe("demand");
  });
});

describe("invariant 24: the acceptance agrees the demand's instant", () => {
  it("an acceptance naming a different instant is rejected", () => {
    const { sequencer, backing } = sequencerAt(5n);
    const demand = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
    const answer = {
      backing,
      demandHash: demandHash(demand),
      instant: 4n,
      deadline: 8n,
      nonce: sequencer.nextNonce(KEYS.backer, backing),
    };
    expect(() =>
      sequencer.submitAcceptance(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer)),
    ).toThrow(/does not agree/);
    expect(sequencer.openDemands(backing)[0]?.acceptedDeadline).toBeUndefined();
  });

  it("agreeing it is two signatures over one value", () => {
    const { sequencer, backing } = sequencerAt(5n);
    const demand = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
    const answer = {
      backing,
      demandHash: demandHash(demand),
      instant: 5n,
      deadline: 8n,
      nonce: sequencer.nextNonce(KEYS.backer, backing),
    };
    sequencer.submitAcceptance(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer));
    const record = sequencer.openDemands(backing)[0]!;
    expect(record.instant).toBe(5n);
    expect(record.acceptedDeadline).toBe(8n);
  });
});
