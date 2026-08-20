import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import { type PublishedOp } from "../src/oplog.js";
import { isNonServing, isSilent, unservedRequests } from "../src/recovery.js";
import { Sequencer } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// §C2b's other grade, and the one that reaches the party the aggravated grade
// cannot: "The clause is measured on service rather than publication. A stalling
// backer-run sequencer publishes on time, and the stall shows only as a spent
// set that stops growing."
//
//   "**Non-service**: a signed transfer request, published where demands are,
//   left unserved past the declared duration and counted only while still
//   unserved... It fires in the aggregate, and E declares the aggregate: at
//   least m distinct requests, each unserved past the duration, standing within
//   a window W."
//
// The remedy is E's replacement rule, which slice 13 built — so this grade
// finally has somewhere to point. And it is the answer to the hole slice 11
// recorded: an operator that drops a backing from its commitments keeps
// publishing and reads as perfectly live, and this is the grade that counts what
// it stopped doing.

const NON_SERVICE = { duration: 10n, count: 2, window: 100n };

function setup(nonService: typeof NON_SERVICE | undefined = NON_SERVICE) {
  const venue = new LocalVenue();
  const backing = makeBacking({
    obligor: KEYS.backer,
    payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: {
      setting: "transparent",
      operator: KEYS.operator,
      silence: { noCommitmentDuration: 1000n, challengeWindow: 5n },
      ...(nonService === undefined ? {} : { nonService }),
    },
  });
  const sequencer = new Sequencer(SECRETS.operator, venue);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  sequencer.submitIssue(
    { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n },
    ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
  );
  return { venue, sequencer, backing };
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

function servedBy(sequencer: Sequencer) {
  return { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
}

describe("§C2b: non-service is counted on service, not on publication", () => {
  it("fires where m requests stand unserved past the duration", () => {
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    // The operator keeps publishing — it is not silent, and never will be.
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.publishOp(backing.name, request(backing, 20n, 1n));
    venue.advance(NON_SERVICE.duration + 1n);

    expect(isSilent(venue, backing)).toBe(false);
    expect(unservedRequests(venue, backing, served)).toHaveLength(2);
    expect(isNonServing(venue, backing, served)).toBe(true);
  });

  it("does not fire before the duration has passed", () => {
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.publishOp(backing.name, request(backing, 20n, 1n));
    venue.advance(NON_SERVICE.duration);
    expect(isNonServing(venue, backing, served)).toBe(false);
    venue.advance(1n);
    expect(isNonServing(venue, backing, served)).toBe(true);
  });

  it("does not fire below m, however long they stand", () => {
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.advance(NON_SERVICE.window - 1n);
    expect(unservedRequests(venue, backing, served)).toHaveLength(1);
    expect(isNonServing(venue, backing, served)).toBe(false);
  });

  it("stops counting a request once the operator serves it", () => {
    // "counted only while still unserved". The operator takes one of the two
    // and commits it, and the grade falls back below m.
    const { venue, sequencer, backing } = setup();
    const first = request(backing, 10n, 0n);
    venue.publishOp(backing.name, first);
    venue.publishOp(backing.name, request(backing, 20n, 1n));
    venue.advance(NON_SERVICE.duration + 1n);
    expect(isNonServing(venue, backing, servedBy(sequencer))).toBe(true);

    sequencer.submitTransfer(
      { backing, from: KEYS.alice, to: KEYS.bob, quantity: 10n, nonce: 0n },
      first.signature,
    );
    const after = servedBy(sequencer);
    expect(unservedRequests(venue, backing, after)).toHaveLength(1);
    expect(isNonServing(venue, backing, after)).toBe(false);
  });

  it("stops counting a request that has aged out of the window", () => {
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.advance(NON_SERVICE.window);
    expect(unservedRequests(venue, backing, served)).toHaveLength(1);
    venue.advance(1n);
    expect(unservedRequests(venue, backing, served)).toHaveLength(0);
  });

  it("counts a republished request once", () => {
    // Distinct by the operation, so anyone echoing the venue cannot manufacture
    // a grade out of one request.
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    const only = request(backing, 10n, 0n);
    venue.publishOp(backing.name, only);
    venue.publishOp(backing.name, only);
    venue.publishOp(backing.name, only);
    venue.advance(NON_SERVICE.duration + 1n);
    expect(unservedRequests(venue, backing, served)).toHaveLength(1);
    expect(isNonServing(venue, backing, served)).toBe(false);
  });

  it("ignores a request the committed state could never have served", () => {
    // "Faking a request means holding a real claim, so the count is checkable."
    // Without this, anyone with a keypair manufactures the grade for free — the
    // same hole the challenge window had when a request the snapshot could not
    // have served counted as a spend.
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    const beyondHerHolding: PublishedOp = {
      kind: "transfer",
      from: KEYS.alice,
      to: KEYS.bob,
      quantity: 10_000n,
      nonce: 0n,
      signature: ed25519.sign(
        encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 10_000n, 0n),
        SECRETS.alice,
      ),
    };
    const byAStranger: PublishedOp = {
      kind: "transfer",
      from: KEYS.mallory,
      to: KEYS.bob,
      quantity: 1n,
      nonce: 0n,
      signature: ed25519.sign(
        encodeTransferMessage(backing.name, KEYS.mallory, KEYS.bob, 1n, 0n),
        SECRETS.mallory,
      ),
    };
    venue.publishOp(backing.name, beyondHerHolding);
    venue.publishOp(backing.name, byAStranger);
    venue.advance(NON_SERVICE.duration + 1n);
    expect(unservedRequests(venue, backing, served)).toHaveLength(0);
    expect(isNonServing(venue, backing, served)).toBe(false);
  });

  it("counts only transfers, not the presentation legs published beside them", () => {
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.publishOp(backing.name, {
      kind: "burn",
      holder: KEYS.alice,
      quantity: 1n,
      nonce: 1n,
      signature: ed25519.sign(new Uint8Array(8), SECRETS.alice),
    } as PublishedOp);
    venue.advance(NON_SERVICE.duration + 1n);
    expect(unservedRequests(venue, backing, served)).toHaveLength(1);
  });

  it("never fires where the backing conceded no non-service grade", () => {
    // The same choice tag 0x01 makes about silence: a backer may concede
    // nothing, and the holder reads that before accepting.
    const { venue, sequencer, backing } = setup(undefined);
    const served = servedBy(sequencer);
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.publishOp(backing.name, request(backing, 20n, 1n));
    venue.advance(1000n);
    expect(unservedRequests(venue, backing, served)).toEqual([]);
    expect(isNonServing(venue, backing, served)).toBe(false);
  });

  it("answers, rather than throwing, on a state this operator did not commit", () => {
    const { venue, sequencer, backing } = setup();
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.publishOp(backing.name, request(backing, 20n, 1n));
    venue.advance(NON_SERVICE.duration + 1n);
    const junk = {
      snapshots: sequencer.snapshot(),
      commitment: { sequence: 0n, root: new Uint8Array(32), operator: KEYS.mallory, signature: new Uint8Array(64) },
    };
    expect(isNonServing(venue, backing, junk)).toBe(false);
    expect(unservedRequests(venue, backing, junk)).toEqual([]);
  });
});

describe("§C2b: the fold is a sequence, so a request behind another still counts", () => {
  it("counts a standing request whose predecessor has aged out of the window", () => {
    // Found reviewing the implementation. The age filter used to run before the
    // fold, so a request outside the counting band was skipped entirely — and
    // every later request by the same signer then failed as ahead of a nonce
    // nobody had reached. An operator could have escaped the grade forever by
    // being handed one request early and the rest later.
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    // Let the first age past the window before the next two arrive.
    venue.advance(NON_SERVICE.window + 1n);
    venue.publishOp(backing.name, request(backing, 20n, 1n));
    venue.publishOp(backing.name, request(backing, 30n, 2n));
    venue.advance(NON_SERVICE.duration + 1n);

    const standing = unservedRequests(venue, backing, served);
    expect(standing.map((w) => w.op.kind === "transfer" && w.op.nonce)).toEqual([1n, 2n]);
    expect(isNonServing(venue, backing, served)).toBe(true);
  });

  it("counts a request too young to stand yet as part of the sequence", () => {
    const { venue, sequencer, backing } = setup();
    const served = servedBy(sequencer);
    venue.publishOp(backing.name, request(backing, 10n, 0n));
    venue.advance(NON_SERVICE.duration + 1n);
    // The second is still inside the duration, so it does not stand — but it
    // must not stop a third behind it from applying.
    venue.publishOp(backing.name, request(backing, 20n, 1n));
    venue.publishOp(backing.name, request(backing, 30n, 2n));
    expect(unservedRequests(venue, backing, served)).toHaveLength(1);
    venue.advance(NON_SERVICE.duration + 1n);
    expect(unservedRequests(venue, backing, served)).toHaveLength(3);
  });
});

describe("§C2b: no calibration is policed", () => {
  it("lets a backer concede the grade unconditionally with m = 0", () => {
    // The numbers are the backer's to choose and the holder's to read. m = 0
    // says the grade stands with nothing standing, which is odd and is what it
    // says — the same latitude a zero silence duration has.
    const { venue, sequencer, backing } = setup({ duration: 10n, count: 0, window: 100n });
    const served = servedBy(sequencer);
    expect(unservedRequests(venue, backing, served)).toEqual([]);
    expect(isNonServing(venue, backing, served)).toBe(true);
  });
});
