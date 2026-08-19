import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { signBacking } from "../src/backing.js";
import {
  isEquivocation,
  signCommitment,
  stateRoot,
  verifyCommitment,
} from "../src/commitment.js";
import { encodeIssuance } from "../src/messages.js";
import { Sequencer } from "../src/sequencer.js";
import { EncodingError } from "../src/bytes.js";
import { stateProvesCommitment } from "../src/commitment.js";
import { receiptProvenBy, verifyReceipt } from "../src/receipt.js";
import { Venue, VenueError } from "../src/venue.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// Invariant 22: every state a sequencer asserts must prove against its latest
// published commitment, so divergent histories are not assertable — two
// commitments at the same index over different roots, both signed by the
// operator, are provable equivocation.

function setup() {
  const sequencer = new Sequencer(SECRETS.operator);
  const backing = makeTransparentBacking(SECRETS.backer);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { sequencer, backing };
}

describe("invariant 22: state proves against the latest commitment", () => {
  it("the published commitment verifies under the operator key", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const commitment = sequencer.commit(venue);
    expect(verifyCommitment(commitment)).toBe(true);
    expect(venue.latestFor(sequencer.operator)).toEqual(commitment);
  });

  it("a commitment with a mutated root or index does not verify", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const commitment = sequencer.commit(venue);
    const mutatedRoot = commitment.root.slice();
    mutatedRoot[0] = (mutatedRoot[0] as number) ^ 0xff;
    expect(verifyCommitment({ ...commitment, root: mutatedRoot })).toBe(false);
    expect(verifyCommitment({ ...commitment, index: commitment.index + 1n })).toBe(false);
  });

  it("the venue rejects an unsigned commitment and a non-extending index", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const first = sequencer.commit(venue);
    const forged = { ...first, signature: new Uint8Array(64) };
    expect(() => venue.publish(forged)).toThrow(VenueError);
    // Re-publishing the same index does not extend the operator's history.
    expect(() => venue.publish(first)).toThrow(VenueError);
  });

  it("the served state recomputes to the committed root", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const commitment = sequencer.commit(venue);
    expect(stateRoot(sequencer.snapshot())).toEqual(commitment.root);
  });

  it("a tampered state does not match the commitment", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const commitment = sequencer.commit(venue);
    const snapshot = sequencer.snapshot();
    // Inflate a balance in the asserted state.
    const tampered = snapshot.map((s) => ({
      ...s,
      balances: s.balances.map(([k, v]) => [k, v + 1n] as const),
    }));
    expect(stateRoot(tampered)).not.toEqual(commitment.root);
  });

  it("two different roots at the same index by one operator are equivocation", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const honest = sequencer.commit(venue);
    // A second, conflicting commitment at the same index.
    const forgedRoot = new Uint8Array(32).fill(0xab);
    const conflicting = signCommitment(SECRETS.operator, honest.index, forgedRoot);
    expect(isEquivocation(honest, conflicting)).toBe(true);
  });

  it("distinct roots at distinct indices are not equivocation", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const first = sequencer.commit(venue);
    const second = sequencer.commit(venue);
    expect(second.index).toBe(first.index + 1n);
    expect(isEquivocation(first, second)).toBe(false);
  });

  it("a commitment signed by a different key is not the operator's equivocation", () => {
    const { sequencer } = setup();
    const venue = new Venue();
    const honest = sequencer.commit(venue);
    const impostor = signCommitment(SECRETS.mallory, honest.index, new Uint8Array(32).fill(0xcd));
    expect(isEquivocation(honest, impostor)).toBe(false);
  });
});

// The root must be INJECTIVE or invariant 22 is worthless: two served states
// sharing a root let an operator equivocate with one signature and no provable
// fault. Injectivity comes from the framing rule — every key and name is
// fixed-width and asserted, so no two field values share an encoding.

describe("invariant 22: the state root is injective", () => {
  const name = new Uint8Array(32).fill(0x01);

  it("rejects adjacent keys that would concatenate ambiguously", () => {
    // 31+33 bytes concatenate exactly like 32+32, so an unframed encoder gives
    // two different transfers one root.
    const bytes = new Uint8Array(64);
    for (let i = 0; i < 64; i++) bytes[i] = i + 1;
    const state = (from: Uint8Array, to: Uint8Array) => [
      {
        name,
        issued: 7n,
        burned: 0n,
        balances: [],
        opLog: [{ position: 0, kind: "transfer" as const, from, to, quantity: 7n, nonce: 0n }],
      },
    ];
    expect(() => stateRoot(state(bytes.slice(0, 32), bytes.slice(32)))).not.toThrow();
    expect(() => stateRoot(state(bytes.slice(0, 31), bytes.slice(31)))).toThrow(EncodingError);
  });

  it("rejects an over-long balance key that would swallow later fields", () => {
    const long = new Uint8Array(87).fill(0xbb);
    expect(() =>
      stateRoot([{ name, issued: 5n, burned: 0n, balances: [[long, 0n]], opLog: [] }]),
    ).toThrow(EncodingError);
  });

  it("rejects two snapshots for one backing", () => {
    const one = { name, issued: 0n, burned: 0n, balances: [], opLog: [] };
    expect(() => stateRoot([one, one])).toThrow(EncodingError);
  });
});

describe("verifiers return false on hostile input, never throw", () => {
  const name = new Uint8Array(32).fill(0x01);
  const shortKey = new Uint8Array(31);
  const sig = new Uint8Array(64);

  it("a malformed operator key fails verification instead of crashing", () => {
    expect(verifyCommitment({ index: 0n, root: name, operator: shortKey, signature: sig })).toBe(false);
    expect(
      verifyReceipt({ backingName: name, opHash: name, position: 0n, operator: shortKey, signature: sig }),
    ).toBe(false);
  });

  it("a non-integer served position fails the proof instead of crashing", () => {
    const hostile = {
      name,
      issued: 0n,
      burned: 0n,
      balances: [],
      opLog: [{ position: 1.5, kind: "burn" as const, holder: name, quantity: 1n, nonce: 0n }],
    };
    const receipt = { backingName: name, opHash: name, position: 0n, operator: name, signature: sig };
    expect(receiptProvenBy(receipt, hostile)).toBe(false);
  });

  it("a negative served amount fails the commitment check instead of crashing", () => {
    const bad = [{ name, issued: -1n, burned: 0n, balances: [], opLog: [] }];
    expect(stateProvesCommitment(bad, { index: 0n, root: name, operator: name, signature: sig })).toBe(false);
  });
});
