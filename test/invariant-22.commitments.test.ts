import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import {
  isEquivocation,
  signCommitment,
  stateRoot,
  verifyCommitment,
} from "../src/commitment.js";
import { encodeIssuance } from "../src/messages.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// Invariant 22: every state a sequencer asserts must prove against its latest
// published commitment, so divergent histories are not assertable — two
// commitments at the same index over different roots, both signed by the
// operator, are provable equivocation.

function servedBacking(obligorSecret: Uint8Array, thing = "EUR"): Backing {
  return makeBacking({
    obligor: ed25519.getPublicKey(obligorSecret),
    payout: { thing, quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: KEYS.operator },
  });
}

function setup() {
  const sequencer = new Sequencer(SECRETS.operator);
  const backing = servedBacking(SECRETS.backer);
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
    expect(venue.latest()).toEqual(commitment);
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
