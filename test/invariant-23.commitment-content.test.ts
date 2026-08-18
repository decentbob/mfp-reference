import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { stateRoot } from "../src/commitment.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { Sequencer } from "../src/sequencer.js";
import { KEYS, SECRETS } from "./support.js";

// Invariant 23: a commitment commits to the issuance log, the spent set, and
// running totals. In the transparent subset that means the root must move
// when issued, burned, balances, or the operation log change — and two
// sequencers with identical served state must produce the identical root.

function servedBacking(obligorSecret: Uint8Array, thing = "EUR"): Backing {
  return makeBacking({
    obligor: ed25519.getPublicKey(obligorSecret),
    payout: { thing, quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: KEYS.operator },
  });
}

function fresh() {
  const sequencer = new Sequencer(SECRETS.operator);
  const backing = servedBacking(SECRETS.backer);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  return { sequencer, backing };
}

function rootOf(sequencer: Sequencer): string {
  return bytesToHex(stateRoot(sequencer.snapshot()));
}

describe("invariant 23: the commitment commits to totals, balances, and the log", () => {
  it("issuance moves the root (issued total + a log entry)", () => {
    const { sequencer, backing } = fresh();
    const before = rootOf(sequencer);
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    expect(rootOf(sequencer)).not.toBe(before);
  });

  it("a transfer moves the root (balances + a log entry) without changing totals", () => {
    const { sequencer, backing } = fresh();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    const before = rootOf(sequencer);
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(sequencer.outstanding(backing)).toBe(100n);
    expect(rootOf(sequencer)).not.toBe(before);
  });

  it("a burn moves the root (burned total)", () => {
    const { sequencer, backing } = fresh();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    const before = rootOf(sequencer);
    const burn = { backing, holder: KEYS.alice, quantity: 30n, nonce: 0n };
    sequencer.submitBurn(burn, ed25519.sign(encodeBurn(burn), SECRETS.alice));
    expect(rootOf(sequencer)).not.toBe(before);
  });

  it("two sequencers with identical served state produce the identical root", () => {
    const build = () => {
      const { sequencer, backing } = fresh();
      const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
      sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
      const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
      sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
      return sequencer;
    };
    expect(rootOf(build())).toBe(rootOf(build()));
  });

  it("the root is independent of the order backings were registered", () => {
    const eur = servedBacking(SECRETS.backer, "EUR");
    const kwh = servedBacking(SECRETS.backer2, "kWh");
    const a = new Sequencer(SECRETS.operator);
    a.register(eur, signBacking(SECRETS.backer, eur));
    a.register(kwh, signBacking(SECRETS.backer2, kwh));
    const b = new Sequencer(SECRETS.operator);
    b.register(kwh, signBacking(SECRETS.backer2, kwh));
    b.register(eur, signBacking(SECRETS.backer, eur));
    expect(rootOf(a)).toBe(rootOf(b));
  });
});
