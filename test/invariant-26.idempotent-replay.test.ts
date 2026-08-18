import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { LedgerError } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { verifyReceipt } from "../src/receipt.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { KEYS, SECRETS } from "./support.js";

// Invariant 26: a repeated request returns the identical prior response, and
// a crash loses nothing. Here the sequencer returns the identical prior
// receipt on replay, and declines a different operation at an already-spent
// nonce (the ledger's nonce rejection — "refuses a second spend").

// The operator that serves these backings is the sequencer's own key.
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
  const receipt = sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { sequencer, backing, issueReceipt: receipt };
}

describe("invariant 26: a repeated request returns the identical prior response", () => {
  it("resubmitting the same operation returns the identical receipt", () => {
    const { sequencer, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    const signature = ed25519.sign(encodeTransfer(move), SECRETS.alice);
    const first = sequencer.submitTransfer(move, signature);
    const second = sequencer.submitTransfer(move, signature);
    expect(second).toEqual(first);
    expect(second.index).toBe(first.index);
    // The replay applied nothing: Bob holds 30, not 60.
    expect(sequencer.balance(backing, KEYS.bob)).toBe(30n);
  });

  it("the receipt is a valid operator co-signature over the operation", () => {
    const { sequencer, issueReceipt } = setup();
    expect(verifyReceipt(issueReceipt)).toBe(true);
    expect(issueReceipt.operator).toEqual(sequencer.operator);
  });

  it("each accepted operation gets the next witnessed index", () => {
    const { sequencer, backing, issueReceipt } = setup();
    expect(issueReceipt.index).toBe(0n);
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    const r1 = sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(r1.index).toBe(1n);
    const burn = { backing, holder: KEYS.bob, quantity: 10n, nonce: 0n };
    const r2 = sequencer.submitBurn(burn, ed25519.sign(encodeBurn(burn), SECRETS.bob));
    expect(r2.index).toBe(2n);
  });

  it("a different operation at an already-spent nonce is declined", () => {
    const { sequencer, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    // Same nonce, different amount — the nonce is spent, so this is refused.
    const conflicting = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n };
    expect(() =>
      sequencer.submitTransfer(conflicting, ed25519.sign(encodeTransfer(conflicting), SECRETS.alice)),
    ).toThrow(LedgerError);
    expect(sequencer.balance(backing, KEYS.bob)).toBe(30n);
  });

  it("an invalid operation is not recorded, so a later valid one at that nonce succeeds", () => {
    const { sequencer, backing } = setup();
    // Wrong signer: rejected by the ledger, records nothing.
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    expect(() =>
      sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.mallory)),
    ).toThrow(LedgerError);
    // The real holder can still use nonce 0.
    const receipt = sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(receipt.index).toBe(1n);
    expect(sequencer.balance(backing, KEYS.bob)).toBe(30n);
  });
});

describe("a sequencer serves only the backings whose E names it", () => {
  it("refuses to register a backing served by a different operator", () => {
    const sequencer = new Sequencer(SECRETS.operator);
    const otherOperator = ed25519.getPublicKey(SECRETS.backer2);
    const backing = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: { setting: "transparent", operator: otherOperator },
    });
    expect(() => sequencer.register(backing, signBacking(SECRETS.backer, backing))).toThrow(
      SequencerError,
    );
  });

  it("refuses to submit against a backing it does not serve", () => {
    const sequencer = new Sequencer(SECRETS.operator);
    const backing = servedBacking(SECRETS.backer);
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    expect(() =>
      sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer)),
    ).toThrow(SequencerError);
  });
});
