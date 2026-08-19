import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking } from "../src/backing.js";
import { LedgerError, NonceError } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { receiptProvenBy, verifyReceipt } from "../src/receipt.js";
import { EncodingError } from "../src/bytes.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// Invariant 26: a repeated request returns the identical prior response, and a
// crash loses nothing. The sequencer returns the identical prior receipt on
// replay, and declines a different operation at an already-spent nonce (it
// "refuses a second spend by declining to sign").

function setup() {
  const sequencer = new Sequencer(SECRETS.operator);
  const backing = makeTransparentBacking(SECRETS.backer);
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
    expect(second.position).toBe(first.position);
    // The replay applied nothing: Bob holds 30, not 60.
    expect(sequencer.balance(backing, KEYS.bob)).toBe(30n);
  });

  it("the receipt is a valid operator co-signature over the operation", () => {
    const { sequencer, issueReceipt } = setup();
    expect(verifyReceipt(issueReceipt)).toBe(true);
    expect(issueReceipt.operator).toEqual(sequencer.operator);
  });

  it("a tampered receipt does not verify", () => {
    const { issueReceipt } = setup();
    expect(verifyReceipt({ ...issueReceipt, position: issueReceipt.position + 1n })).toBe(false);
    const badHash = issueReceipt.opHash.slice();
    badHash[0] = (badHash[0] as number) ^ 0xff;
    expect(verifyReceipt({ ...issueReceipt, opHash: badHash })).toBe(false);
  });

  it("each accepted operation gets the next log position", () => {
    const { sequencer, backing, issueReceipt } = setup();
    expect(issueReceipt.position).toBe(0n);
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    const r1 = sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    expect(r1.position).toBe(1n);
    const burn = { backing, holder: KEYS.bob, quantity: 10n, nonce: 0n };
    const r2 = sequencer.submitBurn(burn, ed25519.sign(encodeBurn(burn), SECRETS.bob));
    expect(r2.position).toBe(2n);
  });

  it("a different operation at an already-spent nonce is refused", () => {
    const { sequencer, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    const conflicting = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 40n, nonce: 0n };
    expect(() =>
      sequencer.submitTransfer(conflicting, ed25519.sign(encodeTransfer(conflicting), SECRETS.alice)),
    ).toThrow(NonceError);
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
    expect(receipt.position).toBe(1n);
    expect(sequencer.balance(backing, KEYS.bob)).toBe(30n);
  });

  it("a malformed operation is an EncodingError from the encoder", () => {
    const { sequencer, backing } = setup();
    const zeroQuantity = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 0n, nonce: 0n };
    expect(() => sequencer.submitTransfer(zeroQuantity, new Uint8Array(64))).toThrow(EncodingError);
  });

  it("a receipt is proven by the committed state at its position", () => {
    const { sequencer, issueReceipt } = setup();
    const snapshot = sequencer.snapshot()[0]!;
    expect(receiptProvenBy(issueReceipt, snapshot)).toBe(true);
    // Tampering the logged quantity breaks the proof.
    const tampered = {
      ...snapshot,
      opLog: snapshot.opLog.map((e) => ({ ...e, quantity: e.quantity + 1n })),
    };
    expect(receiptProvenBy(issueReceipt, tampered)).toBe(false);
  });

  it("a malformed served entry fails the proof rather than throwing", () => {
    const { sequencer, issueReceipt } = setup();
    const snapshot = sequencer.snapshot()[0]!;
    // A hostile operator serves an out-of-range quantity at the position.
    const hostile = {
      ...snapshot,
      opLog: snapshot.opLog.map((e) => ({ ...e, quantity: 0n })),
    };
    expect(receiptProvenBy(issueReceipt, hostile)).toBe(false);
  });
});

describe("a sequencer serves only the backings whose E names it", () => {
  it("refuses to register a backing served by a different operator", () => {
    const sequencer = new Sequencer(SECRETS.operator);
    const foreign = makeBacking({
      obligor: KEYS.backer,
      payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: { setting: "transparent", operator: ed25519.getPublicKey(SECRETS.backer2) },
    });
    expect(() => sequencer.register(foreign, signBacking(SECRETS.backer, foreign))).toThrow(
      SequencerError,
    );
  });

  it("refuses to submit against a backing it does not serve", () => {
    const sequencer = new Sequencer(SECRETS.operator);
    const backing = makeTransparentBacking(SECRETS.backer);
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    expect(() =>
      sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer)),
    ).toThrow(SequencerError);
  });
});
