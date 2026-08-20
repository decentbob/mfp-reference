import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { NonceError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { makeTransparentBacking, KEYS, register, SECRETS } from "./support.js";
import { signBacking } from "../src/backing.js";
import { Sequencer } from "../src/sequencer.js";
import { LocalVenue, type Venue } from "../src/venue.js";

// Invariant 8: no clawback, no reversal, no privileged party who can move
// claims. The rule is not "don't call it" — the path must not exist. These
// tests prove every mutation route demands the holder's own signature, and
// that no accessor hands out a live write path into ledger state.

function setup() {
  const ledger = new TransparentLedger();
  const backing = register(ledger, SECRETS.backer);
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { ledger, backing };
}

describe("invariant 8: no privileged party can move a holder's claims", () => {
  it("the backer cannot transfer out of a holding", () => {
    const { ledger, backing } = setup();
    const op = { backing, from: KEYS.alice, to: KEYS.backer, quantity: 100n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), SECRETS.backer))).toThrow(
      /only the holder moves/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("the operator cannot transfer out of a holding", () => {
    const { ledger, backing } = setup();
    const op = { backing, from: KEYS.alice, to: KEYS.operator, quantity: 100n, nonce: 0n };
    expect(() => ledger.transfer(op, ed25519.sign(encodeTransfer(op), SECRETS.operator))).toThrow(
      /only the holder moves/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("the backer cannot burn a holder's claims", () => {
    const { ledger, backing } = setup();
    const op = { backing, holder: KEYS.alice, quantity: 100n, nonce: 0n };
    expect(() => ledger.burn(op, ed25519.sign(encodeBurn(op), SECRETS.backer))).toThrow(
      /only the holder burns/,
    );
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("a signed transfer cannot be reversed by anyone but the new holder", () => {
    const { ledger, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 100n, nonce: 0n };
    ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));

    // Alice regrets it; her signature over a reverse of Bob's holding fails.
    const reverse = { backing, from: KEYS.bob, to: KEYS.alice, quantity: 100n, nonce: 0n };
    expect(() => ledger.transfer(reverse, ed25519.sign(encodeTransfer(reverse), SECRETS.alice))).toThrow(
      /only the holder moves/,
    );
    // Bob's own signature succeeds — reversal is just a new transfer.
    ledger.transfer(reverse, ed25519.sign(encodeTransfer(reverse), SECRETS.bob));
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("a captured message+signature cannot be replayed by a third party", () => {
    const { ledger, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 10n, nonce: 0n };
    const signature = ed25519.sign(encodeTransfer(move), SECRETS.alice);
    ledger.transfer(move, signature);
    expect(() => ledger.transfer(move, signature)).toThrow(NonceError);
    expect(ledger.balance(backing, KEYS.bob)).toBe(10n);
  });
});

describe("invariant 8: accessors expose no mutation path into ledger state", () => {
  it("mutating the map from balancesOf cannot mint units", () => {
    const { ledger, backing } = setup();
    ledger.balancesOf(backing).set(bytesToHex(KEYS.mallory), 10n ** 9n);
    expect(ledger.balance(backing, KEYS.mallory)).toBe(0n);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("mutating the array from opLog cannot fabricate records", () => {
    const { ledger, backing } = setup();
    ledger.opLog(backing).push({
      position: 99,
      kind: "issue",
      recipient: KEYS.mallory,
      quantity: 10n ** 9n,
      nonce: 0n,
      signature: new Uint8Array(64),
    });
    const logged = ledger.opLog(backing)[0]!;
    if (logged.kind === "issue") logged.recipient.fill(0xff);
    expect(ledger.opLog(backing).length).toBe(1);
    expect(ledger.opLog(backing).filter((e) => e.kind === "issue")[0]!.recipient).toEqual(KEYS.alice);
    expect(ledger.outstanding(backing)).toBe(100n);
  });

  it("mutating the key from Sequencer.operator cannot derail the operator", () => {
    // The rule is absolute: no accessor hands out a write path into state. A
    // public Uint8Array field is one, even where the blast radius is only the
    // operator's own service.
    const venue = new LocalVenue();
    const sequencer = new Sequencer(SECRETS.operator, venue);
    const backing = makeTransparentBacking(SECRETS.backer);
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
    sequencer.commit();

    sequencer.operator.fill(0xff);
    expect(sequencer.operator).toEqual(KEYS.operator);
    // Still routes and still commits, on the next sequence.
    expect(sequencer.commit().sequence).toBe(1n);
    expect(venue.nextSequenceFor(KEYS.operator)).toBe(2n);
  });

  it("mutating the secret handed to a Sequencer cannot split its identity", () => {
    // Retained by reference, this one fails silently rather than loudly: the
    // sequencer keeps routing as the operator E names while signing as another,
    // so its declared identity reads as having gone quiet.
    const secret = new Uint8Array(32).fill(0x07);
    const venue = new LocalVenue();
    const sequencer = new Sequencer(secret, venue);
    const backing = makeTransparentBacking(SECRETS.backer);
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
    sequencer.commit();

    secret.fill(0x09);
    const next = sequencer.commit();
    expect(next.operator).toEqual(KEYS.operator);
    expect(venue.latestFor(KEYS.operator)?.sequence).toBe(1n);
  });

  it("mutating a registered backing's key bytes does not re-home its state", () => {
    const { ledger, backing } = setup();
    backing.obligor[0] = (backing.obligor[0] as number) ^ 0x01;
    // The name was fixed at construction, so the backing still resolves.
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });
});

describe("invariant 8: no accessor exposes the key that authorises issuance", () => {
  it("the ledger hands out no Backing object at all", () => {
    const ledger = new TransparentLedger();
    // A live Backing would expose obligor bytes; Object.freeze does not freeze
    // the contents of a Uint8Array, so exposing one is a write path to the key
    // `issue` reads authority from.
    expect((ledger as unknown as Record<string, unknown>)["registered"]).toBeUndefined();
  });

  it("mutating a registered backing's obligor cannot forge issuance", () => {
    const ledger = new TransparentLedger();
    const backing = makeTransparentBacking(SECRETS.backer);
    ledger.register(backing, signBacking(SECRETS.backer, backing));
    // The caller overwrites the obligor in place, then signs as themselves.
    backing.obligor.set(KEYS.mallory);
    const op = { backing, recipient: KEYS.alice, quantity: 10n ** 9n, nonce: 0n };
    expect(() => ledger.issue(op, ed25519.sign(encodeIssuance(op), SECRETS.mallory))).toThrow();
    expect(ledger.outstanding(backing)).toBe(0n);
  });

  it("a snapshot's name is a copy, not the ledger's own array", () => {
    const ledger = new TransparentLedger();
    const backing = register(ledger, SECRETS.backer);
    const snap = ledger.snapshotAll()[0]!;
    const before = snap.name.slice();
    snap.name.fill(0xff);
    expect(ledger.snapshotAll()[0]!.name).toEqual(before);
  });
});
