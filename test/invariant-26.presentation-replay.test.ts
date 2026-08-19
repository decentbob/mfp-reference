import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { signBacking } from "../src/backing.js";
import { NonceError } from "../src/ledger.js";
import { encodeIssuance } from "../src/messages.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
  encodeWithdrawal,
} from "../src/presentation.js";
import { receiptProvenBy, verifyReceipt } from "../src/receipt.js";
import { replayLog } from "../src/oplog.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { advanceWitnessedIndex, KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// Invariant 26: "The swap is idempotent, and so is presentation. A repeated
// request returns the identical prior response... The rule covers locks and
// releases, so partition recovery simply repeats the request."
//
// Slice 4 left demand/accept/release/withdraw reachable only on the ledger,
// because a receipt binds an operation to its position in the operation log and
// those three move no value, so they had no position. The operation log now
// carries presentation kinds, so all four get positions, receipts and replay
// through the one submit path the value-moving operations already used — no
// second idempotency mechanism.
//
// The witnessed index is no longer a caller's parameter here: the sequencer
// reads it from the venue, which is what invariant 21 requires and what slice 4
// could not supply. That the clock is the venue's rather than the operator's own
// publication history is invariant-21.witnessed-time's subject.

/** Issue 100 to Alice, then publish commitments up to witnessed index 5. */
function setup() {
  const venue = new Venue();
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  venue.advance(5n);
  return { venue, sequencer, backing };
}

type Fixture = ReturnType<typeof setup>;

function demandOp({ sequencer, backing }: Fixture, quantity = 40n, deadline = 10n) {
  return {
    backing,
    holder: KEYS.alice,
    quantity,
    instant: 5n,
    deadline,
    nonce: sequencer.nextNonce(KEYS.alice, backing),
  };
}

function present(f: Fixture, quantity = 40n, deadline = 10n) {
  const op = demandOp(f, quantity, deadline);
  const signature = ed25519.sign(encodeDemand(op), SECRETS.alice);
  return { op, signature, hash: demandHash(op), receipt: f.sequencer.submitDemand(op, signature) };
}

function acceptOp({ sequencer, backing }: Fixture, hash: Uint8Array, deadline = 8n) {
  return {
    backing,
    demandHash: hash,
    instant: 5n,
    deadline,
    nonce: sequencer.nextNonce(KEYS.backer, backing),
  };
}

function accept(f: Fixture, hash: Uint8Array, deadline = 8n) {
  const op = acceptOp(f, hash, deadline);
  const signature = ed25519.sign(encodeAcceptance(op), SECRETS.backer);
  return { op, signature, receipt: f.sequencer.submitAcceptance(op, signature) };
}

function releaseOp({ sequencer, backing }: Fixture, hash: Uint8Array) {
  return { backing, demandHash: hash, nonce: sequencer.nextNonce(KEYS.alice, backing) };
}

function release(f: Fixture, hash: Uint8Array) {
  const op = releaseOp(f, hash);
  const signature = ed25519.sign(encodeRelease(op), SECRETS.alice);
  return { op, signature, receipt: f.sequencer.submitRelease(op, signature) };
}

function withdraw(f: Fixture, hash: Uint8Array) {
  const op = { backing: f.backing, demandHash: hash, nonce: f.sequencer.nextNonce(KEYS.alice, f.backing) };
  const signature = ed25519.sign(encodeWithdrawal(op), SECRETS.alice);
  return { op, signature, receipt: f.sequencer.submitWithdrawal(op, signature) };
}

describe("invariant 26: presentation is sequenced, and sequenced means receipted", () => {
  it("each presentation operation takes the next position in the operation log", () => {
    const f = setup();
    const { hash, receipt } = present(f);
    // The issuance took position 0.
    expect(receipt.position).toBe(1n);
    expect(accept(f, hash).receipt.position).toBe(2n);
    expect(release(f, hash).receipt.position).toBe(3n);
    expect(f.sequencer.opLog(f.backing).map((entry) => entry.kind)).toEqual([
      "issue",
      "demand",
      "acceptance",
      "release",
    ]);
  });

  it("a withdrawal is logged too, so the trail records the demand that ended", () => {
    const f = setup();
    const { hash } = present(f, 40n, 10n);
    advanceWitnessedIndex(f.venue, 11n);
    expect(withdraw(f, hash).receipt.position).toBe(2n);
    expect(f.sequencer.opLog(f.backing).map((entry) => entry.kind)).toEqual([
      "issue",
      "demand",
      "withdrawal",
    ]);
  });

  it("every presentation receipt is a valid operator co-signature", () => {
    const f = setup();
    const { hash, receipt: demandReceipt } = present(f);
    const { receipt: acceptReceipt } = accept(f, hash);
    const { receipt: releaseReceipt } = release(f, hash);
    for (const receipt of [demandReceipt, acceptReceipt, releaseReceipt]) {
      expect(verifyReceipt(receipt)).toBe(true);
      expect(receipt.operator).toEqual(f.sequencer.operator);
    }
  });
});

describe("invariant 26: a repeated presentation request returns the identical response", () => {
  it("resubmitting a demand returns the identical receipt and files nothing twice", () => {
    const f = setup();
    const { op, signature, receipt } = present(f, 40n);
    const again = f.sequencer.submitDemand(op, signature);
    expect(again).toEqual(receipt);
    expect(f.sequencer.openDemands(f.backing)).toHaveLength(1);
    expect(f.sequencer.availableBalance(f.backing, KEYS.alice)).toBe(60n);
  });

  it("resubmitting an acceptance returns the identical receipt", () => {
    const f = setup();
    const { hash } = present(f);
    const { op, signature, receipt } = accept(f, hash);
    expect(f.sequencer.submitAcceptance(op, signature)).toEqual(receipt);
    expect(f.sequencer.opLog(f.backing)).toHaveLength(3);
  });

  it("resubmitting a release settles once, not twice", () => {
    const f = setup();
    const { hash } = present(f, 40n);
    accept(f, hash);
    const { op, signature, receipt } = release(f, hash);
    expect(f.sequencer.submitRelease(op, signature)).toEqual(receipt);
    expect(f.sequencer.balance(f.backing, KEYS.backer)).toBe(40n);
    expect(f.sequencer.balance(f.backing, KEYS.alice)).toBe(60n);
  });

  it("resubmitting a withdrawal returns the identical receipt", () => {
    const f = setup();
    const { hash } = present(f, 40n);
    advanceWitnessedIndex(f.venue, 11n);
    const { op, signature, receipt } = withdraw(f, hash);
    expect(f.sequencer.submitWithdrawal(op, signature)).toEqual(receipt);
    expect(f.sequencer.openDemands(f.backing)).toHaveLength(0);
  });

  it("a replay is answered from the store, so the clock moving cannot change it", () => {
    // "A crash loses nothing": the same signed acceptance resubmitted after its
    // own deadline has passed must still return the prior receipt rather than
    // being re-judged against a clock that has moved on.
    const f = setup();
    const { hash } = present(f);
    const { op, signature, receipt } = accept(f, hash, 8n);
    advanceWitnessedIndex(f.venue, 50n);
    expect(f.sequencer.submitAcceptance(op, signature)).toEqual(receipt);
  });

  it("a different demand at an already-spent nonce is refused", () => {
    const f = setup();
    const { op } = present(f, 40n);
    const conflicting = { ...op, quantity: 50n };
    expect(() =>
      f.sequencer.submitDemand(conflicting, ed25519.sign(encodeDemand(conflicting), SECRETS.alice)),
    ).toThrow(NonceError);
    expect(f.sequencer.availableBalance(f.backing, KEYS.alice)).toBe(60n);
  });

  it("a rejected presentation records nothing, so a later valid one at that nonce succeeds", () => {
    const f = setup();
    // Wrong signer: the ledger refuses and nothing is stored.
    const op = demandOp(f, 40n);
    expect(() =>
      f.sequencer.submitDemand(op, ed25519.sign(encodeDemand(op), SECRETS.mallory)),
    ).toThrow(/only the holder presents/);
    const receipt = f.sequencer.submitDemand(op, ed25519.sign(encodeDemand(op), SECRETS.alice));
    expect(receipt.position).toBe(1n);
  });
});

describe("invariant 26: a presentation receipt proves against committed state", () => {
  it("holds for all four presentation kinds", () => {
    const f = setup();
    const { hash, receipt: demandReceipt } = present(f);
    const { receipt: acceptReceipt } = accept(f, hash);
    const { receipt: releaseReceipt } = release(f, hash);
    const snapshot = f.sequencer.snapshot()[0]!;
    for (const receipt of [demandReceipt, acceptReceipt, releaseReceipt]) {
      expect(receiptProvenBy(receipt, snapshot)).toBe(true);
    }
  });

  it("a withdrawal receipt still proves once the demand record is pruned", () => {
    // The standing record is removed at withdrawal, but the log is append-only,
    // so the operator cannot deny having accepted the withdrawal.
    const f = setup();
    const { hash } = present(f, 40n);
    advanceWitnessedIndex(f.venue, 11n);
    const { receipt } = withdraw(f, hash);
    const snapshot = f.sequencer.snapshot()[0]!;
    expect(replayLog(f.backing, snapshot.opLog)!.demands).toHaveLength(0);
    expect(receiptProvenBy(receipt, snapshot)).toBe(true);
  });

  it("a settled demand's own terms survive in the log after the record is gone", () => {
    const f = setup();
    const { hash } = present(f, 40n);
    accept(f, hash);
    release(f, hash);
    const snapshot = f.sequencer.snapshot()[0]!;
    expect(replayLog(f.backing, snapshot.opLog)!.demands).toHaveLength(0);
    const logged = snapshot.opLog.find((entry) => entry.kind === "demand");
    expect(logged).toMatchObject({ quantity: 40n, instant: 5n, deadline: 10n });
  });

  it("tampering with a logged demand's quantity breaks its receipt", () => {
    const f = setup();
    const { receipt } = present(f, 40n);
    const snapshot = f.sequencer.snapshot()[0]!;
    const tampered = {
      ...snapshot,
      opLog: snapshot.opLog.map((entry) =>
        entry.kind === "demand" ? { ...entry, quantity: entry.quantity + 1n } : entry,
      ),
    };
    expect(receiptProvenBy(receipt, tampered)).toBe(false);
  });

  it("tampering with a logged release's demand hash breaks its receipt", () => {
    const f = setup();
    const { hash } = present(f, 40n);
    accept(f, hash);
    const { receipt } = release(f, hash);
    const snapshot = f.sequencer.snapshot()[0]!;
    const tampered = {
      ...snapshot,
      opLog: snapshot.opLog.map((entry) =>
        entry.kind === "release"
          ? { ...entry, demandHash: new Uint8Array(32).fill(0xff) }
          : entry,
      ),
    };
    expect(receiptProvenBy(receipt, tampered)).toBe(false);
  });
});

describe("the sequencer owns routing and the clock", () => {
  it("presentation against a backing it does not serve is refused", () => {
    const venue = new Venue();
    const sequencer = new Sequencer(SECRETS.operator, venue);
    const backing = makeTransparentBacking(SECRETS.backer);
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 0n,
      deadline: 10n,
      nonce: 0n,
    };
    expect(() => sequencer.submitDemand(op, ed25519.sign(encodeDemand(op), SECRETS.alice))).toThrow(
      SequencerError,
    );
  });

  it("the clock it reads is the venue's", () => {
    const f = setup();
    expect(f.sequencer.witnessedIndex()).toBe(5n);
    f.venue.advance();
    expect(f.sequencer.witnessedIndex()).toBe(6n);
  });
});
