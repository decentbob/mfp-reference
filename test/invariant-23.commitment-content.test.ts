import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { signBacking } from "../src/backing.js";
import { stateRoot } from "../src/commitment.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { TransparentLedger } from "../src/ledger.js";
import {
  advanceWitnessedIndex,
  KEYS,
  makeTransparentBacking,
  register,
  SECRETS,
} from "./support.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
  encodeWithdrawal,
} from "../src/presentation.js";
import { opMessageOfEntry } from "../src/oplog.js";

// Invariant 23: a commitment commits to the issuance log, the spent set, and
// running totals. In the transparent subset that means the root must move
// when issued, burned, balances, or the operation log change — and two
// sequencers with identical served state must produce the identical root.

function fresh() {
  const sequencer = new Sequencer(SECRETS.operator, new Venue());
  const backing = makeTransparentBacking(SECRETS.backer);
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
    const eur = makeTransparentBacking(SECRETS.backer, "EUR");
    const kwh = makeTransparentBacking(SECRETS.backer2, "kWh");
    const a = new Sequencer(SECRETS.operator, new Venue());
    a.register(eur, signBacking(SECRETS.backer, eur));
    a.register(kwh, signBacking(SECRETS.backer2, kwh));
    const b = new Sequencer(SECRETS.operator, new Venue());
    b.register(kwh, signBacking(SECRETS.backer2, kwh));
    b.register(eur, signBacking(SECRETS.backer, eur));
    expect(rootOf(a)).toBe(rootOf(b));
  });
});

// Invariant 23 lists the standing demand record alongside the issuance log and
// running totals as something a commitment commits to. A holder must be able
// to prove their claims are committed against payment.

describe("invariant 23: the commitment commits to the standing demand record", () => {
  it("filing a demand moves the root, and answering it moves it again", () => {
    const ledger = new TransparentLedger();
    const backing = register(ledger, SECRETS.backer);
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    const rootNow = () => bytesToHex(stateRoot(ledger.snapshotAll()));
    const beforeDemand = rootNow();

    const demand = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: ledger.nextNonce(KEYS.alice, backing),
    };
    ledger.demand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice), 5n);
    const afterDemand = rootNow();
    // Balances have not moved - only the standing demand record has.
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
    expect(afterDemand).not.toBe(beforeDemand);

    const answer = {
      backing,
      demandHash: demandHash(demand),
      instant: 5n,
      deadline: 8n,
      nonce: ledger.nextNonce(KEYS.backer, backing),
    };
    ledger.accept(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer), 5n);
    expect(rootNow()).not.toBe(afterDemand);
  });
});

// The commitment now commits to the presentation trail as well: the standing
// demand record (the current state) and the operation-log entries (the history).
// Both are named in invariant 23, and a withdrawal or a settlement removes the
// record while the log keeps the fact.

describe("invariant 23: every presentation operation moves the root", () => {
  function sequencerAt(index: bigint) {
    const { sequencer, backing } = fresh();
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
    advanceWitnessedIndex(sequencer, index);
    return { sequencer, backing };
  }

  it("demand, acceptance and release each move it", () => {
    const { sequencer, backing } = sequencerAt(5n);
    const roots = [rootOf(sequencer)];

    const demand = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
    roots.push(rootOf(sequencer));
    // Balances have not moved - only the demand record and the log have.
    expect(sequencer.balance(backing, KEYS.alice)).toBe(100n);

    const answer = {
      backing,
      demandHash: demandHash(demand),
      instant: 5n,
      deadline: 8n,
      nonce: sequencer.nextNonce(KEYS.backer, backing),
    };
    sequencer.submitAcceptance(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer));
    roots.push(rootOf(sequencer));

    const settle = {
      backing,
      demandHash: demandHash(demand),
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    sequencer.submitRelease(settle, ed25519.sign(encodeRelease(settle), SECRETS.alice));
    roots.push(rootOf(sequencer));

    expect(new Set(roots).size).toBe(roots.length);
  });

  it("a withdrawal moves it, and the log entry is what remains", () => {
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
    const withDemand = rootOf(sequencer);
    advanceWitnessedIndex(sequencer, 11n);

    const walk = {
      backing,
      demandHash: demandHash(demand),
      nonce: sequencer.nextNonce(KEYS.alice, backing),
    };
    sequencer.submitWithdrawal(walk, ed25519.sign(encodeWithdrawal(walk), SECRETS.alice));
    expect(rootOf(sequencer)).not.toBe(withDemand);
    const snapshot = sequencer.snapshot()[0]!;
    expect(snapshot.demands).toHaveLength(0);
    expect(snapshot.opLog.map((entry) => entry.kind)).toEqual(["issue", "demand", "withdrawal"]);
  });

  it("the committed log entry is byte-identical to what the party signed", () => {
    // The commitment commits the signed message itself, so "the entry
    // reconstructs to the receipt's op hash" holds by construction rather than
    // by two encoders agreeing.
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
    const entry = sequencer.snapshot()[0]!.opLog[1]!;
    expect(opMessageOfEntry(backing.name, entry)).toEqual(encodeDemand(demand));
  });
});
