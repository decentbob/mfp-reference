import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { isDishonoured, LedgerError, TransparentLedger } from "../src/ledger.js";
import { encodeBurn, encodeIssuance, encodeTransfer } from "../src/messages.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
  encodeWithdrawal,
} from "../src/presentation.js";
import { KEYS, register, SECRETS } from "./support.js";

// Invariant 27: settling a published demand voids the exact claims offered,
// and only on the holder's release signature. A backer must never void
// unilaterally, or non-payment can be recorded as settlement.
//
// Presentation is demand - accept - release (§C3). Dishonour is not a separate
// mechanism: it is the branch where the acceptance never arrives.

function setup() {
  const ledger = new TransparentLedger();
  const backing = register(ledger, SECRETS.backer);
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { ledger, backing };
}

/** File a demand for `quantity`, returning its record and the op that made it. */
function present(
  ledger: TransparentLedger,
  backing: ReturnType<typeof register>,
  quantity: bigint,
  deadline = 10n,
) {
  const op = {
    backing,
    holder: KEYS.alice,
    quantity,
    instant: 5n,
    deadline,
    nonce: ledger.nextNonce(KEYS.alice, backing),
  };
  ledger.demand(op, ed25519.sign(encodeDemand(op), SECRETS.alice));
  return { op, hash: demandHash(op) };
}

function accept(
  ledger: TransparentLedger,
  backing: ReturnType<typeof register>,
  hash: Uint8Array,
  instant = 5n,
) {
  const op = {
    backing,
    demandHash: hash,
    instant,
    deadline: 20n,
    nonce: ledger.nextNonce(KEYS.backer, backing),
  };
  ledger.accept(op, ed25519.sign(encodeAcceptance(op), SECRETS.backer));
  return op;
}

describe("invariant 27: settlement takes two signatures", () => {
  it("acceptance plus release moves exactly the quantity offered to the backer", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    accept(ledger, backing, hash);

    const rel = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
    ledger.release(rel, ed25519.sign(encodeRelease(rel), SECRETS.alice));

    expect(ledger.balance(backing, KEYS.alice)).toBe(60n);
    expect(ledger.balance(backing, KEYS.backer)).toBe(40n);
    // Presentation destroys nothing (invariant 10): the backer is now holder.
    expect(ledger.outstanding(backing)).toBe(100n);
    expect(ledger.openDemands(backing)).toHaveLength(0);
  });

  it("a release without an acceptance settles nothing", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    const rel = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
    expect(() => ledger.release(rel, ed25519.sign(encodeRelease(rel), SECRETS.alice))).toThrow(
      /has not been accepted/,
    );
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("an acceptance alone moves nothing: the backer cannot void unilaterally", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    accept(ledger, backing, hash);
    // The backer has answered, and still holds nothing: only the holder's
    // release can void, or non-payment would be recorded as settlement.
    expect(ledger.balance(backing, KEYS.backer)).toBe(0n);
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
    expect(ledger.openDemands(backing)).toHaveLength(1);
  });

  it("the backer cannot forge the holder's release", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    accept(ledger, backing, hash);
    const rel = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
    expect(() => ledger.release(rel, ed25519.sign(encodeRelease(rel), SECRETS.backer))).toThrow(
      /only the holder releases/,
    );
    expect(ledger.balance(backing, KEYS.backer)).toBe(0n);
  });

  it("only the obligor answers a demand", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    const op = {
      backing,
      demandHash: hash,
      instant: 5n,
      deadline: 20n,
      nonce: ledger.nextNonce(KEYS.mallory, backing),
    };
    expect(() => ledger.accept(op, ed25519.sign(encodeAcceptance(op), SECRETS.mallory))).toThrow(
      LedgerError,
    );
    expect(ledger.openDemands(backing)[0]?.acceptedDeadline).toBeUndefined();
  });
});

describe("invariant 24: the acceptance agrees the demand's instant", () => {
  it("an acceptance naming a different instant is rejected", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    expect(() => accept(ledger, backing, hash, 6n)).toThrow(/does not agree/);
  });
});

describe("§C3: a demand commits the claims it names", () => {
  it("committed units cannot be transferred or burned", () => {
    const { ledger, backing } = setup();
    present(ledger, backing, 80n);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(20n);

    const move = {
      backing,
      from: KEYS.alice,
      to: KEYS.bob,
      quantity: 30n,
      nonce: ledger.nextNonce(KEYS.alice, backing),
    };
    expect(() => ledger.transfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice))).toThrow(
      /insufficient balance/,
    );
    const burn = {
      backing,
      holder: KEYS.alice,
      quantity: 30n,
      nonce: ledger.nextNonce(KEYS.alice, backing),
    };
    expect(() => ledger.burn(burn, ed25519.sign(encodeBurn(burn), SECRETS.alice))).toThrow(
      /insufficient balance/,
    );
    // The uncommitted remainder still moves freely.
    const small = { ...move, quantity: 20n, nonce: ledger.nextNonce(KEYS.alice, backing) };
    ledger.transfer(small, ed25519.sign(encodeTransfer(small), SECRETS.alice));
    expect(ledger.balance(backing, KEYS.bob)).toBe(20n);
  });

  it("one holding cannot answer two demands", () => {
    const { ledger, backing } = setup();
    present(ledger, backing, 80n);
    expect(() => present(ledger, backing, 40n)).toThrow(/insufficient balance/);
  });

  it("only the holder presents their own holding", () => {
    const { ledger, backing } = setup();
    const op = {
      backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: ledger.nextNonce(KEYS.alice, backing),
    };
    expect(() => ledger.demand(op, ed25519.sign(encodeDemand(op), SECRETS.mallory))).toThrow(
      /only the holder presents/,
    );
  });
});

describe("§C3: an unanswered demand stands, and withdrawal is the way out", () => {
  it("the deadline makes non-payment public but does not end the commitment", () => {
    const { ledger, backing } = setup();
    present(ledger, backing, 80n, 10n);
    const record = ledger.openDemands(backing)[0]!;

    // Well past the deadline, the claims are still committed.
    expect(isDishonoured(record, 11n)).toBe(true);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(20n);
    expect(ledger.openDemands(backing)).toHaveLength(1);
  });

  it("dishonour is the branch where the acceptance never arrives", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n, 10n);
    expect(isDishonoured(ledger.openDemands(backing)[0]!, 10n)).toBe(false); // not yet past
    expect(isDishonoured(ledger.openDemands(backing)[0]!, 11n)).toBe(true);
    accept(ledger, backing, hash);
    expect(isDishonoured(ledger.openDemands(backing)[0]!, 999n)).toBe(false);
  });

  it("withdrawal is unilateral and frees the claims", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n);
    const wd = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
    ledger.withdraw(wd, ed25519.sign(encodeWithdrawal(wd), SECRETS.alice));
    expect(ledger.openDemands(backing)).toHaveLength(0);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(100n);
  });

  it("the backer cannot withdraw the holder's demand", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n);
    const wd = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
    expect(() => ledger.withdraw(wd, ed25519.sign(encodeWithdrawal(wd), SECRETS.backer))).toThrow(
      /only the holder withdraws/,
    );
    expect(ledger.openDemands(backing)).toHaveLength(1);
  });

  it("an accepted demand cannot be withdrawn", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    accept(ledger, backing, hash);
    const wd = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
    expect(() => ledger.withdraw(wd, ed25519.sign(encodeWithdrawal(wd), SECRETS.alice))).toThrow(
      /accepted demand cannot be withdrawn/,
    );
  });
});
