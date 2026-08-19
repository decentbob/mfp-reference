import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { acceptanceIsLive, isDishonoured, LedgerError, TransparentLedger } from "../src/ledger.js";
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
//
// Witnessed indices are parameters here, supplied by whoever witnesses;
// invariant 21 forbids a time the holder asserts alone, and through the
// sequencer the index comes from the operator's own latest commitment. The
// demand's own deadline is 10 and an acceptance's is 8 throughout, so "index 5"
// is live, "index 9" is past the acceptance's deadline, and "index 11" is past
// the demand's.

function setup() {
  const ledger = new TransparentLedger();
  const backing = register(ledger, SECRETS.backer);
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  ledger.issue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { ledger, backing };
}

type Backing = ReturnType<typeof register>;

function present(
  ledger: TransparentLedger,
  backing: Backing,
  quantity: bigint,
  deadline = 10n,
  at = 5n,
) {
  const op = {
    backing,
    holder: KEYS.alice,
    quantity,
    instant: 5n,
    deadline,
    nonce: ledger.nextNonce(KEYS.alice, backing),
  };
  const entry = ledger.demand(op, ed25519.sign(encodeDemand(op), SECRETS.alice), at);
  return { op, entry, hash: demandHash(op) };
}

function accept(
  ledger: TransparentLedger,
  backing: Backing,
  hash: Uint8Array,
  { instant = 5n, deadline = 8n, at = 5n } = {},
) {
  const op = {
    backing,
    demandHash: hash,
    instant,
    deadline,
    nonce: ledger.nextNonce(KEYS.backer, backing),
  };
  ledger.accept(op, ed25519.sign(encodeAcceptance(op), SECRETS.backer), at);
  return op;
}

function release(ledger: TransparentLedger, backing: Backing, hash: Uint8Array, at = 6n) {
  const op = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
  return ledger.release(op, ed25519.sign(encodeRelease(op), SECRETS.alice), at);
}

function withdraw(ledger: TransparentLedger, backing: Backing, hash: Uint8Array, at = 6n) {
  const op = { backing, demandHash: hash, nonce: ledger.nextNonce(KEYS.alice, backing) };
  return ledger.withdraw(op, ed25519.sign(encodeWithdrawal(op), SECRETS.alice), at);
}

describe("invariant 27: settlement takes two signatures", () => {
  it("acceptance plus release moves exactly the quantity offered to the backer", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    accept(ledger, backing, hash);
    release(ledger, backing, hash);

    expect(ledger.balance(backing, KEYS.alice)).toBe(60n);
    expect(ledger.balance(backing, KEYS.backer)).toBe(40n);
    // Presentation destroys nothing (invariant 10): the backer is now holder.
    expect(ledger.outstanding(backing)).toBe(100n);
    expect(ledger.openDemands(backing)).toHaveLength(0);
  });

  it("a release without an acceptance settles nothing", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    expect(() => release(ledger, backing, hash)).toThrow(/no live acceptance/);
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("an acceptance alone moves nothing: the backer cannot void unilaterally", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    accept(ledger, backing, hash);
    expect(ledger.balance(backing, KEYS.backer)).toBe(0n);
    expect(ledger.balance(backing, KEYS.alice)).toBe(100n);
    expect(ledger.openDemands(backing)).toHaveLength(1);
  });

  it("the backer cannot forge the holder's release", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    accept(ledger, backing, hash);
    const nonceBefore = ledger.nextNonce(KEYS.alice, backing);
    const op = { backing, demandHash: hash, nonce: nonceBefore };
    expect(() => ledger.release(op, ed25519.sign(encodeRelease(op), SECRETS.backer), 6n)).toThrow(
      /only the holder releases/,
    );
    expect(ledger.balance(backing, KEYS.backer)).toBe(0n);
    expect(ledger.openDemands(backing)).toHaveLength(1);
    // A rejected operation consumes nothing.
    expect(ledger.nextNonce(KEYS.alice, backing)).toBe(nonceBefore);
  });

  it("only the obligor answers a demand", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n);
    const op = {
      backing,
      demandHash: hash,
      instant: 5n,
      deadline: 8n,
      nonce: ledger.nextNonce(KEYS.mallory, backing),
    };
    expect(() =>
      ledger.accept(op, ed25519.sign(encodeAcceptance(op), SECRETS.mallory), 5n),
    ).toThrow(LedgerError);
    expect(ledger.openDemands(backing)[0]?.acceptedDeadline).toBeUndefined();
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
    expect(() => ledger.demand(op, ed25519.sign(encodeDemand(op), SECRETS.mallory), 5n)).toThrow(
      /only the holder presents/,
    );
  });

  it("a demand on one backing cannot be answered against another", () => {
    const ledger = new TransparentLedger();
    const eur = register(ledger, SECRETS.backer, "EUR");
    const kwh = register(ledger, SECRETS.backer2, "kWh");
    for (const [backing, secret] of [
      [eur, SECRETS.backer],
      [kwh, SECRETS.backer2],
    ] as const) {
      const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
      ledger.issue(issue, ed25519.sign(encodeIssuance(issue), secret));
    }
    const { hash } = present(ledger, eur, 40n);
    // The same hash means nothing in kWh's book.
    const op = {
      backing: kwh,
      demandHash: hash,
      instant: 5n,
      deadline: 8n,
      nonce: ledger.nextNonce(KEYS.backer2, kwh),
    };
    expect(() =>
      ledger.accept(op, ed25519.sign(encodeAcceptance(op), SECRETS.backer2), 5n),
    ).toThrow(/no such standing demand/);
  });

  it("a returned demand record is a copy", () => {
    const { ledger, backing } = setup();
    present(ledger, backing, 40n);
    const record = ledger.openDemands(backing)[0]!;
    record.holder.fill(0xff);
    record.hash.fill(0xff);
    const fresh = ledger.openDemands(backing)[0]!;
    expect(fresh.holder).toEqual(KEYS.alice);
    expect(fresh.hash).not.toEqual(record.hash);
  });
});

describe("§C3: an unanswered demand stands, and withdrawal is the way out", () => {
  it("the deadline makes non-payment public but does not end the commitment", () => {
    const { ledger, backing } = setup();
    present(ledger, backing, 80n, 10n);
    const record = ledger.openDemands(backing)[0]!;
    expect(isDishonoured(record, 11n)).toBe(true);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(20n);
    expect(ledger.openDemands(backing)).toHaveLength(1);
  });

  it("dishonour is the branch where no live acceptance arrives", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 40n, 10n);
    expect(isDishonoured(ledger.openDemands(backing)[0]!, 10n)).toBe(false);
    expect(isDishonoured(ledger.openDemands(backing)[0]!, 11n)).toBe(true);
    // A live acceptance is an answer, so while it stands there is no dishonour.
    accept(ledger, backing, hash, { deadline: 8n });
    expect(isDishonoured(ledger.openDemands(backing)[0]!, 7n)).toBe(false);
  });

  it("withdrawal is unilateral and frees the claims", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n);
    withdraw(ledger, backing, hash);
    expect(ledger.openDemands(backing)).toHaveLength(0);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(100n);
  });

  it("the backer cannot withdraw the holder's demand", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n);
    const nonceBefore = ledger.nextNonce(KEYS.alice, backing);
    const op = { backing, demandHash: hash, nonce: nonceBefore };
    expect(() =>
      ledger.withdraw(op, ed25519.sign(encodeWithdrawal(op), SECRETS.backer), 6n),
    ).toThrow(/only the holder withdraws/);
    expect(ledger.openDemands(backing)).toHaveLength(1);
    expect(ledger.nextNonce(KEYS.alice, backing)).toBe(nonceBefore);
  });
});

// An acceptance is free to sign and moves no value. If it locked the holder's
// claims forever, one signature would sterilise them: the backer could accept,
// never pay, and the holder could neither spend nor walk away. The acceptance
// therefore carries its own deadline, that deadline is enforced, and it may not
// outlast the window the holder chose.

describe("§C3: an acceptance is an answer, not a trap", () => {
  it("a live acceptance holds the claims", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n);
    accept(ledger, backing, hash, { deadline: 8n });
    expect(() => withdraw(ledger, backing, hash, 8n)).toThrow(/live acceptance stands/);
  });

  it("once the acceptance expires the claims are the holder's again", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n);
    accept(ledger, backing, hash, { deadline: 8n });
    withdraw(ledger, backing, hash, 9n);
    expect(ledger.openDemands(backing)).toHaveLength(0);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(100n);
  });

  it("settlement against an expired acceptance is refused", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n);
    accept(ledger, backing, hash, { deadline: 8n });
    expect(() => release(ledger, backing, hash, 9n)).toThrow(/no live acceptance/);
    expect(ledger.balance(backing, KEYS.backer)).toBe(0n);
  });

  it("a backer cannot answer a demand it has already dishonoured", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n, 10n);
    // Past the deadline no legal acceptance deadline is left, so the answer is
    // refused: the holder has earned the right to walk away, and the backer
    // must not be able to convert its own failure into a lock.
    expect(() => accept(ledger, backing, hash, { deadline: 11n, at: 11n })).toThrow(
      /acceptance deadline/,
    );
    withdraw(ledger, backing, hash, 11n);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(100n);
  });
});

// Two holes this closes, each demonstrated by a working exploit before the fix.

describe("§C3: an acceptance cannot launder the backer's own failure", () => {
  it("an acceptance whose deadline is already past cannot be signed", () => {
    // The exploit: a free signature naming a deadline nobody can release
    // against, which under the old rule made the demand permanently
    // un-dishonourable and burned the only acceptance slot.
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n, 10n);
    expect(() => accept(ledger, backing, hash, { deadline: 1n, at: 5n })).toThrow(
      /acceptance deadline/,
    );
    expect(ledger.openDemands(backing)[0]?.acceptedDeadline).toBeUndefined();
    expect(isDishonoured(ledger.openDemands(backing)[0]!, 11n)).toBe(true);
  });

  it("an acceptance that expires unpaid leaves the demand dishonoured", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n, 10n);
    accept(ledger, backing, hash, { deadline: 8n, at: 5n });
    const record = ledger.openDemands(backing)[0]!;
    expect(record.acceptedDeadline).toBe(8n);
    expect(ledger.balance(backing, KEYS.backer)).toBe(0n);
    // Past the demand's own deadline, with no live acceptance and nothing paid,
    // non-payment is a public fact.
    expect(isDishonoured(record, 11n)).toBe(true);
    expect(isDishonoured(record, 1_000_000n)).toBe(true);
  });

  it("an acceptance may not outlast the demand's own deadline", () => {
    // The exploit: the holder chose a five-index lock-up, the backer answered on
    // the last legal index with a deadline of a million, paid nothing, and froze
    // the claims. "The window is the holder's."
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 100n, 10n);
    expect(() => accept(ledger, backing, hash, { deadline: 1_000_000n, at: 10n })).toThrow(
      /no later than the demand's deadline/,
    );
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(0n);
    withdraw(ledger, backing, hash, 11n);
    expect(ledger.availableBalance(backing, KEYS.alice)).toBe(100n);
  });

  it("the backer may answer again once its own acceptance has expired", () => {
    // Bounded by the demand's deadline, which the holder set, so re-answering
    // cannot extend the lock-up past the holder's own term.
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n, 10n);
    accept(ledger, backing, hash, { deadline: 7n, at: 5n });
    accept(ledger, backing, hash, { deadline: 10n, at: 8n });
    expect(ledger.openDemands(backing)[0]?.acceptedDeadline).toBe(10n);
    release(ledger, backing, hash, 10n);
    expect(ledger.balance(backing, KEYS.backer)).toBe(80n);
  });

  it("a second acceptance while one is live is refused", () => {
    const { ledger, backing } = setup();
    const { hash } = present(ledger, backing, 80n, 10n);
    accept(ledger, backing, hash, { deadline: 8n, at: 5n });
    expect(() => accept(ledger, backing, hash, { deadline: 10n, at: 6n })).toThrow(
      /live acceptance already stands/,
    );
    expect(ledger.openDemands(backing)[0]?.acceptedDeadline).toBe(8n);
  });

  it("past the holder's own deadline the holder is always free", () => {
    // Because an acceptance may not outlast the demand's deadline, no acceptance
    // can be live past it — so withdrawal is unconditionally open and dishonour
    // unconditionally reported, whatever the backer signed.
    for (const acceptanceDeadline of [undefined, 5n, 8n, 10n]) {
      const { ledger, backing } = setup();
      const { hash } = present(ledger, backing, 80n, 10n);
      if (acceptanceDeadline !== undefined) {
        accept(ledger, backing, hash, { deadline: acceptanceDeadline, at: 5n });
      }
      const record = ledger.openDemands(backing)[0]!;
      expect(acceptanceIsLive(record, 11n)).toBe(false);
      expect(isDishonoured(record, 11n)).toBe(true);
      withdraw(ledger, backing, hash, 11n);
      expect(ledger.availableBalance(backing, KEYS.alice)).toBe(100n);
    }
  });

  it("exactly one exit is open at every index", () => {
    // Release and withdrawal are complements on one predicate, so the holder
    // always has exactly one way out and never two or none.
    for (let at = 5n; at <= 13n; at++) {
      for (const accepted of [false, true]) {
        const settle = setup();
        const settleHash = present(settle.ledger, settle.backing, 80n, 10n).hash;
        if (accepted) accept(settle.ledger, settle.backing, settleHash, { deadline: 8n, at: 5n });
        let released = true;
        try {
          release(settle.ledger, settle.backing, settleHash, at);
        } catch {
          released = false;
        }

        const walk = setup();
        const walkHash = present(walk.ledger, walk.backing, 80n, 10n).hash;
        if (accepted) accept(walk.ledger, walk.backing, walkHash, { deadline: 8n, at: 5n });
        let withdrew = true;
        try {
          withdraw(walk.ledger, walk.backing, walkHash, at);
        } catch {
          withdrew = false;
        }

        expect([at, accepted, released, withdrew]).toEqual([at, accepted, released, !released]);
      }
    }
  });
});
