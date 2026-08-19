import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { signBacking } from "../src/backing.js";
import { signCommitment, stateProvesCommitment, stateRoot } from "../src/commitment.js";
import { encodeIssuance, encodeTransfer } from "../src/messages.js";
import { entriesAreAuthentic, foldBalances } from "../src/oplog.js";
import {
  demandHash,
  encodeAcceptance,
  encodeDemand,
  encodeRelease,
  encodeWithdrawal,
} from "../src/presentation.js";
import { provesHolding, stateIsAuthentic } from "../src/recovery.js";
import { receiptProvenBy } from "../src/receipt.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// Invariant 8: "No clawback, no reversal, no privileged party who can move
// claims... this one forbids the path existing at all." Slices 2-6 forbade it in
// the ledger. It was still open in *served state*: an operator could commit a
// state in which it held everything, and nothing checked that the balances
// followed from the log or that the log followed from anybody's signature.
//
// Two attacks, both demonstrated before this slice:
//   - the sweep. Balances reassigned to the operator. Conservation passes,
//     because nothing was destroyed, and every holder is locked out.
//   - the fabricated append. Transfers nobody signed, appended to the log so
//     that the fold agrees with the swept balances. Earlier receipts still
//     prove, because their positions did not move.
//
// So a served state now has to survive three questions at once (invariants 8,
// 22, 23): is it what the operator committed to, do its balances follow from its
// own log, and was every operation in that log authorised by the party the law
// requires? The signature is served rather than committed — the entry's
// canonical message is already committed and only the true signer can sign it,
// which is invariant 23's own arrangement: the commitment "does not contain any
// of them, and anything checked against them has to be served".

function setup() {
  const venue = new Venue();
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], {
    noCommitmentDuration: 10n,
    challengeWindow: 5n,
  });
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const receipts = [];
  for (const [who, q] of [
    [KEYS.alice, 100n],
    [KEYS.bob, 60n],
  ] as const) {
    const op = { backing, recipient: who, quantity: q, nonce: sequencer.nextNonce(KEYS.backer, backing) };
    receipts.push(sequencer.submitIssue(op, ed25519.sign(encodeIssuance(op), SECRETS.backer)));
  }
  return { venue, sequencer, backing, receipts };
}

/** Publish `snapshots` as this operator's committed state, whatever they say. */
function publish(venue: Venue, snapshots: ReturnType<Sequencer["snapshot"]>) {
  const commitment = signCommitment(SECRETS.operator, venue.nextSequenceFor(KEYS.operator), stateRoot(snapshots));
  venue.publish(commitment);
  return { snapshots, commitment };
}

describe("invariant 8: a served state cannot move claims nobody signed away", () => {
  it("an honest served state is authentic", () => {
    const { venue, sequencer, backing } = setup();
    const served = publish(venue, sequencer.snapshot());
    expect(stateIsAuthentic(backing, served)).toBe(true);
    expect(provesHolding(venue, backing, served, KEYS.alice, 100n)).toBe(true);
  });

  it("refuses the sweep: balances reassigned to the operator", () => {
    const { venue, sequencer, backing, receipts } = setup();
    const swept = sequencer.snapshot().map((s) => ({ ...s, balances: [[KEYS.backer, 160n] as const] }));
    const served = publish(venue, swept);

    // It is the committed state, and it conserves — those were never the
    // properties that made it a lie.
    expect(stateProvesCommitment(swept, served.commitment)).toBe(true);
    // Its own log says otherwise, and the receipts still prove against it.
    expect(receiptProvenBy(receipts[0]!, swept[0]!)).toBe(true);
    expect(stateIsAuthentic(backing, served)).toBe(false);
    expect(provesHolding(venue, backing, served, KEYS.backer, 160n)).toBe(false);
  });

  it("refuses a fabricated append that makes the fold agree", () => {
    const { venue, sequencer, backing } = setup();
    const snapshot = sequencer.snapshot()[0]!;
    const forged = [
      {
        ...snapshot,
        balances: [[KEYS.backer, 160n] as const],
        opLog: [
          ...snapshot.opLog,
          {
            position: 2,
            kind: "transfer" as const,
            from: KEYS.alice,
            to: KEYS.backer,
            quantity: 100n,
            nonce: 0n,
            signature: new Uint8Array(64),
          },
          {
            position: 3,
            kind: "transfer" as const,
            from: KEYS.bob,
            to: KEYS.backer,
            quantity: 60n,
            nonce: 0n,
            signature: new Uint8Array(64),
          },
        ],
      },
    ];
    const served = publish(venue, forged);
    // The fold now agrees with the balances, so conservation and consistency
    // both pass. Only the missing signatures give it away.
    expect(foldBalances(backing, forged[0]!.opLog).get(Buffer.from(KEYS.backer).toString("hex"))).toBe(
      160n,
    );
    expect(stateProvesCommitment(forged, served.commitment)).toBe(true);
    expect(stateIsAuthentic(backing, served)).toBe(false);
    expect(provesHolding(venue, backing, served, KEYS.backer, 160n)).toBe(false);
  });

  it("refuses a signed operation logged more than once", () => {
    // A signature authorises ONE operation, and the nonce inside it is what
    // makes it single-use. Unchecked, the operator replays a transfer the holder
    // really did sign and takes a multiple of the units on one signature.
    const { venue, sequencer, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.carol, quantity: 30n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    const snapshot = sequencer.snapshot()[0]!;
    const replayed = snapshot.opLog[2]!;
    const log = [...snapshot.opLog, { ...replayed, position: 3 }, { ...replayed, position: 4 }];

    // Every entry still carries a signature the holder really made.
    const folded = foldBalances(backing, log);
    const forged = [
      { ...snapshot, opLog: log, balances: [...folded].map(([hex, units]) => [hexToBytes(hex), units] as const) },
    ];
    expect(folded.get(Buffer.from(KEYS.carol).toString("hex"))).toBe(90n);
    expect(stateIsAuthentic(backing, publish(venue, forged))).toBe(false);
  });

  it("refuses a log with a gap in a signer's nonce sequence", () => {
    // The same rule read the other way: dropping an operation from the middle
    // leaves the next one at a nonce nobody reached.
    const { venue, sequencer, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.carol, quantity: 30n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    const second = { backing, from: KEYS.alice, to: KEYS.carol, quantity: 10n, nonce: 1n };
    sequencer.submitTransfer(second, ed25519.sign(encodeTransfer(second), SECRETS.alice));
    const snapshot = sequencer.snapshot()[0]!;
    // Drop Alice's first transfer, renumbering so the positions stay dense.
    const log = snapshot.opLog
      .filter((_, i) => i !== 2)
      .map((entry, i) => ({ ...entry, position: i }));
    const folded = foldBalances(backing, log);
    const forged = [
      { ...snapshot, opLog: log, balances: [...folded].map(([hex, units]) => [hexToBytes(hex), units] as const) },
    ];
    expect(stateIsAuthentic(backing, publish(venue, forged))).toBe(false);
  });

  it("accepts a signer whose operations interleave with another's", () => {
    // The sequence is per signer, not per log: the obligor's issuances and
    // acceptances share one counter while a holder keeps their own.
    const f = setup();
    f.venue.advance(5n);
    const demand = {
      backing: f.backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
    };
    f.sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
    const answer = {
      backing: f.backing,
      demandHash: demandHash(demand),
      instant: 5n,
      deadline: 10n,
      nonce: f.sequencer.nextNonce(KEYS.backer, f.backing),
    };
    f.sequencer.submitAcceptance(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer));
    const settle = {
      backing: f.backing,
      demandHash: demandHash(demand),
      nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
    };
    f.sequencer.submitRelease(settle, ed25519.sign(encodeRelease(settle), SECRETS.alice));
    expect(stateIsAuthentic(f.backing, publish(f.venue, f.sequencer.snapshot()))).toBe(true);
  });

  it("refuses balances that do not follow from the log", () => {
    const { venue, sequencer, backing } = setup();
    const snapshot = sequencer.snapshot()[0]!;
    // Totals conserved, holders swapped, log untouched.
    const swapped = [{ ...snapshot, balances: [[KEYS.carol, 160n] as const] }];
    expect(stateIsAuthentic(backing, publish(venue, swapped))).toBe(false);
  });

  it("refuses a tampered signature on an otherwise honest state", () => {
    const { venue, sequencer, backing } = setup();
    const snapshot = sequencer.snapshot()[0]!;
    const tampered = [
      {
        ...snapshot,
        opLog: snapshot.opLog.map((entry, i) =>
          i === 0 ? { ...entry, signature: new Uint8Array(64) } : entry,
        ),
      },
    ];
    expect(stateIsAuthentic(backing, publish(venue, tampered))).toBe(false);
  });

  it("refuses an issuance signed by anyone but the obligor", () => {
    // The signer for an issuance comes from the backing's terms, never from the
    // served state — nothing an operator writes can nominate its own authority.
    const { venue, sequencer, backing } = setup();
    const snapshot = sequencer.snapshot()[0]!;
    const entry = snapshot.opLog[0]!;
    if (entry.kind !== "issue") throw new Error("fixture: expected an issuance first");
    const forgedIssue = {
      backing,
      recipient: entry.recipient,
      quantity: entry.quantity,
      nonce: entry.nonce,
    };
    const impostor = [
      {
        ...snapshot,
        opLog: snapshot.opLog.map((e, i) =>
          i === 0
            ? { ...e, signature: ed25519.sign(encodeIssuance(forgedIssue), SECRETS.mallory) }
            : e,
        ),
      },
    ];
    expect(stateIsAuthentic(backing, publish(venue, impostor))).toBe(false);
  });
});

describe("the signer of a presentation entry comes from the log, not the operator", () => {
  function withDemand() {
    const f = setup();
    f.venue.advance(5n);
    const demand = {
      backing: f.backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
    };
    f.sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
    const hash = demandHash(demand);
    const answer = {
      backing: f.backing,
      demandHash: hash,
      instant: 5n,
      deadline: 10n,
      nonce: f.sequencer.nextNonce(KEYS.backer, f.backing),
    };
    f.sequencer.submitAcceptance(answer, ed25519.sign(encodeAcceptance(answer), SECRETS.backer));
    return { ...f, hash };
  }

  it("a demand's hash is exactly its operation hash, so the log resolves its holder", () => {
    const f = withDemand();
    const settle = {
      backing: f.backing,
      demandHash: f.hash,
      nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
    };
    f.sequencer.submitRelease(settle, ed25519.sign(encodeRelease(settle), SECRETS.alice));
    const served = publish(f.venue, f.sequencer.snapshot());
    expect(stateIsAuthentic(f.backing, served)).toBe(true);
    // Settlement moved the units to the obligor, and the fold knows that from
    // the terms rather than from anything the operator wrote in the entry.
    expect(provesHolding(f.venue, f.backing, served, KEYS.backer, 40n)).toBe(true);
    expect(provesHolding(f.venue, f.backing, served, KEYS.alice, 60n)).toBe(true);
  });

  it("a withdrawal is authentic against the demand it names", () => {
    const f = setup();
    f.venue.advance(5n);
    const demand = {
      backing: f.backing,
      holder: KEYS.alice,
      quantity: 40n,
      instant: 5n,
      deadline: 10n,
      nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
    };
    f.sequencer.submitDemand(demand, ed25519.sign(encodeDemand(demand), SECRETS.alice));
    f.venue.advance(6n);
    const walk = {
      backing: f.backing,
      demandHash: demandHash(demand),
      nonce: f.sequencer.nextNonce(KEYS.alice, f.backing),
    };
    f.sequencer.submitWithdrawal(walk, ed25519.sign(encodeWithdrawal(walk), SECRETS.alice));
    expect(stateIsAuthentic(f.backing, publish(f.venue, f.sequencer.snapshot()))).toBe(true);
  });

  it("refuses a release naming a demand the log does not contain", () => {
    // Otherwise an operator invents a settlement of a demand nobody ever filed,
    // and there is no holder against whom to check the release signature.
    const f = withDemand();
    const snapshot = f.sequencer.snapshot()[0]!;
    const orphaned = [
      {
        ...snapshot,
        opLog: snapshot.opLog.map((e) =>
          e.kind === "acceptance" ? { ...e, demandHash: new Uint8Array(32).fill(0xaa) } : e,
        ),
      },
    ];
    expect(stateIsAuthentic(f.backing, publish(f.venue, orphaned))).toBe(false);
  });
});

describe("authenticity verifiers return false on hostile input, never throw", () => {
  it("survives malformed entries and a junk commitment", () => {
    const { backing } = setup();
    const junk = [
      { position: 0, kind: "burn" as const, holder: new Uint8Array(3), quantity: 1n, nonce: 0n, signature: new Uint8Array(0) },
      { position: 1, kind: "release" as const, demandHash: new Uint8Array(1), nonce: -1n, signature: new Uint8Array(64) },
    ];
    expect(entriesAreAuthentic(backing, junk)).toBe(false);
    expect(() => foldBalances(backing, junk)).not.toThrow();
    expect(
      stateIsAuthentic(backing, {
        snapshots: [
          { name: new Uint8Array(31), issued: -1n, burned: 0n, balances: [], opLog: junk, demands: [] },
        ],
        commitment: {
          sequence: -1n,
          root: new Uint8Array(2),
          operator: new Uint8Array(5),
          signature: new Uint8Array(1),
        },
      }),
    ).toBe(false);
  });

  it("refuses a state carrying no snapshot for this backing", () => {
    const { venue, backing } = setup();
    expect(stateIsAuthentic(backing, publish(venue, []))).toBe(false);
  });
});

describe("a transfer still needs the holder's own signature in served state", () => {
  it("an honest transfer is authentic and folds", () => {
    const { venue, sequencer, backing } = setup();
    const move = { backing, from: KEYS.alice, to: KEYS.carol, quantity: 30n, nonce: 0n };
    sequencer.submitTransfer(move, ed25519.sign(encodeTransfer(move), SECRETS.alice));
    const served = publish(venue, sequencer.snapshot());
    expect(stateIsAuthentic(backing, served)).toBe(true);
    expect(provesHolding(venue, backing, served, KEYS.carol, 30n)).toBe(true);
    expect(provesHolding(venue, backing, served, KEYS.alice, 71n)).toBe(false);
    expect(provesHolding(venue, backing, served, KEYS.alice, 70n)).toBe(true);
  });
});
