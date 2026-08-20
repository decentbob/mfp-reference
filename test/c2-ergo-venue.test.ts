import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking } from "../src/backing.js";
import { signCommitment, stateRoot, type Commitment } from "../src/commitment.js";
import {
  commitmentRegisters,
  ErgoVenue,
  ergoVenueId,
  type ErgoAddressing,
  type ErgoBoxView,
  type ErgoNode,
} from "../src/ergo.js";
import { encodePublishedOp } from "../src/oplog.js";
import { encodeTransferMessage } from "../src/messages.js";
import { isSilent, provesHolding, quietFor } from "../src/recovery.js";
import { VenueError } from "../src/venue.js";
import { operatorAt } from "../src/replacement.js";
import { KEYS, SECRETS } from "./support.js";

// Ergo read as a witness venue. The chain witnesses and adjudicates nothing, so
// there is no contract here and nothing verifies a signature on-chain — a
// commitment is a record in box registers and every judgement is the reader's.
//
// Two properties carry the security of it, and both are tested below:
//
//   - **the witnessed index is the box's inclusionHeight**, which is the block
//     that included the creating transaction. A box's own creationHeight is
//     written by whoever built the transaction and may be set lower, so using it
//     would let an operator backdate a commitment to before a redemption leg it
//     actually followed — the veto slice 8 closed. It is not even modelled here.
//   - **nothing inside the finality depth is read at all**, because
//     inclusionHeight is reorg-sensitive and a venue answering from the tip would
//     change its mind about the past.
//
// And the seam is only real if the existing predicates accept it, so the last
// group runs them against this venue rather than the local one.

const DEPTH = 3n;
const SCRIPT = "publication-script-v1";
const VENUE_ID = ergoVenueId("ergo-testnet", DEPTH, SCRIPT);

const ADDRESSING: ErgoAddressing = {
  commitments: (operator) => `commit:${Buffer.from(operator).toString("hex")}`,
  publications: (backingName) => `publish:${Buffer.from(backingName).toString("hex")}`,
  revocations: (obligor) => `revoke:${Buffer.from(obligor).toString("hex")}`,
};

/** The node, as far as a venue can see it: boxes by address, and a height. */
class FakeNode implements ErgoNode {
  private height = 0n;
  private readonly boxes = new Map<string, ErgoBoxView[]>();

  at(height: bigint): this {
    this.height = height;
    return this;
  }

  put(address: string, box: ErgoBoxView): this {
    const at = this.boxes.get(address) ?? [];
    at.push(box);
    this.boxes.set(address, at);
    return this;
  }

  putCommitment(commitment: Commitment, inclusionHeight: bigint): this {
    return this.put(ADDRESSING.commitments(commitment.operator), {
      inclusionHeight,
      registers: commitmentRegisters(commitment),
    });
  }

  async indexedHeight(): Promise<bigint> {
    return this.height;
  }

  async boxesByAddress(address: string): Promise<ErgoBoxView[]> {
    return this.boxes.get(address) ?? [];
  }
}

const backing = makeBacking({
  obligor: KEYS.backer,
  payout: { thing: "EUR", quantumExponent: -2, perUnit: 100n },
  reliance: [],
  evidence: {
    setting: "transparent",
    operator: KEYS.operator,
    silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
    witnessing: { venue: VENUE_ID, interval: 5n },
  },
});

function commitment(sequence: bigint, fill: number): Commitment {
  return signCommitment(SECRETS.operator, sequence, new Uint8Array(32).fill(fill));
}

function venue(): ErgoVenue {
  return new ErgoVenue(VENUE_ID, DEPTH, ADDRESSING);
}

describe("a venue's identity commits to its finality rule", () => {
  it("changes with the depth, so naming the venue agrees the depth", () => {
    // §C2 names a venue together with the depth under which an index counts as
    // witnessed there — "a floor under the interval, or two sequencers answer
    // §C3's release predicate differently". Two backings naming one id cannot
    // disagree about the depth if the id is derived from it.
    const base = ergoVenueId("ergo-testnet", 3n, SCRIPT);
    expect(ergoVenueId("ergo-testnet", 3n, SCRIPT)).toEqual(base);
    expect(ergoVenueId("ergo-testnet", 4n, SCRIPT)).not.toEqual(base);
    expect(ergoVenueId("ergo-mainnet", 3n, SCRIPT)).not.toEqual(base);
    expect(ergoVenueId("ergo-testnet", 3n, "other-script")).not.toEqual(base);
    expect(base).toHaveLength(32);
  });
});

describe("the witnessed index is the block that included the box", () => {
  it("reads a commitment at its inclusion height", async () => {
    const v = venue();
    await v.sync(new FakeNode().at(100n).putCommitment(commitment(0n, 0xaa), 40n), [backing]);
    expect(v.witnessedAtFor(KEYS.operator)).toBe(40n);
    expect(v.latestFor(KEYS.operator)?.sequence).toBe(0n);
  });

  it("reads nothing inside the finality depth", async () => {
    // A box at the tip is not witnessed yet: a reorg would move it, and a venue
    // that changed its mind about the past would unmake settled answers.
    const node = new FakeNode().at(100n).putCommitment(commitment(0n, 0xaa), 98n);
    const v = venue();
    await v.sync(node, [backing]);
    expect(v.witnessedIndex()).toBe(97n);
    expect(v.latestFor(KEYS.operator)).toBeUndefined();

    await v.sync(node.at(101n), [backing]);
    expect(v.witnessedIndex()).toBe(98n);
    expect(v.latestFor(KEYS.operator)?.sequence).toBe(0n);
  });

  it("answers about the past, which is what four of the nine reads need", async () => {
    const v = venue();
    const node = new FakeNode()
      .at(100n)
      .putCommitment(commitment(0n, 0xaa), 10n)
      .putCommitment(commitment(1n, 0xbb), 50n);
    await v.sync(node, [backing]);

    expect(v.latestFor(KEYS.operator)?.sequence).toBe(1n);
    expect(v.latestFor(KEYS.operator, 49n)?.sequence).toBe(0n);
    expect(v.witnessedAtFor(KEYS.operator, 49n)).toBe(10n);
    expect(v.latestFor(KEYS.operator, 9n)).toBeUndefined();
    expect(v.firstCommitmentFor(KEYS.operator)).toBe(10n);
    expect(v.firstCommitmentFor(KEYS.operator, 11n)).toBe(50n);
    expect(v.nextSequenceFor(KEYS.operator)).toBe(2n);
  });

  it("orders by the chain's word, not by the order boxes came back", async () => {
    const v = venue();
    await v.sync(
      new FakeNode()
        .at(100n)
        .putCommitment(commitment(1n, 0xbb), 50n)
        .putCommitment(commitment(0n, 0xaa), 10n),
      [backing],
    );
    expect(v.firstCommitmentFor(KEYS.operator)).toBe(10n);
    expect(v.latestFor(KEYS.operator)?.sequence).toBe(1n);
  });
});

describe("nothing rests on the address alone", () => {
  it("skips a box whose commitment is not this operator's", async () => {
    // Anyone may create a box at an address, so the signature does the deciding.
    const v = venue();
    const stranger = signCommitment(SECRETS.mallory, 0n, new Uint8Array(32).fill(0xcc));
    await v.sync(
      new FakeNode().at(100n).put(ADDRESSING.commitments(KEYS.operator), {
        inclusionHeight: 10n,
        registers: commitmentRegisters(stranger),
      }),
      [backing],
    );
    expect(v.latestFor(KEYS.operator)).toBeUndefined();
  });

  it("skips a box whose signature does not verify", async () => {
    const v = venue();
    const torn = { ...commitment(0n, 0xaa), signature: new Uint8Array(64) };
    await v.sync(
      new FakeNode().at(100n).put(ADDRESSING.commitments(KEYS.operator), {
        inclusionHeight: 10n,
        registers: commitmentRegisters(torn),
      }),
      [backing],
    );
    expect(v.latestFor(KEYS.operator)).toBeUndefined();
  });

  it("skips noise rather than failing on it", async () => {
    const v = venue();
    await v.sync(
      new FakeNode()
        .at(100n)
        .put(ADDRESSING.commitments(KEYS.operator), { inclusionHeight: 5n, registers: {} })
        .put(ADDRESSING.commitments(KEYS.operator), {
          inclusionHeight: 6n,
          registers: { R4: new Uint8Array(3), R5: new Uint8Array(1), R6: new Uint8Array(0), R7: new Uint8Array(2) },
        })
        .putCommitment(commitment(0n, 0xaa), 10n),
      [backing],
    );
    expect(v.latestFor(KEYS.operator)?.sequence).toBe(0n);
  });

  it("reads published operations, and only this backing's", async () => {
    const v = venue();
    const op = {
      kind: "transfer" as const,
      from: KEYS.alice,
      to: KEYS.bob,
      quantity: 40n,
      nonce: 0n,
      signature: ed25519.sign(
        encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 40n, 0n),
        SECRETS.alice,
      ),
    };
    await v.sync(
      new FakeNode().at(100n).put(ADDRESSING.publications(backing.name), {
        inclusionHeight: 20n,
        registers: { R4: backing.name, R5: encodePublishedOp(backing.name, op) },
      }),
      [backing],
    );
    const published = v.publishedOpsFor(backing.name);
    expect(published).toHaveLength(1);
    expect(published[0]!.at).toBe(20n);
    expect(published[0]!.op).toEqual(op);
  });
});

describe("this venue reads; publishing is somebody else's wallet", () => {
  it("refuses to publish, and says which boundary refused", async () => {
    const v = venue();
    expect(() => v.publish()).toThrow(VenueError);
    expect(() => v.publishOp()).toThrow(VenueError);
    expect(() => v.publishReplacement()).toThrow(VenueError);
  });
});

describe("the seam is real: the existing predicates take this venue", () => {
  it("grades silence off the chain's own heights", async () => {
    // The point of the whole slice. isSilent, quietFor and provesHolding were
    // written against an in-memory stand-in and are handed an Ergo venue here
    // with nothing changed in them.
    const v = venue();
    const node = new FakeNode().at(100n).putCommitment(commitment(0n, 0xaa), 40n);
    await v.sync(node, [backing]);

    expect(quietFor(v, KEYS.operator)).toBe(57n);
    expect(isSilent(v, backing)).toBe(true);

    // And it stops being silent the moment a later commitment is witnessed.
    await v.sync(node.at(101n).putCommitment(commitment(1n, 0xbb), 95n), [backing]);
    expect(isSilent(v, backing)).toBe(false);
  });

  it("refuses to grade a backing that declares another venue", async () => {
    const elsewhere = makeBacking({
      ...backing,
      evidence: {
        ...backing.evidence,
        witnessing: { venue: ergoVenueId("ergo-mainnet", DEPTH, SCRIPT), interval: 5n },
      },
    });
    const v = venue();
    await v.sync(new FakeNode().at(1000n), [elsewhere]);
    expect(isSilent(v, elsewhere)).toBe(false);
  });

  it("proves a holding against a state the chain witnessed", async () => {
    // The full path: the operator's committed state, anchored by a commitment
    // this venue read out of box registers.
    const snapshots = [{ name: backing.name, opLog: [] }];
    const anchored = signCommitment(SECRETS.operator, 0n, stateRoot(snapshots));
    const v = venue();
    await v.sync(new FakeNode().at(100n).putCommitment(anchored, 40n), [backing]);
    // No issuance in this log, so nobody holds anything — what is being checked
    // is that the served state resolves against a chain-read commitment at all.
    expect(provesHolding(v, backing, { snapshots, commitment: anchored }, KEYS.alice, 1n)).toBe(false);
    expect(v.latestFor(KEYS.operator)?.root).toEqual(anchored.root);
  });
});

describe("a view answers only for what it was synced for", () => {
  it("refuses an operator it never fetched, rather than grading it silent", async () => {
    // The finding this group exists for. A venue has one height, because
    // witnessedIndex answers without being asked about a backing — so it must
    // have one coherent set of records to go with it. Refreshing part of the
    // view while the clock moved for all of it graded a punctual operator
    // silent: its records stopped where the last partial sync left them, which
    // opens snapshot redemption against somebody who committed moments ago.
    //
    // Absence of data must not read as an accusation, so the venue refuses
    // instead of answering. VenueError names the boundary: this is a caller
    // asking the wrong object, not adversary input.
    const other = makeBacking({
      obligor: KEYS.backer2,
      payout: { thing: "USD", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.mallory,
        silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
        witnessing: { venue: VENUE_ID, interval: 5n },
      },
    });
    const v = venue();
    // Committed two blocks inside the view, so a correct reading is "not silent".
    const node = new FakeNode().at(200n).putCommitment(commitment(0n, 0xaa), 195n);
    await v.sync(node, [other]);

    expect(() => isSilent(v, backing)).toThrow(VenueError);
    expect(() => v.publishedOpsFor(backing.name)).toThrow(VenueError);

    // Synced for it, and the punctual operator reads as punctual.
    await v.sync(node, [other, backing]);
    expect(isSilent(v, backing)).toBe(false);
  });

  it("refuses an unsynced backing whose operator IS fetched, which is the common case", async () => {
    // Found regression-reviewing slice 19, and the guard above passes for a
    // coincidental reason: its unsynced backing has an operator nobody fetched,
    // so the operator-keyed guard fires. §C5 recommends one operator serving
    // many backings, and then syncing backing A fetches that operator — so
    // asking about unsynced backing B sails past both guards.
    //
    // It takes a backing that DECLARES a replacement rule, because that is when
    // the chain is read at all: without one successionOf never reaches the venue,
    // and the answer it gives is right, since an operator's commitments are the
    // operator's and were fetched.
    //
    // What answered instead was successionOf's catch, which turned the venue's
    // refusal into the GENESIS chain: the pre-succession answer slice 14 warned
    // a caller must never get silently. On a backing whose operator had been
    // replaced that reads the RETIRED key as the one in force, so a successor
    // committing on schedule grades as silent and snapshot redemption opens
    // against an honest operator — out of not having looked.
    const sameOperator = makeBacking({
      obligor: KEYS.backer2,
      payout: { thing: "USD", quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: {
        setting: "transparent",
        operator: KEYS.operator,
        silence: { noCommitmentDuration: 10n, challengeWindow: 5n },
        replacementRule: KEYS.backer2,
        witnessing: { venue: VENUE_ID, interval: 5n },
      },
    });
    const v = venue();
    const node = new FakeNode().at(200n).putCommitment(commitment(0n, 0xaa), 195n);
    await v.sync(node, [backing]);

    // The operator is fetched, so the operator-keyed guard cannot fire.
    expect(() => v.latestFor(KEYS.operator)).not.toThrow();
    expect(() => isSilent(v, sameOperator)).toThrow(VenueError);
    expect(() => operatorAt(sameOperator, v, v.witnessedIndex())).toThrow(VenueError);

    await v.sync(node, [backing, sameOperator]);
    expect(isSilent(v, sameOperator)).toBe(false);
  });

  it("fetches every operator in a covered backing's chain, so succession still reads", async () => {
    // The guard must not break succession: sync widens until the chain stops
    // revealing operators, so operatorAt can never reach one that was not
    // fetched.
    const v = venue();
    await v.sync(new FakeNode().at(100n).putCommitment(commitment(0n, 0xaa), 40n), [backing]);
    expect(() => v.latestFor(KEYS.operator)).not.toThrow();
    expect(v.latestFor(KEYS.operator)?.sequence).toBe(0n);
  });
});
