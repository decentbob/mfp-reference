import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { signBacking } from "../src/backing.js";
import {
  isEquivocation,
  signCommitment,
  stateRoot,
  verifyCommitment,
} from "../src/commitment.js";
import { encodeIssuance } from "../src/messages.js";
import { Sequencer } from "../src/sequencer.js";
import { EncodingError } from "../src/bytes.js";
import { stateProvesCommitment } from "../src/commitment.js";
import { receiptProvenBy, verifyReceipt } from "../src/receipt.js";
import { Venue, VenueError } from "../src/venue.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// Invariant 22: every state a sequencer asserts must prove against its latest
// published commitment, so divergent histories are not assertable — two
// commitments at the same index over different roots, both signed by the
// operator, are provable equivocation.

function setup() {
  const venue = new Venue();
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuance(issue), SECRETS.backer));
  return { sequencer, backing, venue };
}

describe("invariant 22: state proves against the latest commitment", () => {
  it("the published commitment verifies under the operator key", () => {
    const { sequencer, venue } = setup();
    const commitment = sequencer.commit();
    expect(verifyCommitment(commitment)).toBe(true);
    expect(venue.latestFor(sequencer.operator)).toEqual(commitment);
  });

  it("a commitment with a mutated root or index does not verify", () => {
    const { sequencer } = setup();
    const commitment = sequencer.commit();
    const mutatedRoot = commitment.root.slice();
    mutatedRoot[0] = (mutatedRoot[0] as number) ^ 0xff;
    expect(verifyCommitment({ ...commitment, root: mutatedRoot })).toBe(false);
    expect(verifyCommitment({ ...commitment, index: commitment.index + 1n })).toBe(false);
  });

  it("the venue rejects an unsigned commitment and a non-extending index", () => {
    const { sequencer, venue } = setup();
    const first = sequencer.commit();
    const forged = { ...first, signature: new Uint8Array(64) };
    expect(() => venue.publish(forged)).toThrow(VenueError);
    // Re-publishing the same index does not extend the operator's history.
    expect(() => venue.publish(first)).toThrow(VenueError);
  });

  it("the served state recomputes to the committed root", () => {
    const { sequencer } = setup();
    const commitment = sequencer.commit();
    expect(stateRoot(sequencer.snapshot())).toEqual(commitment.root);
  });

  it("a tampered state does not match the commitment", () => {
    const { sequencer } = setup();
    const commitment = sequencer.commit();
    const snapshot = sequencer.snapshot();
    // Inflate a balance in the asserted state.
    const tampered = snapshot.map((s) => ({
      ...s,
      balances: s.balances.map(([k, v]) => [k, v + 1n] as const),
    }));
    expect(stateRoot(tampered)).not.toEqual(commitment.root);
  });

  it("two different roots at the same index by one operator are equivocation", () => {
    const { sequencer } = setup();
    const honest = sequencer.commit();
    // A second, conflicting commitment at the same index.
    const forgedRoot = new Uint8Array(32).fill(0xab);
    const conflicting = signCommitment(SECRETS.operator, honest.index, forgedRoot);
    expect(isEquivocation(honest, conflicting)).toBe(true);
  });

  it("distinct roots at distinct indices are not equivocation", () => {
    const { sequencer } = setup();
    const first = sequencer.commit();
    const second = sequencer.commit();
    expect(second.index).toBe(first.index + 1n);
    expect(isEquivocation(first, second)).toBe(false);
  });

  it("a commitment signed by a different key is not the operator's equivocation", () => {
    const { sequencer } = setup();
    const honest = sequencer.commit();
    const impostor = signCommitment(SECRETS.mallory, honest.index, new Uint8Array(32).fill(0xcd));
    expect(isEquivocation(honest, impostor)).toBe(false);
  });
});

// The root must be INJECTIVE or invariant 22 is worthless: two served states
// sharing a root let an operator equivocate with one signature and no provable
// fault. Injectivity comes from the framing rule — every key and name is
// fixed-width and asserted, so no two field values share an encoding.

describe("invariant 22: the state root is injective", () => {
  const name = new Uint8Array(32).fill(0x01);

  it("rejects adjacent keys that would concatenate ambiguously", () => {
    // 31+33 bytes concatenate exactly like 32+32, so an unframed encoder gives
    // two different transfers one root.
    const bytes = new Uint8Array(64);
    for (let i = 0; i < 64; i++) bytes[i] = i + 1;
    const state = (from: Uint8Array, to: Uint8Array) => [
      {
        name,
        issued: 7n,
        burned: 0n,
        balances: [],
        opLog: [{ position: 0, kind: "transfer" as const, from, to, quantity: 7n, nonce: 0n }],
        demands: [],
      },
    ];
    expect(() => stateRoot(state(bytes.slice(0, 32), bytes.slice(32)))).not.toThrow();
    expect(() => stateRoot(state(bytes.slice(0, 31), bytes.slice(31)))).toThrow(EncodingError);
  });

  it("rejects an over-long balance key that would swallow later fields", () => {
    const long = new Uint8Array(87).fill(0xbb);
    expect(() =>
      stateRoot([{ name, issued: 5n, burned: 0n, balances: [[long, 0n]], opLog: [], demands: [] }]),
    ).toThrow(EncodingError);
  });

  it("rejects two snapshots for one backing", () => {
    const one = { name, issued: 0n, burned: 0n, balances: [], opLog: [], demands: [] };
    expect(() => stateRoot([one, one])).toThrow(EncodingError);
  });
});

describe("verifiers return false on hostile input, never throw", () => {
  const name = new Uint8Array(32).fill(0x01);
  const shortKey = new Uint8Array(31);
  const sig = new Uint8Array(64);

  it("a malformed operator key fails verification instead of crashing", () => {
    expect(verifyCommitment({ index: 0n, root: name, operator: shortKey, signature: sig })).toBe(false);
    expect(
      verifyReceipt({ backingName: name, opHash: name, position: 0n, operator: shortKey, signature: sig }),
    ).toBe(false);
  });

  it("a non-integer served position fails the proof instead of crashing", () => {
    const hostile = {
      name,
      issued: 0n,
      burned: 0n,
      balances: [],
      opLog: [{ position: 1.5, kind: "burn" as const, holder: name, quantity: 1n, nonce: 0n }],
      demands: [],
    };
    const receipt = { backingName: name, opHash: name, position: 0n, operator: name, signature: sig };
    expect(receiptProvenBy(receipt, hostile)).toBe(false);
  });

  it("a negative served amount fails the commitment check instead of crashing", () => {
    const bad = [{ name, issued: -1n, burned: 0n, balances: [], opLog: [], demands: [] }];
    expect(stateProvesCommitment(bad, { index: 0n, root: name, operator: name, signature: sig })).toBe(false);
  });
});

// A root can be injective and still let an operator assert state with more
// than one meaning, or state that hides an accepted operation. Canonical form
// closes both.

describe("invariant 22: committed state has exactly one meaning", () => {
  const name = new Uint8Array(32).fill(0x01);
  const holder = new Uint8Array(32).fill(0x02);

  it("rejects one holder appearing twice in balances", () => {
    // Sum, first-wins and last-wins readers would disagree under one valid
    // signature, and no second root exists to prove a fault.
    expect(() =>
      stateRoot([
        { name, issued: 100n, burned: 0n, balances: [[holder, 100n], [holder, 0n]], opLog: [], demands: [] },
      ]),
    ).toThrow(EncodingError);
  });

  it("rejects an op-log position that does not match its index", () => {
    // A gap lets an operator commit to state in which a holder's valid,
    // operator-signed receipt for the missing position proves against nothing.
    const entry = (position: number) => ({
      position,
      kind: "burn" as const,
      holder,
      quantity: 1n,
      nonce: 0n,
    });
    expect(() =>
      stateRoot([{ name, issued: 2n, burned: 2n, balances: [], opLog: [entry(0), entry(5)] , demands: [] }]),
    ).toThrow(EncodingError);
  });

  it("rejects an accepted deadline the law could not have produced", () => {
    // `accept` enforces acceptedDeadline <= the demand's own deadline. A record
    // outside that range is state the ledger cannot reach, and isDishonoured
    // reads the committed record — so an operator (frequently the backer) could
    // otherwise serve a demand as answered forever with no acceptance signature
    // anywhere. The encoder defines canonical committed state independently of
    // who produced it, exactly as it does for op-log positions.
    const state = (acceptedDeadline: bigint | undefined) => [
      {
        name,
        issued: 1n,
        burned: 0n,
        balances: [],
        opLog: [],
        demands: [
          { hash: name, holder, quantity: 1n, instant: 0n, deadline: 10n, nonce: 0n, acceptedDeadline },
        ],
      },
    ];
    expect(() => stateRoot(state(10n))).not.toThrow();
    expect(() => stateRoot(state(11n))).toThrow(EncodingError);
    expect(
      stateProvesCommitment(state(1_000_000n), {
        index: 0n,
        root: name,
        operator: name,
        signature: new Uint8Array(64),
      }),
    ).toBe(false);
  });

  it("rejects an oversized amount instead of grinding on it", () => {
    // Unbounded, an attacker-sized integer turns "a malformed state fails the
    // proof" into a hang.
    const started = Date.now();
    expect(
      stateProvesCommitment([{ name, issued: 1n << 200000n, burned: 0n, balances: [], opLog: [], demands: [] }], {
        index: 0n,
        root: name,
        operator: name,
        signature: new Uint8Array(64),
      }),
    ).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe("a hostile standing demand record fails the proof, never throws", () => {
  const name = new Uint8Array(32).fill(0x01);
  const base = { name, issued: 0n, burned: 0n, balances: [], opLog: [] };
  const commitment = {
    index: 0n,
    root: name,
    operator: name,
    signature: new Uint8Array(64),
  };
  const demand = (over: Record<string, unknown>) => [
    {
      ...base,
      demands: [
        {
          hash: name,
          holder: name,
          quantity: 1n,
          instant: 0n,
          deadline: 0n,
          nonce: 0n,
          acceptedDeadline: undefined,
          ...over,
        },
      ],
    },
  ];

  it("rejects malformed demand fields at the encoder", () => {
    expect(() => stateRoot(demand({ holder: new Uint8Array(31) }))).toThrow(EncodingError);
    expect(() => stateRoot(demand({ quantity: -5n }))).toThrow(EncodingError);
    expect(() => stateRoot(demand({ deadline: -1n }))).toThrow(EncodingError);
    expect(() => stateRoot(demand({ nonce: -1n }))).toThrow(EncodingError);
  });

  it("does not commit the self-declared hash, so it cannot be lied about", () => {
    // The hash is derived from the committed fields. Committing it instead
    // would let an operator publish a genuine hash beside a false quantity.
    const a = demand({ hash: new Uint8Array(32).fill(0xaa) });
    const b = demand({ hash: new Uint8Array(32).fill(0xbb) });
    expect(bytesToHex(stateRoot(a))).toBe(bytesToHex(stateRoot(b)));
    // The fields themselves still move it.
    expect(bytesToHex(stateRoot(demand({ quantity: 2n })))).not.toBe(bytesToHex(stateRoot(a)));
  });

  it("rejects one demand appearing twice", () => {
    expect(() =>
      stateRoot([
        {
          ...base,
          demands: [
            { hash: name, holder: name, quantity: 1n, instant: 0n, deadline: 0n, nonce: 0n, acceptedDeadline: undefined },
            { hash: name, holder: name, quantity: 2n, instant: 0n, deadline: 0n, nonce: 0n, acceptedDeadline: undefined },
          ],
        },
      ]),
    ).toThrow(EncodingError);
  });

  it("the verifier returns false rather than propagating the throw", () => {
    expect(stateProvesCommitment(demand({ quantity: -5n }), commitment)).toBe(false);
    expect(stateProvesCommitment(demand({ nonce: -1n }), commitment)).toBe(false);
  });

  it("an unanswered demand does not encode like one accepted at index 0", () => {
    // The presence byte must actually separate the two, or a backer could be
    // shown as having answered when it has not.
    expect(bytesToHex(stateRoot(demand({ acceptedDeadline: undefined })))).not.toBe(
      bytesToHex(stateRoot(demand({ acceptedDeadline: 0n }))),
    );
  });
});

// The operation log now carries presentation entries too, and their committed
// bytes are the bytes the party signed. A hostile operator must not be able to
// serve a malformed one and turn a failed proof into a crash.

describe("invariant 22: hostile presentation entries fail the proof, never throw", () => {
  const name = new Uint8Array(32).fill(0x01);
  const holder = new Uint8Array(32).fill(0x02);
  const sig = new Uint8Array(64);
  const commitment = { index: 0n, root: name, operator: name, signature: sig };
  const withLog = (entry: unknown) => [
    { name, issued: 1n, burned: 0n, balances: [], opLog: [entry], demands: [] },
  ] as Parameters<typeof stateRoot>[0];

  it("rejects a short demand hash on an acceptance, release or withdrawal", () => {
    const short = new Uint8Array(31);
    for (const kind of ["release", "withdrawal"] as const) {
      expect(() => stateRoot(withLog({ position: 0, kind, demandHash: short, nonce: 0n }))).toThrow(
        EncodingError,
      );
    }
    expect(() =>
      stateRoot(
        withLog({
          position: 0,
          kind: "acceptance",
          demandHash: short,
          instant: 0n,
          deadline: 0n,
          nonce: 0n,
        }),
      ),
    ).toThrow(EncodingError);
  });

  it("rejects a logged demand with a zero or negative quantity", () => {
    const entry = (quantity: bigint) => ({
      position: 0,
      kind: "demand" as const,
      holder,
      quantity,
      instant: 0n,
      deadline: 0n,
      nonce: 0n,
    });
    expect(() => stateRoot(withLog(entry(0n)))).toThrow(EncodingError);
    expect(() => stateRoot(withLog(entry(-1n)))).toThrow(EncodingError);
  });

  it("rejects a logged presentation entry with a negative nonce or instant", () => {
    expect(() =>
      stateRoot(withLog({ position: 0, kind: "withdrawal", demandHash: name, nonce: -1n })),
    ).toThrow(EncodingError);
    expect(() =>
      stateRoot(
        withLog({
          position: 0,
          kind: "acceptance",
          demandHash: name,
          instant: -1n,
          deadline: 0n,
          nonce: 0n,
        }),
      ),
    ).toThrow(EncodingError);
  });

  it("the verifier returns false rather than propagating the throw", () => {
    expect(
      stateProvesCommitment(
        withLog({ position: 0, kind: "release", demandHash: new Uint8Array(31), nonce: 0n }),
        commitment,
      ),
    ).toBe(false);
  });

  it("a logged demand and a logged withdrawal for it do not share an encoding", () => {
    // Two different presentation kinds must never produce one committed entry;
    // the domain tag inside each signed message is what separates them.
    const demandEntry = {
      position: 0,
      kind: "demand" as const,
      holder,
      quantity: 1n,
      instant: 0n,
      deadline: 0n,
      nonce: 0n,
    };
    const withdrawalEntry = { position: 0, kind: "withdrawal" as const, demandHash: holder, nonce: 0n };
    expect(bytesToHex(stateRoot(withLog(demandEntry)))).not.toBe(
      bytesToHex(stateRoot(withLog(withdrawalEntry))),
    );
  });
});
