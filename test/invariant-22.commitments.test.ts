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

  it("a commitment with a mutated root or sequence does not verify", () => {
    const { sequencer } = setup();
    const commitment = sequencer.commit();
    const mutatedRoot = commitment.root.slice();
    mutatedRoot[0] = (mutatedRoot[0] as number) ^ 0xff;
    expect(verifyCommitment({ ...commitment, root: mutatedRoot })).toBe(false);
    expect(verifyCommitment({ ...commitment, sequence: commitment.sequence + 1n })).toBe(false);
  });

  it("the venue rejects an unsigned commitment and a non-extending sequence", () => {
    const { sequencer, venue } = setup();
    const first = sequencer.commit();
    const forged = { ...first, signature: new Uint8Array(64) };
    expect(() => venue.publish(forged)).toThrow(VenueError);
    // Re-publishing the same sequence does not extend the operator's history.
    expect(() => venue.publish(first)).toThrow(VenueError);
  });

  it("a published commitment cannot be rewritten in place", () => {
    // The venue is a shared public record read by strangers, and the party with
    // the motive to mutate it is the operator, which still holds the object it
    // published. Copy in, copy out — otherwise an operator can retroactively
    // deny its own commitment, which is exactly what the venue exists to stop.
    const { sequencer, venue } = setup();
    const mine = sequencer.commit();
    mine.root.fill(0xff);
    mine.signature.fill(0xff);
    mine.operator.fill(0xff);
    expect(verifyCommitment(venue.latestFor(sequencer.operator)!)).toBe(true);
  });

  it("nor by a reader poisoning the record for the next reader", () => {
    const { sequencer, venue } = setup();
    sequencer.commit();
    const handedOut = venue.latestFor(sequencer.operator)!;
    handedOut.root.fill(0xee);
    handedOut.signature.fill(0xee);
    expect(verifyCommitment(venue.latestFor(sequencer.operator)!)).toBe(true);
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
    // Retarget the issuance in the log — the log is the whole of what is
    // committed, so the root is what has to catch it.
    const tampered = snapshot.map((s) => ({
      ...s,
      opLog: s.opLog.map((entry) =>
        entry.kind === "issue" ? { ...entry, recipient: KEYS.mallory } : entry,
      ),
    }));
    expect(stateRoot(tampered)).not.toEqual(commitment.root);
  });

  it("two different roots at one sequence by one operator are equivocation", () => {
    const { sequencer } = setup();
    const honest = sequencer.commit();
    // A second, conflicting commitment at the same sequence.
    const forgedRoot = new Uint8Array(32).fill(0xab);
    const conflicting = signCommitment(SECRETS.operator, honest.sequence, forgedRoot);
    expect(isEquivocation(honest, conflicting)).toBe(true);
  });

  it("distinct roots at distinct sequences are not equivocation", () => {
    const { sequencer } = setup();
    const first = sequencer.commit();
    const second = sequencer.commit();
    expect(second.sequence).toBe(first.sequence + 1n);
    expect(isEquivocation(first, second)).toBe(false);
  });

  it("a commitment signed by a different key is not the operator's equivocation", () => {
    const { sequencer } = setup();
    const honest = sequencer.commit();
    const impostor = signCommitment(SECRETS.mallory, honest.sequence, new Uint8Array(32).fill(0xcd));
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
        opLog: [{ position: 0, kind: "transfer" as const, from, to, quantity: 7n, nonce: 0n, signature: new Uint8Array(64) }],
      },
    ];
    expect(() => stateRoot(state(bytes.slice(0, 32), bytes.slice(32)))).not.toThrow();
    expect(() => stateRoot(state(bytes.slice(0, 31), bytes.slice(31)))).toThrow(EncodingError);
  });

  it("rejects two snapshots for one backing", () => {
    const one = { name, issued: 0n, burned: 0n, opLog: [] };
    expect(() => stateRoot([one, one])).toThrow(EncodingError);
  });
});

describe("verifiers return false on hostile input, never throw", () => {
  const name = new Uint8Array(32).fill(0x01);
  const shortKey = new Uint8Array(31);
  const sig = new Uint8Array(64);

  it("a malformed operator key fails verification instead of crashing", () => {
    expect(verifyCommitment({ sequence: 0n, root: name, operator: shortKey, signature: sig })).toBe(false);
    expect(
      verifyReceipt({ backingName: name, opHash: name, position: 0n, operator: shortKey, signature: sig }),
    ).toBe(false);
  });

  it("a non-integer served position fails the proof instead of crashing", () => {
    const hostile = {
      name,
      opLog: [{ position: 1.5, kind: "burn" as const, holder: name, quantity: 1n, nonce: 0n, signature: new Uint8Array(64) }],
    };
    const receipt = { backingName: name, opHash: name, position: 0n, operator: name, signature: sig };
    expect(receiptProvenBy(receipt, hostile)).toBe(false);
  });

  it("a negative served amount fails the commitment check instead of crashing", () => {
    const bad = [{ name, issued: -1n, burned: 0n, opLog: [] }];
    expect(stateProvesCommitment(bad, { sequence: 0n, root: name, operator: name, signature: sig })).toBe(false);
  });
});

// A root can be injective and still let an operator assert state with more
// than one meaning, or state that hides an accepted operation. Canonical form
// closes both.

describe("invariant 22: committed state has exactly one meaning", () => {
  const name = new Uint8Array(32).fill(0x01);
  const holder = new Uint8Array(32).fill(0x02);

  it("rejects an op-log position that does not match its index", () => {
    // A gap lets an operator commit to state in which a holder's valid,
    // operator-signed receipt for the missing position proves against nothing.
    const entry = (position: number) => ({
      position,
      kind: "burn" as const,
      holder,
      quantity: 1n,
      nonce: 0n,
      signature: new Uint8Array(64),
    });
    expect(() =>
      stateRoot([{ name, opLog: [entry(0), entry(5)] }]),
    ).toThrow(EncodingError);
  });

  it("rejects an oversized quantity in a logged operation", () => {
    // Unbounded, an attacker-sized integer turns "a malformed state fails the
    // proof" into a hang. The bound now lives in one place, the message
    // encoders, rather than beside every committed amount.
    const started = Date.now();
    expect(
      stateProvesCommitment(
        [
          {
            name,
            opLog: [
              {
                position: 0,
                kind: "burn" as const,
                holder,
                quantity: 1n << 200000n,
                nonce: 0n,
                signature: new Uint8Array(64),
              },
            ],
          },
        ],
        { sequence: 0n, root: name, operator: name, signature: new Uint8Array(64) },
      ),
    ).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

// The operation log now carries presentation entries too, and their committed
// bytes are the bytes the party signed. A hostile operator must not be able to
// serve a malformed one and turn a failed proof into a crash.

describe("invariant 22: hostile presentation entries fail the proof, never throw", () => {
  const name = new Uint8Array(32).fill(0x01);
  const holder = new Uint8Array(32).fill(0x02);
  const sig = new Uint8Array(64);
  const commitment = { sequence: 0n, root: name, operator: name, signature: sig };
  const withLog = (entry: unknown) =>
    [{ name, opLog: [entry] }] as Parameters<typeof stateRoot>[0];

  it("rejects a short demand hash on an acceptance, release or withdrawal", () => {
    const short = new Uint8Array(31);
    for (const kind of ["release", "withdrawal"] as const) {
      expect(() => stateRoot(withLog({ position: 0, kind, demandHash: short, nonce: 0n, signature: new Uint8Array(64) }))).toThrow(
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
          signature: new Uint8Array(64),
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
      signature: new Uint8Array(64),
    });
    expect(() => stateRoot(withLog(entry(0n)))).toThrow(EncodingError);
    expect(() => stateRoot(withLog(entry(-1n)))).toThrow(EncodingError);
  });

  it("rejects a logged presentation entry with a negative nonce or instant", () => {
    expect(() =>
      stateRoot(withLog({ position: 0, kind: "withdrawal", demandHash: name, nonce: -1n, signature: new Uint8Array(64) })),
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
          signature: new Uint8Array(64),
        }),
      ),
    ).toThrow(EncodingError);
  });

  it("the verifier returns false rather than propagating the throw", () => {
    expect(
      stateProvesCommitment(
        withLog({ position: 0, kind: "release", demandHash: new Uint8Array(31), nonce: 0n, signature: new Uint8Array(64) }),
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
      signature: new Uint8Array(64),
    };
    const withdrawalEntry = {
      position: 0,
      kind: "withdrawal" as const,
      demandHash: holder,
      nonce: 0n,
      signature: new Uint8Array(64),
    };
    expect(bytesToHex(stateRoot(withLog(demandEntry)))).not.toBe(
      bytesToHex(stateRoot(withLog(withdrawalEntry))),
    );
  });
});
