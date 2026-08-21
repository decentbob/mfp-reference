import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { EncodingError } from "../src/bytes.js";
import { decodeCommitment, encodeCommitment, signCommitment } from "../src/commitment.js";
import {
  encodeBurnMessage,
  encodeIssuanceMessage,
  encodeTransferMessage,
} from "../src/messages.js";
import {
  encodeAcceptanceMessage,
  encodeDemandMessage,
  encodeReleaseMessage,
  encodeWithdrawalMessage,
} from "../src/presentation.js";
import { decodePublishedOp, encodePublishedOp, type PublishedOp } from "../src/oplog.js";
import {
  decodeReplacement,
  encodeReplacement,
  ROLE_OPERATOR,
  type Replacement,
} from "../src/replacement.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, makeTransparentBacking, SECRETS } from "./support.js";

// A venue that is not a variable in this process stores **bytes** — a chain
// stores bytes. So every record a venue holds needs a canonical encoding and a
// strict inverse, and this is what an Ergo (or any other) venue serialises.
//
// Two properties, and the second is the one that keeps the first honest:
//
//   - decode(encode(x)) is x, so nothing is lost;
//   - encode(decode(bytes)) is bytes, so a record has exactly ONE spelling.
//
// The operation record carries the **signed message** rather than a second
// field-by-field description of the operation. Two encoders that have to agree
// is the drift slice 5 removed, and it would be worse here: the message is what
// the signature covers, so a record describing the operation differently could
// carry a signature over something else.

const backing = makeTransparentBacking(SECRETS.backer);

type TransferOp = Extract<PublishedOp, { kind: "transfer" }>;

function transferOp(quantity = 40n, nonce = 0n): TransferOp {
  return {
    kind: "transfer",
    from: KEYS.alice,
    to: KEYS.bob,
    quantity,
    nonce,
    signature: ed25519.sign(
      encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, quantity, nonce),
      SECRETS.alice,
    ),
  };
}

describe("a venue's records have one canonical spelling", () => {
  it("round-trips a commitment, and refuses anything else", () => {
    const commitment = signCommitment(SECRETS.operator, 7n, new Uint8Array(32).fill(0xab));
    const bytes = encodeCommitment(commitment);
    expect(bytes).toHaveLength(8 + 32 + 32 + 64);
    expect(decodeCommitment(bytes)).toEqual(commitment);
    expect(encodeCommitment(decodeCommitment(bytes))).toEqual(bytes);

    expect(() => decodeCommitment(bytes.slice(0, bytes.length - 1))).toThrow(EncodingError);
    expect(() => decodeCommitment(new Uint8Array([...bytes, 0]))).toThrow(EncodingError);
  });

  it("round-trips every operation kind, and recovers the backing it names", () => {
    // The backing name is inside the signed message, so a record stands alone:
    // nothing beside it says which backing it belongs to and can disagree.
    // All seven kinds, because the decoder dispatches on the domain tag and a
    // kind it got wrong would only show up on the one it got wrong.
    const n = backing.name;
    const h = new Uint8Array(32).fill(0x5c); // a demand hash
    const sign = (m: Uint8Array, s: Uint8Array) => ed25519.sign(m, s);
    const ops: PublishedOp[] = [
      { kind: "issue", recipient: KEYS.alice, quantity: 100n, nonce: 0n,
        signature: sign(encodeIssuanceMessage(n, KEYS.alice, 100n, 0n), SECRETS.backer) },
      transferOp(),
      { kind: "burn", holder: KEYS.alice, quantity: 5n, nonce: 1n,
        signature: sign(encodeBurnMessage(n, KEYS.alice, 5n, 1n), SECRETS.alice) },
      { kind: "demand", holder: KEYS.alice, quantity: 40n, instant: 3n, deadline: 9n, nonce: 2n,
        signature: sign(encodeDemandMessage(n, KEYS.alice, 40n, 3n, 9n, 2n), SECRETS.alice) },
      { kind: "acceptance", demandHash: h, instant: 3n, deadline: 9n, nonce: 1n,
        signature: sign(encodeAcceptanceMessage(n, h, 3n, 9n, 1n), SECRETS.backer) },
      { kind: "release", demandHash: h, nonce: 3n,
        signature: sign(encodeReleaseMessage(n, h, 3n), SECRETS.alice) },
      { kind: "withdrawal", demandHash: h, nonce: 4n,
        signature: sign(encodeWithdrawalMessage(n, h, 4n), SECRETS.alice) },
    ];
    expect(new Set(ops.map((o) => o.kind)).size).toBe(7);
    for (const op of ops) {
      const bytes = encodePublishedOp(n, op);
      const decoded = decodePublishedOp(bytes);
      expect(decoded.op).toEqual(op);
      expect(decoded.backingName).toEqual(n);
      expect(encodePublishedOp(n, decoded.op)).toEqual(bytes);
    }
  });

  it("refuses a record whose message opens with no known context", () => {
    // The kind is read from the domain tag the message already carries, and
    // contexts.ts asserts those are prefix-free, so at most one can match. A
    // second kind tag beside it would be a second mechanism for one property.
    const bytes = encodePublishedOp(backing.name, transferOp());
    const tampered = bytes.slice();
    tampered[4] = 0x00; // first byte of the context, after the u32 length
    expect(() => decodePublishedOp(tampered)).toThrow(EncodingError);
  });

  it("refuses a record with a truncated or extended message", () => {
    const bytes = encodePublishedOp(backing.name, transferOp());
    expect(() => decodePublishedOp(bytes.slice(0, bytes.length - 1))).toThrow(EncodingError);
    expect(() => decodePublishedOp(new Uint8Array([...bytes, 0]))).toThrow(EncodingError);
  });

  it("round-trips a replacement, and refuses anything else", () => {
    const replacement: Replacement = {
      role: ROLE_OPERATOR,
      successor: KEYS.operator,
      predecessor: backing.name,
      effective: 12n,
      signature: ed25519.sign(new Uint8Array(8), SECRETS.backer),
    };
    const bytes = encodeReplacement(backing.name, replacement);
    expect(bytes).toHaveLength(32 + 1 + 32 + 32 + 8 + 64);
    const decoded = decodeReplacement(bytes);
    expect(decoded.replacement).toEqual(replacement);
    expect(decoded.backingName).toEqual(backing.name);
    expect(encodeReplacement(decoded.backingName, decoded.replacement)).toEqual(bytes);
    expect(() => decodeReplacement(bytes.slice(1))).toThrow(EncodingError);
  });
});

describe("holding bytes makes copy-in copy-out structural", () => {
  it("does not let a publisher rewrite what it published", () => {
    // The rule CLAUDE.md states without exception, and it used to need three
    // explicit copy functions. Encoding on the way in is the same guarantee
    // with nothing to forget: the record is bytes the publisher never held.
    const venue = new LocalVenue();
    const commitment = signCommitment(SECRETS.operator, 0n, new Uint8Array(32).fill(0x11));
    venue.publish(commitment);
    commitment.root.fill(0xff);
    expect(venue.latestFor(KEYS.operator)?.root).toEqual(new Uint8Array(32).fill(0x11));

    const op = transferOp();
    venue.publishOp(backing.name, op);
    op.signature.fill(0xff);
    expect((venue.publishedOpsFor(backing.name)[0]!.op as TransferOp).signature).toEqual(transferOp().signature);
  });

  it("does not let one reader poison the record for the next", () => {
    const venue = new LocalVenue();
    venue.publishOp(backing.name, transferOp());
    (venue.publishedOpsFor(backing.name)[0]!.op as TransferOp).signature.fill(0xff);
    expect((venue.publishedOpsFor(backing.name)[0]!.op as TransferOp).signature).toEqual(transferOp().signature);
  });
});
