// One backing's operation log: the entry shape, and the canonical bytes of an
// entry.
//
// Every accepted operation appends exactly one entry, and `position` is the
// per-backing append index — a stand-in for witnessed interval time (§C2). The
// log carries all seven operation kinds: the three that move value (issue,
// transfer, burn) and the four of presentation (demand, acceptance, release,
// withdrawal). Presentation belongs here because a receipt binds an operation to
// its position in the committed log (receipt.ts), and an operation that moves no
// value still needs to be undeniable.
//
// The one property this file exists for: **an entry's canonical bytes ARE the
// bytes the party signed.** So a verifier holding only a committed log entry can
// reconstruct the exact signed message, hash it, and compare it with a receipt;
// and the commitment (commitment.ts) commits precisely the operation the receipt
// attests to, rather than a re-description of it that a second encoder might get
// wrong. Each entry therefore carries its signed fields and nothing else:
//
//   - a release names the demand it settles, not the balances it moves. The
//     quantity and the holder come from the demand's own entry, earlier in the
//     same append-only log, and the destination is the obligor named in the
//     backing's terms. Neither is the operator's to assert.
//   - the demand hash an acceptance, release or withdrawal names is recomputable
//     from that demand's entry, so nothing here rests on an operator's word.
//
// Beside the signed fields each entry carries the signature that authorised it.
// That signature is NOT part of the entry's canonical bytes and is not
// committed: the message it covers already is, and only the true signer can
// produce one over it. It is served, which is what lets a verifier establish
// that a committed log was authorised rather than invented.
//
// This module knows the shape of an entry and its bytes, and nothing about the
// law. What an entry does to a state, and when it is refused, is ledger.ts:
// applyEntry, which the ledger applies as operations arrive and a verifier
// folds a served log through.

import {
  encodeBurnMessage,
  encodeIssuanceMessage,
  encodeTransferMessage,
} from "./messages.js";
import {
  encodeAcceptanceMessage,
  encodeDemandMessage,
  encodeReleaseMessage,
  encodeWithdrawalMessage,
} from "./presentation.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ByteReader, ByteWriter, compareBytes, copyBytes, EncodingError, MAX_QUANTITY_BYTES, minimalBytesToBigint } from "./bytes.js";
import {
  ACCEPTANCE_CONTEXT,
  BURN_CONTEXT,
  DEMAND_CONTEXT,
  ISSUANCE_CONTEXT,
  RELEASE_CONTEXT,
  TRANSFER_CONTEXT,
  WITHDRAWAL_CONTEXT,
} from "./contexts.js";
import { SIGNATURE_LENGTH } from "./keys.js";

/**
 * One operation, as its signer put a signature over it: the signed fields and
 * that signature, and nothing about where it ended up. This is what a party
 * hands a sequencer, and it is also what §C2b has a holder publish at the venue
 * when the sequencer is dark — the same operation, put somewhere else.
 */
export type PublishedOp =
  | {
      readonly kind: "issue";
      readonly recipient: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly kind: "transfer";
      readonly from: Uint8Array;
      readonly to: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly kind: "burn";
      readonly holder: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly kind: "demand";
      readonly holder: Uint8Array;
      readonly quantity: bigint;
      readonly instant: bigint;
      readonly deadline: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly kind: "acceptance";
      readonly demandHash: Uint8Array;
      readonly instant: bigint;
      readonly deadline: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly kind: "release";
      readonly demandHash: Uint8Array;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly kind: "withdrawal";
      readonly demandHash: Uint8Array;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    };

/**
 * One entry in a backing's operation log: an operation, plus the append index
 * it landed at. The position is the log's own bookkeeping and is in no signed
 * message, which is what lets the same operation exist before it has a log to
 * be in — the shape §C2b's venue publication needs.
 */
export type OpLogEntry = PublishedOp & { readonly position: number };

/**
 * An operation of no known kind is not an operation, and every switch over the
 * seven kinds ends here.
 *
 * The parameter is `never`, so a kind added to PublishedOp and forgotten at a
 * call site is a compile error at the place that has to decide. The return is
 * `never` too, because the runtime needs the same answer the types give: a
 * switch that simply ran off its end returned `undefined` typed as bytes, and
 * the callers that treat a throw as a refusal — the venue's one guard on what it
 * records, and every verifier's catch — read that as success. It is an
 * EncodingError because that is the boundary: these fields are not well-formed.
 */
export function unknownOpKind(entry: never): never {
  const { kind } = entry as { kind?: unknown };
  throw new EncodingError(`unknown operation kind ${String(kind)}`);
}

/**
 * The canonical signed message of an operation. Throws EncodingError on a
 * malformed entry — a served log may come from a hostile operator, so every
 * caller that reads adversary-supplied state treats a throw as a failed proof
 * (receiptProvenBy, stateProvesCommitment) rather than letting it escape.
 */
export function opMessageOfEntry(backingName: Uint8Array, entry: PublishedOp): Uint8Array {
  switch (entry.kind) {
    case "issue":
      return encodeIssuanceMessage(backingName, entry.recipient, entry.quantity, entry.nonce);
    case "transfer":
      return encodeTransferMessage(backingName, entry.from, entry.to, entry.quantity, entry.nonce);
    case "burn":
      return encodeBurnMessage(backingName, entry.holder, entry.quantity, entry.nonce);
    case "demand":
      return encodeDemandMessage(
        backingName,
        entry.holder,
        entry.quantity,
        entry.instant,
        entry.deadline,
        entry.nonce,
      );
    case "acceptance":
      return encodeAcceptanceMessage(
        backingName,
        entry.demandHash,
        entry.instant,
        entry.deadline,
        entry.nonce,
      );
    case "release":
      return encodeReleaseMessage(backingName, entry.demandHash, entry.nonce);
    case "withdrawal":
      return encodeWithdrawalMessage(backingName, entry.demandHash, entry.nonce);
  }
  return unknownOpKind(entry);
}

/** The operation hash a receipt is bound to: sha256 of the signed message. */
export function opHashOfEntry(backingName: Uint8Array, entry: PublishedOp): Uint8Array {
  return sha256(opMessageOfEntry(backingName, entry));
}

/**
 * An operation as a **record**: the exact bytes its signer signed, then the
 * signature over them.
 *
 * A venue that is anything but an object in memory stores bytes, so a published
 * operation needs one. It is the signed message rather than a second
 * field-by-field description of the operation, because two encoders that have to
 * agree is the drift slice 5 removed — the message is the only description, and
 * this record is that message with the signature that authorised it.
 *
 * The backing name is inside the message, so a record stands alone: nothing
 * beside it says which backing it belongs to and can disagree.
 */
export function encodePublishedOp(backingName: Uint8Array, op: PublishedOp): Uint8Array {
  const w = new ByteWriter();
  w.lengthPrefixed(opMessageOfEntry(backingName, op));
  w.fixed(op.signature, SIGNATURE_LENGTH, "signature");
  return w.finish();
}

/**
 * Every operation context, with the kind whose message opens with it.
 *
 * **At most one can ever match**, because contexts.ts asserts at load that no tag
 * is a prefix of another. That is what makes reading the kind off the message
 * sound, and it is why the order of this list carries no meaning and no tie-break
 * is needed: there is never more than one candidate to break a tie between.
 */
const OP_CONTEXTS: readonly (readonly [Uint8Array, PublishedOp["kind"]])[] = [
  [ISSUANCE_CONTEXT, "issue"],
  [TRANSFER_CONTEXT, "transfer"],
  [BURN_CONTEXT, "burn"],
  [DEMAND_CONTEXT, "demand"],
  [ACCEPTANCE_CONTEXT, "acceptance"],
  [RELEASE_CONTEXT, "release"],
  [WITHDRAWAL_CONTEXT, "withdrawal"],
];

/** A quantity, as every operation message writes it. */
function readQuantity(r: ByteReader): bigint {
  return minimalBytesToBigint(r.lengthPrefixed(MAX_QUANTITY_BYTES));
}

/**
 * Strict inverse of encodePublishedOp: accepts exactly the canonical bytes and
 * nothing else, and hands back the backing name the message names alongside the
 * operation.
 *
 * The kind is read from the domain tag the message already opens with.
 * contexts.ts asserts those are prefix-free, so at most one can match and no
 * second tag is needed — the same reason commitment.ts stopped writing one.
 *
 * Throws EncodingError on anything else. Round-tripping is the contract:
 * decode(encode(x)) is x, and encode(decode(bytes)) is bytes, so a record has
 * exactly one spelling.
 */
export function decodePublishedOp(bytes: Uint8Array): {
  readonly backingName: Uint8Array;
  readonly op: PublishedOp;
} {
  const outer = new ByteReader(bytes);
  const message = outer.lengthPrefixed(1 << 16);
  const signature = outer.raw(SIGNATURE_LENGTH);
  outer.expectEnd();

  const found = OP_CONTEXTS.find(
    ([context]) =>
      message.length >= context.length &&
      compareBytes(message.subarray(0, context.length), context) === 0,
  );
  if (found === undefined) throw new EncodingError("no known operation context");
  const [context, kind] = found;

  const r = new ByteReader(message.subarray(context.length));
  const backingName = r.raw(32);
  const op = ((): PublishedOp => {
    switch (kind) {
      case "issue": {
        const recipient = r.raw(32);
        return { kind, recipient, quantity: readQuantity(r), nonce: r.u64(), signature };
      }
      case "transfer": {
        const from = r.raw(32);
        const to = r.raw(32);
        return { kind, from, to, quantity: readQuantity(r), nonce: r.u64(), signature };
      }
      case "burn": {
        const holder = r.raw(32);
        return { kind, holder, quantity: readQuantity(r), nonce: r.u64(), signature };
      }
      case "demand": {
        const holder = r.raw(32);
        const quantity = readQuantity(r);
        return { kind, holder, quantity, instant: r.u64(), deadline: r.u64(), nonce: r.u64(), signature };
      }
      case "acceptance": {
        const demandHash = r.raw(32);
        return { kind, demandHash, instant: r.u64(), deadline: r.u64(), nonce: r.u64(), signature };
      }
      case "release":
      case "withdrawal":
        return { kind, demandHash: r.raw(32), nonce: r.u64(), signature };
    }
  })();
  r.expectEnd();
  // The message is the only description of the operation, so the round trip is
  // what proves this decoder is its inverse rather than a second reading of it.
  if (compareBytes(encodePublishedOp(backingName, op), bytes) !== 0) {
    throw new EncodingError("published operation is not canonical");
  }
  return { backingName, op };
}

/** A deep copy: no accessor hands out a write path into ledger state (inv 8). */
export function copyOp(entry: PublishedOp): PublishedOp {
  switch (entry.kind) {
    case "issue":
      return { ...entry, recipient: copyBytes(entry.recipient), signature: copyBytes(entry.signature) };
    case "transfer":
      return {
        ...entry,
        from: copyBytes(entry.from),
        to: copyBytes(entry.to),
        signature: copyBytes(entry.signature),
      };
    case "burn":
    case "demand":
      return { ...entry, holder: copyBytes(entry.holder), signature: copyBytes(entry.signature) };
    case "acceptance":
    case "release":
    case "withdrawal":
      return {
        ...entry,
        demandHash: copyBytes(entry.demandHash),
        signature: copyBytes(entry.signature),
      };
  }
  return unknownOpKind(entry);
}

/** The same copy, keeping the entry's place in the log. */
export function copyOpEntry(entry: OpLogEntry): OpLogEntry {
  return { ...copyOp(entry), position: entry.position };
}
