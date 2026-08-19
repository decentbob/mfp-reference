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
import { copyBytes } from "./bytes.js";

/** One entry in a backing's operation log. `position` is the append index. */
export type OpLogEntry =
  | {
      readonly position: number;
      readonly kind: "issue";
      readonly recipient: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly position: number;
      readonly kind: "transfer";
      readonly from: Uint8Array;
      readonly to: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly position: number;
      readonly kind: "burn";
      readonly holder: Uint8Array;
      readonly quantity: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly position: number;
      readonly kind: "demand";
      readonly holder: Uint8Array;
      readonly quantity: bigint;
      readonly instant: bigint;
      readonly deadline: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly position: number;
      readonly kind: "acceptance";
      readonly demandHash: Uint8Array;
      readonly instant: bigint;
      readonly deadline: bigint;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly position: number;
      readonly kind: "release";
      readonly demandHash: Uint8Array;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    }
  | {
      readonly position: number;
      readonly kind: "withdrawal";
      readonly demandHash: Uint8Array;
      readonly nonce: bigint;
      readonly signature: Uint8Array;
    };

/**
 * The canonical signed message of a logged operation. Throws EncodingError on a
 * malformed entry — a served log may come from a hostile operator, so every
 * caller that reads adversary-supplied state treats a throw as a failed proof
 * (receiptProvenBy, stateProvesCommitment) rather than letting it escape.
 */
export function opMessageOfEntry(backingName: Uint8Array, entry: OpLogEntry): Uint8Array {
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
}

/** The operation hash a receipt is bound to: sha256 of the signed message. */
export function opHashOfEntry(backingName: Uint8Array, entry: OpLogEntry): Uint8Array {
  return sha256(opMessageOfEntry(backingName, entry));
}

/** A deep copy: no accessor hands out a write path into ledger state (inv 8). */
export function copyOpEntry(entry: OpLogEntry): OpLogEntry {
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
}
