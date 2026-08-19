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
import { bytesToHex } from "@noble/hashes/utils.js";
import { type Backing } from "./backing.js";
import { copyBytes } from "./bytes.js";
import { verifySignatureStrict } from "./keys.js";

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

/**
 * Who the law requires to have signed a logged operation.
 *
 * Read from the backing's terms and from the log itself, never from a field the
 * operator writes beside the entry: an issuance is the obligor's, and so is an
 * acceptance; a transfer, burn and demand name their own signer; and a release
 * or withdrawal names a demand, whose holder is in that demand's own entry
 * earlier in the same append-only log. `demandHolders` accumulates those as the
 * walk proceeds — a demand's hash is exactly its operation hash, because a
 * demand's canonical message is what both are taken over.
 *
 * Undefined means no signer can be established, which is itself a refusal: an
 * operator that invents a settlement of a demand nobody filed leaves nothing to
 * check the release against.
 */
function signerOf(
  backing: Backing,
  entry: OpLogEntry,
  demandHolders: Map<string, Uint8Array>,
): Uint8Array | undefined {
  switch (entry.kind) {
    case "issue":
    case "acceptance":
      return backing.obligor;
    case "transfer":
      return entry.from;
    case "burn":
    case "demand":
      return entry.holder;
    case "release":
    case "withdrawal":
      return demandHolders.get(bytesToHex(entry.demandHash));
  }
}

/**
 * Whether every operation in this log carries the signature that authorised it.
 *
 * This is invariant 8 applied to served state: without it an operator can append
 * transfers nobody signed, make the balances agree with them, and lock every
 * holder out — conservation and the fold both pass, because nothing was
 * destroyed and the state is consistent with its own lie.
 *
 * The signature is served rather than committed: the entry's canonical message
 * is already inside the root, and only the true signer can produce a signature
 * over it, so committing it would add bytes without adding a property. That is
 * invariant 23's arrangement — the commitment "does not contain any of them, and
 * anything checked against them has to be served".
 *
 * A verifier, so it returns false on any malformed entry rather than throwing.
 */
export function entriesAreAuthentic(backing: Backing, entries: readonly OpLogEntry[]): boolean {
  try {
    const demandHolders = new Map<string, Uint8Array>();
    for (const entry of entries) {
      const signer = signerOf(backing, entry, demandHolders);
      if (signer === undefined) return false;
      const message = opMessageOfEntry(backing.name, entry);
      if (!verifySignatureStrict(entry.signature, message, signer)) return false;
      if (entry.kind === "demand") {
        demandHolders.set(bytesToHex(sha256(message)), entry.holder);
      }
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * The balances this log produces, replayed from an empty book: holder hex ->
 * units. A settlement moves its demand's quantity to the obligor named in the
 * backing's terms, which is why this needs the backing and not only the entries
 * — the release entry deliberately does not assert where the units went.
 *
 * Never throws: a malformed log simply folds to something that will not match
 * the balances it is checked against.
 */
export function foldBalances(
  backing: Backing,
  entries: readonly OpLogEntry[],
): Map<string, bigint> {
  const balances = new Map<string, bigint>();
  const demands = new Map<string, { holder: Uint8Array; quantity: bigint }>();
  const move = (key: Uint8Array, delta: bigint): void => {
    const hex = bytesToHex(key);
    const units = (balances.get(hex) ?? 0n) + delta;
    // Drop at zero so the fold enumerates current holders only, exactly as the
    // ledger's own book does.
    if (units === 0n) balances.delete(hex);
    else balances.set(hex, units);
  };
  for (const entry of entries) {
    try {
      switch (entry.kind) {
        case "issue":
          move(entry.recipient, entry.quantity);
          break;
        case "transfer":
          move(entry.from, -entry.quantity);
          move(entry.to, entry.quantity);
          break;
        case "burn":
          move(entry.holder, -entry.quantity);
          break;
        case "demand":
          demands.set(bytesToHex(sha256(opMessageOfEntry(backing.name, entry))), {
            holder: entry.holder,
            quantity: entry.quantity,
          });
          break;
        case "release": {
          const demand = demands.get(bytesToHex(entry.demandHash));
          if (demand === undefined) break;
          move(demand.holder, -demand.quantity);
          move(backing.obligor, demand.quantity);
          break;
        }
        case "acceptance":
        case "withdrawal":
          break;
      }
    } catch {
      // A malformed entry contributes nothing; the mismatch is the refusal.
    }
  }
  return balances;
}
