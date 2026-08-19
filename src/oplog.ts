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
import type { DemandRecord } from "./ledger.js";

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
 * earlier in the same append-only log. A demand's hash is exactly its operation
 * hash, because a demand's canonical message is what both are taken over.
 *
 * Undefined means no signer can be established, which is itself a refusal: a
 * settlement of a demand that is not standing has nobody to check against.
 */
function signerOf(
  backing: Backing,
  entry: OpLogEntry,
  standing: Map<string, DemandRecord>,
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
      return standing.get(bytesToHex(entry.demandHash))?.holder;
  }
}

/**
 * The state a log leaves behind: balances by holder hex, the running totals, and
 * the standing demand record. Invariant 23's objects, every one of them a fold
 * over the log rather than something an operator asserts beside it.
 *
 * Invariant 10 holds here by construction rather than by inspection: an issue
 * credits a holder and raises `issued` by the same amount, a burn debits and
 * raises `burned`, and transfers and settlements move units without touching
 * either — so `outstanding = issued − burned` is always the sum of the balances.
 */
export interface LogReplay {
  readonly balances: Map<string, bigint>;
  readonly issued: bigint;
  readonly burned: bigint;
  readonly demands: readonly DemandRecord[];
}

/**
 * Replay a served operation log, or undefined if it is not a history that could
 * have happened.
 *
 * This is invariant 8 applied to served state, and it takes three refusals
 * because an operator can lie in three places. Without the **signature** it
 * appends transfers nobody signed and makes the balances agree with them —
 * conservation and the arithmetic both pass, because nothing was destroyed and
 * the state is consistent with its own lie. Without the **nonce sequence** it
 * does not even need to forge one: it logs a transfer the holder really did sign
 * as many times as the balances will bear, and takes a multiple of the units on
 * one signature. Without the **demand lifecycle and its lock** it settles a
 * demand the holder withdrew, using a release the holder signed and the ledger
 * refused, or spends units an open demand has committed and leaves a demand no
 * units back. All of them were demonstrated before they were closed.
 *
 * The nonce inside the signed message is what makes a signature single-use, so
 * each signer is held to the sequence the ledger holds them to — starting at 0
 * and rising by 1 — which also rejects a log with a gap, since an operation
 * dropped from the middle leaves the next one at a nonce nobody reached.
 *
 * What it does NOT replay is the law's time-dependent rules: whether an
 * acceptance was still live when released against, whether a demand's deadline
 * had passed when answered. The log does not record the witnessed index each
 * operation was accepted at, so they cannot be checked from it. See DECISIONS.md.
 *
 * A verifier: the log comes from an operator with a motive, so any malformed
 * entry is a refusal rather than a throw.
 */
export function replayLog(
  backing: Backing,
  entries: readonly OpLogEntry[],
): LogReplay | undefined {
  try {
    const balances = new Map<string, bigint>();
    const standing = new Map<string, DemandRecord>();
    let issued = 0n;
    let burned = 0n;
    const nextNonce = new Map<string, bigint>();
    const move = (key: Uint8Array, delta: bigint): void => {
      const hex = bytesToHex(key);
      const units = (balances.get(hex) ?? 0n) + delta;
      // Drop at zero so the replay enumerates current holders only, exactly as
      // the ledger's own book does.
      if (units === 0n) balances.delete(hex);
      else balances.set(hex, units);
    };
    // Units an open demand has committed cannot leave by an ordinary path
    // (§C3), so the replay reads the same spendable figure the ledger does:
    // held minus committed. Derived from the standing demands rather than
    // tracked beside them, so there is one source of truth.
    const spendable = (key: Uint8Array): bigint => {
      const hex = bytesToHex(key);
      let locked = 0n;
      for (const record of standing.values()) {
        if (bytesToHex(record.holder) === hex) locked += record.quantity;
      }
      return (balances.get(hex) ?? 0n) - locked;
    };

    for (const entry of entries) {
      const signer = signerOf(backing, entry, standing);
      if (signer === undefined) return undefined;
      // Nonce first: it is the cheap half, and a hostile log should not buy a
      // signature verification per entry before being refused.
      const signerHex = bytesToHex(signer);
      const expected = nextNonce.get(signerHex) ?? 0n;
      if (entry.nonce !== expected) return undefined;
      const message = opMessageOfEntry(backing.name, entry);
      if (!verifySignatureStrict(entry.signature, message, signer)) return undefined;
      nextNonce.set(signerHex, expected + 1n);

      switch (entry.kind) {
        case "issue":
          move(entry.recipient, entry.quantity);
          issued += entry.quantity;
          break;
        case "transfer":
          if (spendable(entry.from) < entry.quantity) return undefined;
          move(entry.from, -entry.quantity);
          move(entry.to, entry.quantity);
          break;
        case "burn":
          if (spendable(entry.holder) < entry.quantity) return undefined;
          move(entry.holder, -entry.quantity);
          burned += entry.quantity;
          break;
        case "demand": {
          // A backing with reliance cannot be presented at all until its legs
          // move (§C3, invariant 13), so a log that files one is not a history
          // the law could have produced.
          if (backing.reliance.length > 0) return undefined;
          // Only unlocked units may be committed, or one holding answers two
          // demands.
          if (spendable(entry.holder) < entry.quantity) return undefined;
          const hash = sha256(message);
          standing.set(bytesToHex(hash), {
            hash,
            holder: entry.holder,
            quantity: entry.quantity,
            instant: entry.instant,
            deadline: entry.deadline,
            nonce: entry.nonce,
            acceptedDeadline: undefined,
          });
          break;
        }
        case "acceptance": {
          // The backer cannot have answered a demand nobody filed, or one that
          // had already ended. An operator saying otherwise is inventing
          // evidence about the backer, which is the party §C3 says nobody paid
          // by can be trusted to record.
          const key = bytesToHex(entry.demandHash);
          const record = standing.get(key);
          if (record === undefined) return undefined;
          standing.set(key, { ...record, acceptedDeadline: entry.deadline });
          break;
        }
        case "release": {
          const key = bytesToHex(entry.demandHash);
          const record = standing.get(key);
          if (record === undefined) return undefined;
          move(record.holder, -record.quantity);
          move(backing.obligor, record.quantity);
          standing.delete(key);
          break;
        }
        case "withdrawal":
          standing.delete(bytesToHex(entry.demandHash));
          break;
      }
    }
    // A settlement is the one debit not guarded above, because the demand's own
    // lock already reserved the units. Sweep once rather than guard twice: a log
    // that drives any holding below zero is not a history that happened.
    for (const units of balances.values()) if (units < 0n) return undefined;
    return { balances, issued, burned, demands: [...standing.values()] };
  } catch {
    return undefined;
  }
}
