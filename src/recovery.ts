// §C2b: failure, silence, and recovery — the two facts that open snapshot
// redemption.
//
// "When sequencers go dark, claims go illiquid rather than dead. Value discounts
// until they return, and after the declared silence, redemption against the last
// witnessed snapshot opens without co-signature, with the holder proving the
// claim unspent as of that snapshot."
//
// Two things have to be true, and both are checkable by a stranger against the
// published record — which is what makes the grade something a backer concedes
// rather than argues:
//
//   1. **the grade.** "No commitment past a second declared duration, in any
//      setting: the aggravated grade. It opens snapshot redemption and runs from
//      the first missed commitment until commitments resume." Measured on the
//      venue's clock, never the silent party's own publications, and against the
//      duration the backing itself declares in E.
//   2. **the unspentness proof.** Invariant 23: "The spent set must support
//      non-membership proofs, since §C2b's recovery path proves a claim *not*
//      spent as of the last commitment, which a bare Merkle root cannot do."
//      §C2b names the transparent form: "a signed spend record published at the
//      venue, checked against the last committed balance state, stands in for
//      the nullifier."
//
// Under transparent the whole served state is rehashed against the root, which
// is already how a receipt proves, so **serving everything IS the
// non-membership proof** — the Merkle machinery is what a construction needs
// when it cannot serve everything, and belongs with the shielded ones. See
// DECISIONS.md.
//
// **The payment path is those legs, published somewhere else.** §C2b:
// "Snapshot redemption publishes the claim's nullifier at the witness venue as
// the release leg, after the backer's acceptance." So it is not a second
// protocol beside §C3's demand-accept-release; it is that protocol with the legs
// published at the venue because there is no sequencer to submit them to, and
// under transparent a signed spend record IS an operation-log entry. One law,
// one replay, one nonce sequence — the legs go through the same `applyEntry`,
// and a returning sequencer adopting them is appending them in the order the
// venue witnessed them.
//
// Two things follow, and neither needed a new rule:
//
//   - **a standing demand is continued, not blocked.** Where the holder already
//     filed at the sequencer, the claim leg has happened and only the answer and
//     the release are left, which is §C2b's sentence read literally. Where they
//     had not, the claim leg is an ordinary demand, and a demand needs SPENDABLE
//     units — held minus what open demands commit — so the same units cannot
//     back two claims. Blocking instead would have deadlocked the holder, since
//     ending a demand takes a withdrawal and a withdrawal takes a sequencer.
//   - **the clock is the venue's stamp.** Every leg is judged at the index the
//     venue witnessed it at, which is the venue's word rather than the
//     operator's, so no leg needs an index anybody asserts. See DECISIONS.md.
//
// Everything here is a verifier: it answers questions about state an untrusted
// operator served, so it returns false on any malformed input and never throws.

import { type Backing } from "./backing.js";
import {
  applyEntry,
  copyState,
  replayLog,
  type DemandRecord,
  type LedgerState,
} from "./ledger.js";
import { compareBytes, copyBytes, isValidQuantity } from "./bytes.js";
import { type PublishedOp } from "./oplog.js";
import {
  stateProvesCommitment,
  type BackingSnapshot,
  type Commitment,
} from "./commitment.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Venue, type WitnessedOp } from "./venue.js";

/** A served state and the commitment it must prove against — what a holder is handed. */
export interface ServedState {
  readonly snapshots: readonly BackingSnapshot[];
  readonly commitment: Commitment;
}

/**
 * How many witnessed indices this operator has been quiet. Measured from its
 * latest commitment, or from the venue's genesis where it has never published —
 * otherwise never publishing at all would be the way to escape the grade.
 */
export function quietFor(venue: Venue, operator: Uint8Array): bigint {
  return venue.witnessedIndex() - (venue.witnessedAtFor(operator) ?? 0n);
}

/**
 * §C2b's aggravated grade for this backing: its operator has published no
 * commitment for longer than the duration the backing declares. A backing whose
 * E declares no silence clause is never silent — snapshot redemption never opens
 * for it and its claims can go illiquid forever, which is a setting the backer
 * chose and the holder read before accepting.
 */
export function isSilent(venue: Venue, backing: Backing): boolean {
  const clause = backing.evidence.silence;
  if (clause === undefined) return false;
  return quietFor(venue, backing.evidence.operator) > clause.noCommitmentDuration;
}

/**
 * The one check on served state, and what everything else here rests on: it is
 * the state this backing's operator committed to, and its operation log replays
 * under the law.
 *
 * Two properties, because a committed log is the whole of what is served: what
 * the operator asserts, and whether it could have happened. Balances, totals and
 * standing demands are not compared against anything, because they are not
 * asserted separately — they are what the replay returns.
 *
 * A verifier: the state comes from an operator with a motive, so any malformed
 * field is a failed check rather than a crash.
 */
export function stateIsAuthentic(backing: Backing, served: ServedState): boolean {
  return replayServedState(backing, served) !== undefined;
}

/**
 * The state a served snapshot replays to, or undefined if it is not this
 * backing's committed state or not a history that could have happened. The
 * shared body behind stateIsAuthentic and provesHolding, so a caller that needs
 * the numbers does not verify twice.
 */
function replayServedState(backing: Backing, served: ServedState): LedgerState | undefined {
  try {
    const operator = backing.evidence.operator;
    // Signed by the operator E names — anyone can sign a valid commitment over
    // any state they like, and a stranger's says nothing about this backing.
    if (compareBytes(served.commitment.operator, operator) !== 0) return undefined;
    if (!stateProvesCommitment(served.snapshots, served.commitment)) return undefined;
    const snapshot = served.snapshots.find((s) => compareBytes(s.name, backing.name) === 0);
    if (snapshot === undefined) return undefined;
    return replayLog(backing, snapshot.opLog);
  } catch {
    return undefined;
  }
}

/**
 * Whether the served state proves this holder held at least `quantity` of this
 * backing as of the operator's LAST witnessed commitment.
 *
 * "Last" is load-bearing rather than decorative: against an older commitment a
 * holder who has since spent the units would still prove the state that shows
 * them.
 *
 * It answers the holding, not the policy: whether a standing demand on the same
 * units blocks redemption is a question for the redemption legs, where the
 * double-payment it would risk actually arises. See DECISIONS.md.
 */
export function provesHolding(
  venue: Venue,
  backing: Backing,
  served: ServedState,
  holder: Uint8Array,
  quantity: bigint,
): boolean {
  try {
    if (!isValidQuantity(quantity)) return false;
    const replay = replayLatestState(venue, backing, served);
    if (replay === undefined) return false;
    return (replay.balances.get(bytesToHex(holder)) ?? 0n) >= quantity;
  } catch {
    return false;
  }
}

/**
 * The state a served snapshot replays to, once it has been established that it
 * IS this operator's last witnessed commitment. Shared by provesHolding and by
 * the redemption walk, which both turn on "last": against an older commitment a
 * holder who has since spent the units still proves the state that shows them.
 */
function replayLatestState(
  venue: Venue,
  backing: Backing,
  served: ServedState,
): LedgerState | undefined {
  const latest = venue.latestFor(backing.evidence.operator);
  if (latest === undefined) return undefined;
  if (latest.sequence !== served.commitment.sequence) return undefined;
  if (compareBytes(latest.root, served.commitment.root) !== 0) return undefined;
  return replayServedState(backing, served);
}

/**
 * Whether snapshot redemption is open to this holder for this quantity: the
 * operator is silent past the declared duration, and the last witnessed snapshot
 * proves the holding. Both, or neither — silence without a proved holding
 * redeems nothing, and a proved holding while the operator is answering belongs
 * at the sequencer, where §C3's presentation already handles it.
 */
export function redemptionIsOpen(
  venue: Venue,
  backing: Backing,
  served: ServedState,
  holder: Uint8Array,
  quantity: bigint,
): boolean {
  return isSilent(venue, backing) && provesHolding(venue, backing, served, holder, quantity);
}

/**
 * The four legs of §C3's presentation, and nothing else. A publication of any
 * other kind is evidence or noise, never an operation on the claim layer:
 *
 *   - an **issue** or **burn** at the venue would let a dark operator's backing
 *     be inflated or destroyed by a party the sequencer never served.
 *   - a **transfer** is read as a challenge (below) and must not be applied, and
 *     the reason is not squeamishness: §C2b promises that claims "go illiquid
 *     rather than dead" while a sequencer is dark, and illiquid means the
 *     transfers stop. Applying them would make the venue a second sequencer
 *     without an operator, order, or a receipt.
 */
function isLeg(op: PublishedOp): boolean {
  return (
    op.kind === "demand" ||
    op.kind === "acceptance" ||
    op.kind === "release" ||
    op.kind === "withdrawal"
  );
}

/**
 * **A publication is judged against the record as it stood strictly before its
 * own index**, which is the record it was made against. Both questions asked of
 * one below turn on it: had this operator gone silent, and which snapshot was
 * its last.
 *
 * The venue witnesses a commitment at index t and an operation at index t
 * together, so neither precedes the other — and the tie must not go to the
 * operator. It watches the venue: resolve the tie the other way and a silent
 * operator strips the force from any leg by committing at the index that leg
 * appears, which is a free veto over the whole clause. Silence is not a holder's
 * to manufacture (§C2b), and the end of it is not an operator's to backdate.
 *
 * It costs nothing in the other direction. A leg published at the index an
 * operator returns still has to name a state that was current, and the
 * snapshot check below is what refuses it.
 */
function before(at: bigint): bigint {
  return at - 1n;
}

/** Whether a publication witnessed at `at` landed inside a gap in commitments. */
function publishedInGap(venue: Venue, backing: Backing, at: bigint): boolean {
  const clause = backing.evidence.silence;
  if (clause === undefined) return false;
  const last = venue.witnessedAtFor(backing.evidence.operator, before(at)) ?? 0n;
  return at - last > clause.noCommitmentDuration;
}

/**
 * The operations a gap gave force to: its presentation legs, in the order the
 * venue witnessed them. This is what a returning sequencer adopts, and what the
 * redemption walk folds — exported so the two read one definition of what a
 * publication can do, rather than two that have to agree.
 */
export function gapLegsFor(venue: Venue, backing: Backing): WitnessedOp[] {
  return venue
    .publishedOpsFor(backing.name)
    .filter((w) => isLeg(w.op) && publishedInGap(venue, backing, w.at));
}

/** One party the backer pays for one redemption, and how much of it. */
export interface Payment {
  readonly payee: Uint8Array;
  readonly quantity: bigint;
}

/**
 * A redemption the gap settled: the demand it settles, and who is paid for it.
 *
 * A challenge does not void this. §C2b: "On publication the redemption pays the
 * request's presenter instead" — the payee moves, the settlement stands, and the
 * claims are the backer's either way. `payments` always sums to `quantity`.
 */
export interface Redemption {
  /** The demand settled, by the hash of its own canonical encoding. */
  readonly demandHash: Uint8Array;
  /** The holder who filed it. Not necessarily who gets paid. */
  readonly claimant: Uint8Array;
  readonly quantity: bigint;
  /** Who the backer pays, and how much: the claimant, unless challenged. */
  readonly payments: readonly Payment[];
  /** The witnessed index the release leg was published at. */
  readonly releasedAt: bigint;
  /** The last index at which a challenge is still heard. */
  readonly challengeClosesAt: bigint;
  /** Whether the window has closed, so the payee can no longer move. */
  readonly settled: boolean;
}

/** A settlement seen during the walk: the demand as it stood, and when. */
interface Settlement {
  readonly record: DemandRecord;
  readonly at: bigint;
}

/**
 * Fold the served log, then the gap's legs on top of it, each judged at the
 * index the venue witnessed it at. Returns what the gap settled, together with
 * the transfer requests published against the same backing — the raw material
 * for a challenge.
 *
 * A leg the law refuses is skipped rather than fatal: anyone may publish
 * anything at the venue, so a publication nobody could have accepted is noise,
 * not a corrupt log.
 */
function walkGap(
  venue: Venue,
  backing: Backing,
  served: ServedState,
  state: LedgerState,
): Settlement[] {
  const settlements: Settlement[] = [];
  for (const witnessed of gapLegsFor(venue, backing)) {
    // "Redemption against the LAST witnessed snapshot": the snapshot in hand
    // must be the one that was last when this leg was published. Asked about the
    // present instead, an operator that would rather a redemption were
    // unresolvable could make it so by publishing one more commitment — and a
    // backer-run operator is exactly the party with that motive.
    if (!isLatestAt(venue, backing, served, witnessed.at)) continue;
    // A release settles the demand and drops it, so the record has to be read
    // before the law applies the leg that removes it.
    const settling =
      witnessed.op.kind === "release"
        ? state.demands.get(bytesToHex(witnessed.op.demandHash))
        : undefined;
    try {
      applyEntry(state, backing, witnessed.op, witnessed.at);
    } catch {
      continue;
    }
    if (settling !== undefined) settlements.push({ record: settling, at: witnessed.at });
  }
  return settlements;
}

/**
 * Who the backer pays for one redemption: §C2b's challenge, generalised to
 * however many spends the operator swallowed.
 *
 * "Anyone may publish at the venue the holder-signed transfer request that spent
 * the named claim... on publication the redemption pays the request's presenter
 * instead." Under transparent a request spent the claim iff the SNAPSHOT could
 * have served it — the operator would have taken it, and went dark instead — so
 * the requests are folded onto a copy of the snapshot in the order the venue
 * witnessed them, and the redemption pays whoever ends up holding the units it
 * claimed. The law does the judging: a forged signature, a nonce already spent,
 * units the claimant never had, all refuse themselves.
 *
 * That gives four properties without four rules. Two conflicting requests at one
 * nonce are the claimant equivocating, and the earlier one wins because the
 * second finds its nonce spent — witnessing pins order (§C2). A chain of the
 * claimant's own spends pays each payee in turn, rather than the first and
 * nobody else. A request for more than was claimed redirects only what the
 * redemption pays. And a demand already standing in the snapshot cannot be
 * challenged at all, because its units were locked and its nonce spent before
 * the darkness — the lock had already done this job.
 *
 * **It pays the payee named in the request, not whoever published it.** The
 * spec's words are "pays the request's presenter", and its next clause explains
 * why they are normally the same party ("the payee already holds that request").
 * Read literally, anyone who merely saw a holder-signed transfer could publish
 * it and take the payment from the party it was made out to. See DECISIONS.md.
 *
 * The window bounds it and nothing else does: a request is evidence rather than
 * an operation, so it is not gated on the gap the legs are gated on. §C2b gives
 * the redemption a DECLARED window, and cutting it short the moment the operator
 * returns would let a prompt return decide how long anyone has to object.
 */
function paymentsFor(
  backing: Backing,
  snapshot: LedgerState,
  record: DemandRecord,
  requests: readonly WitnessedOp[],
  closesAt: bigint,
): Payment[] {
  const state = copyState(snapshot);
  const payments: Payment[] = [];
  let unpaid = record.quantity;
  // In sequence order, then in witnessed order. A chain has to be folded in the
  // order the claimant signed it: read in publication order instead and a payee
  // who reached the venue ahead of the one before them in the chain is passed
  // over and never reconsidered — which is whoever was quickest, deciding who
  // is paid. Witnessed order still settles the case it is for, which is two
  // requests at ONE nonce: that is the claimant equivocating, and the earlier
  // one wins (§C2, witnessing pins order).
  for (const witnessed of inSequenceOrder(requests, record.holder)) {
    const request = witnessed.op;
    if (request.kind !== "transfer") continue;
    if (witnessed.at > closesAt) continue;
    // **The chain starts where the claim leg stands, or not at all.** A spend
    // displaces this claim only by occupying its own point in the claimant's
    // sequence, or by following one that did. Take any spend that merely folds
    // and two of them go wrong: a spend of the claimant's OTHER units — free of
    // the demand's lock, and so nothing to do with the claimed ones — redirects
    // the payment; and where a holder files twice in one gap, one spend is paid
    // for against both claims.
    if (payments.length === 0 && request.nonce !== record.nonce) continue;
    try {
      applyEntry(state, backing, request, undefined);
    } catch {
      continue;
    }
    const quantity = request.quantity < unpaid ? request.quantity : unpaid;
    payments.push({ payee: copyBytes(request.to), quantity });
    unpaid -= quantity;
    if (unpaid === 0n) break;
  }
  if (unpaid > 0n) payments.push({ payee: copyBytes(record.holder), quantity: unpaid });
  return payments;
}

/**
 * This holder's published transfer requests, by nonce and then by the index the
 * venue witnessed them at. Both keys are needed and neither is enough: the nonce
 * is the order the claimant signed in, and the witnessed index is the only thing
 * that separates two requests signed at one nonce.
 */
function inSequenceOrder(requests: readonly WitnessedOp[], holder: Uint8Array): WitnessedOp[] {
  return requests
    .filter((w) => w.op.kind === "transfer" && compareBytes(w.op.from, holder) === 0)
    .sort((a, b) => {
      if (a.op.nonce !== b.op.nonce) return a.op.nonce < b.op.nonce ? -1 : 1;
      return a.at < b.at ? -1 : a.at > b.at ? 1 : 0;
    });
}

/** Whether the served state was this operator's latest commitment before `at`. */
function isLatestAt(venue: Venue, backing: Backing, served: ServedState, at: bigint): boolean {
  const latest = venue.latestFor(backing.evidence.operator, before(at));
  if (latest === undefined) return false;
  if (latest.sequence !== served.commitment.sequence) return false;
  return compareBytes(latest.root, served.commitment.root) === 0;
}

/**
 * Every snapshot redemption this backing's gap settled, in the order the
 * releases were witnessed, and who the backer pays for each.
 *
 * Each leg is judged against the snapshot that was this operator's last when
 * that leg was published — §C2b's "redemption against the last witnessed
 * snapshot", read at the index the leg was witnessed at rather than at the index
 * somebody asks. Against an older snapshot a holder who had since spent the
 * units would still prove the state that shows them, and here they would be paid
 * for it; against "whatever is latest now", one further commitment would make a
 * settled redemption unresolvable, which is a move its operator may well want.
 *
 * A verifier: the state comes from an operator with a motive, and the venue's
 * publications come from anyone at all, so anything malformed is a redemption
 * that does not resolve rather than a throw.
 */
export function snapshotRedemptions(
  venue: Venue,
  backing: Backing,
  served: ServedState,
): Redemption[] {
  try {
    const clause = backing.evidence.silence;
    if (clause === undefined) return [];
    const state = replayServedState(backing, served);
    if (state === undefined) return [];

    // The snapshot as it stood before any leg touched it: what a request has to
    // have been servable against to have spent anything.
    const snapshot = copyState(state);
    const requests = venue.publishedOpsFor(backing.name);
    return walkGap(venue, backing, served, state).map(({ record, at }) => {
      const closesAt = at + clause.challengeWindow;
      return {
        payments: paymentsFor(backing, snapshot, record, requests, closesAt),
        demandHash: copyBytes(record.hash),
        claimant: copyBytes(record.holder),
        quantity: record.quantity,
        releasedAt: at,
        challengeClosesAt: closesAt,
        settled: venue.witnessedIndex() > closesAt,
      };
    });
  } catch {
    return [];
  }
}
