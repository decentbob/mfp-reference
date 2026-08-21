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
import { committedLogFor, type ServedState } from "./commitment.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { opHashOfEntry } from "./oplog.js";
import { operatorAt, operatorIn, successionOf, type Succession } from "./replacement.js";
import { revokedAt } from "./revocation.js";
import { answering, venueIsDeclared, Venue, type WitnessedOp } from "./venue.js";

export type { ServedState };

/**
 * How many witnessed indices this operator has been quiet. Measured from its
 * latest commitment, or from the venue's genesis where it has never published —
 * otherwise never publishing at all would be the way to escape the grade.
 */
export function quietFor(venue: Venue, operator: Uint8Array): bigint {
  return venue.witnessedIndex() - (venue.witnessedAtFor(operator) ?? 0n);
}

/** The operator in force at the venue's present index. */
function operatorNow(venue: Venue, backing: Backing): Uint8Array {
  return operatorAt(backing, venue, venue.witnessedIndex());
}

export { venueIsDeclared };

/**
 * §C2b's aggravated grade for this backing: its operator has published no
 * commitment for longer than the duration the backing declares. A backing whose
 * E declares no silence clause is never silent — snapshot redemption never opens
 * for it and its claims can go illiquid forever, which is a setting the backer
 * chose and the holder read before accepting.
 *
 * **False means this record does not show it, never that the operator is fine.**
 * A record from a venue the backing does not declare answers false however dark
 * the operator has gone, because a grade is read on the declared venue and this
 * is not it. Ask venueIsDeclared first to tell the two apart — as provesHolding
 * already asks callers to read its false as "this state does not prove it".
 *
 * **And there is one operator it does not reach, which the spec now says.** §C2b:
 * "A shared operator batches, and what a venue witnesses is a root, so whether a
 * commitment carries any particular backing is unreadable from it: the grade
 * fires on the operator publishing nothing, not on it covering nothing." So an
 * operator that drops THIS backing and commits the rest on time is not silent,
 * and this is faithful rather than blind. What reaches that operator is the
 * non-service grade, read against the last state that did carry the backing, and
 * the fault is isRewrittenHistory. See DECISIONS.md.
 */
export function isSilent(venue: Venue, backing: Backing): boolean {
  const clause = backing.evidence.silence;
  if (clause === undefined) return false;
  if (!venueIsDeclared(venue, backing)) return false;
  // The operator in force now, not the key E names: §C2's "a wallet verifies the
  // chain rather than the key it remembers". Accrual against a replaced
  // incumbent stops at the handover, because the successor's own first
  // commitment is what gave it force — so its quiet time starts there.
  return quietFor(venue, operatorNow(venue, backing)) > clause.noCommitmentDuration;
}

/**
 * Whether this operator is late against the schedule its backing declares (§C2:
 * "At the declared interval each publishes a small commitment").
 *
 * **A fact, not a grade.** §C2b declares two grades and this is neither: nothing
 * fires, nothing opens, and no remedy follows. It is what a payee reads to
 * decide whether to wait, because a payment is final when witnessed rather than
 * co-signed — so "is the next commitment merely due, or overdue" has to be
 * answerable, and §C2 makes the interval "a signed field rather than operational
 * discretion" for exactly that reason.
 *
 * Quiet for exactly the interval is on time; one index more is late. Counted
 * from the venue's genesis where the operator has never published, or never
 * publishing at all would be the way to look punctual forever.
 *
 * **False means this record does not show it**, on the same terms as isSilent: a
 * backing that declared no schedule cannot be late against one, and a record
 * from a venue it does not declare says nothing either way.
 */
export function isOverdue(venue: Venue, backing: Backing): boolean {
  const terms = backing.evidence.witnessing;
  if (terms === undefined) return false;
  if (!venueIsDeclared(venue, backing)) return false;
  return quietFor(venue, operatorNow(venue, backing)) > terms.interval;
}

/**
 * The requests this operator has left unserved, as §C2b counts them: "a signed
 * transfer request, published where demands are, left unserved past the declared
 * duration and counted only while still unserved."
 *
 * This is the grade **measured on service rather than publication**, and it is
 * the one that reaches the party the aggravated grade cannot: "A stalling
 * backer-run sequencer publishes on time, and the stall shows only as a spent
 * set that stops growing."
 *
 * Four things make a request count, and each is a sentence of the clause:
 *
 *   - **It is a transfer published at the venue.** §C3's demand shape without
 *     the backer.
 *   - **It is not in the committed log.** Served means served, and a request the
 *     operator took stops counting the moment it commits it.
 *   - **Its age is past the declared duration and inside the window W.** Below
 *     the duration it has not been left unserved yet; past the window it is no
 *     longer standing.
 *   - **The committed state could have served them.** "Faking a request means
 *     holding a real claim, so the count is checkable" - so they are put to the
 *     law against the state the operator actually committed, which is the test
 *     the challenge window needed when a request the snapshot could never have
 *     served counted as a spend.
 *
 * **Served as a sequence, not one at a time.** The paper's own case for m is one
 * holder: "one holder can split a holding into m claims and file as many
 * requests... no request is fake, though one holder can supply all m of them."
 * Under transparent those m requests occupy consecutive nonces, so tested
 * independently against the committed state every one after the first is refused
 * as ahead of the signer's next - and the clause could never fire for the
 * scenario it was written for. They are folded onto one working state in nonce
 * order instead, which is what "the operator could have served these" means: it
 * could have served them in the order they were signed.
 *
 * Chains across holders - Alice pays Bob, Bob spends onward, both unserved - are
 * out of scope here for the reason they are in the challenge window: "a spend by
 * the payee is a different signer's sequence".
 *
 * Distinct by the operation each request is, so republishing one is not two. Two
 * requests at one nonce are one holder equivocating, and the second finds its
 * nonce spent by the first, so the fold counts one without needing a rule.
 *
 * A verifier: the state comes from an operator with a motive and the venue from
 * anyone at all.
 */
export function unservedRequests(
  venue: Venue,
  backing: Backing,
  served: ServedState,
): WitnessedOp[] {
  return answering(() => {
    const terms = backing.evidence.nonService;
    if (terms === undefined) return [];
    if (!venueIsDeclared(venue, backing)) return [];
    const committed = committedLogFor(backing, venue, served);
    // A state that carries no log for this backing has nothing to fold the
    // requests onto, so the count is zero and honestly so. **What a holder must
    // know is which state to ask**: an operator that has dropped the backing is
    // graded against the last state that DID carry it, and that is the state
    // this grade — the only one that reaches a dropped backing at all — fires
    // against. See DECISIONS.md.
    if (committed === undefined || committed.kind === "dropped") return [];
    const state = replayLog(backing, committed.opLog);
    if (state === undefined) return [];

    const servedAlready = new Set(
      committed.opLog.map((entry) => bytesToHex(opHashOfEntry(backing.name, entry))),
    );
    const now = venue.witnessedIndex();
    // Applied to the sequence, which is not the same as counted toward the
    // grade: a request outside the band still advances the fold. `standing` is
    // the count.
    const applied = new Set<string>();
    const standing: WitnessedOp[] = [];
    // In nonce order, then witnessed order: a signer's own requests must be
    // folded in the order they were signed, and the witnessed index is the only
    // thing that separates two signed at one nonce (§C2, witnessing pins order).
    const candidates = venue
      .publishedOpsFor(backing.name)
      .filter((w) => w.op.kind === "transfer")
      .sort((a, b) =>
        a.op.nonce !== b.op.nonce
          ? a.op.nonce < b.op.nonce
            ? -1
            : 1
          : a.at < b.at
            ? -1
            : a.at > b.at
              ? 1
              : 0,
      );
    const working = copyState(state);
    for (const witnessed of candidates) {
      const hash = bytesToHex(opHashOfEntry(backing.name, witnessed.op));
      // Already in the committed log, so the state below already has it, and
      // applying it again would only meet its own spent nonce.
      if (servedAlready.has(hash) || applied.has(hash)) continue;
      try {
        applyEntry(working, backing, witnessed.op, undefined);
      } catch {
        continue;
      }
      applied.add(hash);
      // **Applied, then counted — not the other way round.** A request outside
      // the counting band is still one the operator was handed and did not
      // serve, so it advances the sequence even though it no longer stands: a
      // request too young to count today is what tomorrow's depends on, and one
      // that has aged out is what a still-standing later request sits behind.
      // Filtering before the fold would silently refuse every request behind
      // them, which is the same mistake as testing them one at a time.
      const age = now - witnessed.at;
      if (age <= terms.duration || age > terms.window) continue;
      standing.push(witnessed);
    }
    return standing;
  }, []);
}

/**
 * §C2b's non-service grade: at least *m* distinct requests standing unserved
 * within the window the backing declares.
 *
 * **False means this record does not show it**, on the same terms as isSilent: a
 * backing that conceded no non-service grade is never non-serving, and a state
 * that is not this backing's operator's says nothing either way.
 *
 * **What firing does here, and what it deliberately does not.** §C2b says it
 * outright now: "Firing makes the case for E's replacement rule, which stands
 * whether or not a grade has fired." So the grade unlocks nothing - it is a fact
 * a stranger checks, exactly like silence and dishonour. Slice 16 read it that
 * way while the word was "opens" and flagged the choice rather than taking it
 * silently; the paper settled it.
 *
 * The remedy "is inert wherever that rule names the backer, and absent wherever
 * E names no rule at all" - the second of those is the OPEN case pinned in
 * c2-dropped-backing. See DECISIONS.md.
 */
export function isNonServing(venue: Venue, backing: Backing, served: ServedState): boolean {
  const terms = backing.evidence.nonService;
  if (terms === undefined) return false;
  return unservedRequests(venue, backing, served).length >= terms.count;
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
export function stateIsAuthentic(backing: Backing, venue: Venue, served: ServedState): boolean {
  return replayServedState(backing, venue, served) !== undefined;
}

/**
 * The state a served snapshot replays to, or undefined if it is not this
 * backing's committed state or not a history that could have happened. The
 * shared body behind stateIsAuthentic and provesHolding, so a caller that needs
 * the numbers does not verify twice.
 */
export function replayServedState(
  backing: Backing,
  venue: Venue,
  served: ServedState,
): LedgerState | undefined {
  return answering(() => {
    // committedLogFor asks the three questions that always travel together: is
    // this signed by a key that served this backing, is this the state it
    // commits to, and does it carry this backing. What is left here is the law.
    // A state that carries no log for the backing replays to nothing: there is
    // no history of it here to be authentic or to hold a balance.
    const committed = committedLogFor(backing, venue, served);
    if (committed === undefined || committed.kind === "dropped") return undefined;
    return replayLog(backing, committed.opLog);
  }, undefined);
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
  return answering(() => {
    if (!isValidQuantity(quantity)) return false;
    const replay = replayLatestState(venue, backing, served);
    if (replay === undefined) return false;
    return (replay.balances.get(bytesToHex(holder)) ?? 0n) >= quantity;
  }, false);
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
  if (!venueIsDeclared(venue, backing)) return undefined;
  const latest = venue.latestFor(operatorNow(venue, backing));
  if (latest === undefined) return undefined;
  if (latest.sequence !== served.commitment.sequence) return undefined;
  if (compareBytes(latest.root, served.commitment.root) !== 0) return undefined;
  return replayServedState(backing, venue, served);
}

/**
 * This backing's outstanding as one of its operators committed it: issued minus
 * burned (invariant 10), out of a served state. Undefined where the state is not
 * one this backing's operator committed, or does not replay under the law.
 *
 * Any committed state, not only the latest — a caller comparing two of them
 * needs both, and which one is current is a question about the commitment rather
 * than about this arithmetic. The verifier had no way to read this number at all
 * before, which is what made a shortfall uncomputable.
 */
export function committedOutstanding(
  backing: Backing,
  venue: Venue,
  served: ServedState,
): bigint | undefined {
  const state = replayServedState(backing, venue, served);
  return state === undefined ? undefined : state.issued - state.burned;
}

/**
 * The outstanding that **stands** against a revoked backing: issued minus burned
 * as of the last commitment witnessed strictly before the revocation. Undefined
 * where the backing is not revoked here, or where `boundary` is not that
 * commitment's state.
 *
 * §C2b: "issuance witnessed before the revocation stands, anything witnessed
 * after is void." An issuance is witnessed when a commitment carrying it is
 * witnessed, and a log entry records no index of its own (slice 13), so the
 * boundary is read between committed states rather than per entry. Strictly
 * before: a commitment witnessed at the revocation's own index is not before it,
 * and the tie goes against the operator for the reason submitIssue's does.
 *
 * **What this is for, and what it is deliberately not.** Subtracting it from
 * committedOutstanding gives one number — how far the committed supply exceeds
 * what stands — and that number is a fact about the BACKING. It is never a
 * verdict about a holding. Which units descend from a void issuance is
 * provenance, which CLAUDE.md rules out rather than defers and which no blinded
 * construction could answer anyway; and allocation was settled in P before
 * anyone accepted, since invariant 19 forbids a payout reading holder identity
 * and §18 excludes "discretion after the fact".
 *
 * **Nothing is unwound, and that is not squeamishness.** Refusing a
 * post-boundary issuance in the replay would make replayLog return undefined, so
 * stateIsAuthentic and provesHolding would answer false for EVERY holder of the
 * backing, including ones whose units predate the theft entirely. Revocation
 * would go from capping a supply to destroying the backing's verifiability. It
 * would also allocate the loss by spend order, which is worse than any declared
 * shape, and it is a reversal in all but name (invariant 8).
 *
 * **This is the count invariant 19's payout reads**, and §C2b now says so: "A
 * payout reading this backing's own outstanding count (invariant 19) reads what
 * stands rather than what was committed, or a revoked thief dilutes every holder
 * by issuing on." Checkable from the published record, so it meets invariant
 * 19's "published" condition, and a thief cannot move it.
 */
export function standingOutstanding(
  backing: Backing,
  venue: Venue,
  boundary: ServedState,
): bigint | undefined {
  return answering(() => {
    const revoked = revokedAt(venue, backing);
    if (revoked === undefined) return undefined;
    const before = revoked - 1n;
    // Whoever was in force just before the boundary — a handover and a
    // revocation are independent axes, and this reads the same chain everything
    // else does rather than assuming the key E names.
    const last = venue.latestFor(operatorAt(backing, venue, before), before);
    if (last === undefined) return undefined;
    if (
      boundary.commitment.sequence !== last.sequence ||
      compareBytes(boundary.commitment.root, last.root) !== 0 ||
      compareBytes(boundary.commitment.operator, last.operator) !== 0
    ) {
      return undefined;
    }
    return committedOutstanding(backing, venue, boundary);
  }, undefined);
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
function publishedInGap(
  venue: Venue,
  backing: Backing,
  chain: readonly Succession[],
  at: bigint,
): boolean {
  const clause = backing.evidence.silence;
  if (clause === undefined) return false;
  // Judged against whoever was in force at the index the publication landed at,
  // which is the same rule the publication itself is judged by. The chain is
  // walked once by the caller: it is the same chain at every index, and walking
  // it costs a signature verification per published replacement.
  const last = venue.witnessedAtFor(operatorIn(chain, at), before(at)) ?? 0n;
  return at - last > clause.noCommitmentDuration;
}

/**
 * The operations a gap gave force to: its presentation legs, in the order the
 * venue witnessed them. This is what a returning sequencer adopts, and what the
 * redemption walk folds — exported so the two read one definition of what a
 * publication can do, rather than two that have to agree.
 */
export function gapLegsFor(venue: Venue, backing: Backing): WitnessedOp[] {
  if (!venueIsDeclared(venue, backing)) return [];
  const chain = successionOf(backing, venue);
  return venue
    .publishedOpsFor(backing.name)
    .filter((w) => isLeg(w.op) && publishedInGap(venue, backing, chain, w.at));
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
  const chain = successionOf(backing, venue);
  for (const witnessed of gapLegsFor(venue, backing)) {
    // "Redemption against the LAST witnessed snapshot": the snapshot in hand
    // must be the one that was last when this leg was published. Asked about the
    // present instead, an operator that would rather a redemption were
    // unresolvable could make it so by publishing one more commitment — and a
    // backer-run operator is exactly the party with that motive.
    if (!isLatestAt(venue, backing, chain, served, witnessed.at)) continue;
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
    .filter(
      (w) =>
        w.op.kind === "transfer" &&
        compareBytes(w.op.from, holder) === 0 &&
        // A request that pays the claimant moved nothing away from them, so it
        // is no evidence that anything was spent.
        //
        // **It is not a defence, and must not be read as one.** It was added
        // as one, against a claimant who pre-empts a genuine request by
        // publishing at the contested nonce first. That is a real attack and
        // this does not stop it: keys are free, so the claimant pays a key
        // generated for the purpose and this check — which asks only whether
        // the payee is the claimant's OWN key — sees an ordinary transfer.
        // Kept because it is a true statement about what evidence is, not
        // because it buys anything. See DECISIONS.md for what would.
        compareBytes(w.op.to, holder) !== 0,
    )
    .sort((a, b) => {
      if (a.op.nonce !== b.op.nonce) return a.op.nonce < b.op.nonce ? -1 : 1;
      return a.at < b.at ? -1 : a.at > b.at ? 1 : 0;
    });
}

/** Whether the served state was this operator's latest commitment before `at`. */
function isLatestAt(
  venue: Venue,
  backing: Backing,
  chain: readonly Succession[],
  served: ServedState,
  at: bigint,
): boolean {
  const latest = venue.latestFor(operatorIn(chain, at), before(at));
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
  return answering(() => {
    const clause = backing.evidence.silence;
    if (clause === undefined) return [];
    if (!venueIsDeclared(venue, backing)) return [];
    const state = replayServedState(backing, venue, served);
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
  }, []);
}
