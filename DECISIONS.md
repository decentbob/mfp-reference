# Decisions

Resolved questions about the spec and this implementation. Decisions here
can be reopened — with a good reason — but reopening one should be done
knowingly, with the earlier reasoning in view, not by forgetting it was ever
decided. One entry per decision, newest first.

Format:

```
## YYYY-MM-DD — short title
**Question:** what was ambiguous, contradictory, or wrong (quote the spec).
**Decision:** what was decided, and by whom.
**Spec change:** link to the issue/commit on the paper repo, or "none needed".
```

---

## 2026-08-19 - Design review: commit the log, and enforce presentability

**Question:** Bob asked for a review of the merged implementation against the
reference goal - maximally simple and general while enforcing what is necessary
- rather than a hunt for bugs. Two things came out of it.

**Decisions (Bob):**

- **The commitment commits the operation log, and nothing else.**
  `encodeSnapshot` wrote issued, burned, balances and the standing demands -
  sorting them, deduping them, checking conservation - and `stateIsAuthentic`
  then re-derived every one of them from the log and demanded equality. Three
  mechanisms for data one of them fixes.

  It was also the direct cause of three findings in slices 6 and 7, each of which
  was the same sentence - "field X is not tied to the log" - and each of which
  got its own patch. Deriving the fields instead does not check that class of lie;
  it makes it unsayable. Invariant 23 asks the commitment to commit to "the
  issuance log, the spent set, running totals and the standing demand record",
  and under transparent the log determines every one, so committing it commits
  them all.

  `BackingSnapshot` is now `{ name, opLog }`. Six rules left `commitment.ts` and
  every one was accounted for rather than dropped:

  | rule | where it went |
  | --- | --- |
  | amounts non-negative and bounded | the amounts are gone; log quantities are bounded by `validateQuantity` in the message encoders, which is the one place a quantity is written |
  | balances sum to issued − burned | structural: every operation the replay applies either conserves the total or moves issued/burned with it |
  | no duplicate holder in balances | balances are a Map built by the replay, one entry per holder by construction |
  | no duplicate demand in state | two demands by one holder need distinct nonces, which the per-signer nonce sequence already enforces |
  | accepted deadline within the demand's | **moved into `replayLog`** - and it was missed on the first pass; see below |
  | op-log position pinned to its index | kept, and now the only canonicality rule the encoder has |

  Invariant 10 stops being policed and becomes a property of the fold. Its test
  changed to match: the identity is checked over every prefix of a log carrying
  all seven operation kinds, rather than an encoder refusing a state that breaks
  it.

- **Invariant 13 is enforced where presentation happens, by refusing what cannot
  be completed.** `presentableFor` - "a holding is presentable at b for q iff it
  contains q units of b and q·cᵢ units of each (bᵢ, cᵢ) in R(b)" - was written in
  slice 2 and called by nothing but its own tests. `demand` checked only the
  backing's own balance and `release` moved only its own units, so reliance was
  inert everywhere.

  That is right for transfer, where invariant 17 keeps an unaccompanied claim
  inert rather than invalid. It is wrong for presentation, and it left the
  implementation running outside the condition that licensed its own design: the
  slice-4 decision quotes §C3's "R empty and the payout settling outside the
  claim layer", and nothing checked R empty.

  So a demand on a backing with reliance is refused, on both inputs - the ledger
  and the replay. Such a backing stays fully usable for issue, transfer and burn;
  only the presentation whose legs cannot move is declined. Implementing the legs
  is the other reading of §C3 ("the whole set and the paying leg inside one
  operator") and needs a decision about targets served by another operator, which
  is the multi-sequencer case.

**Found by the review of the change, and fixed:** deleting `writeDemand` dropped
the acceptance-deadline range rule that slice 6 added to close
dishonour-laundering, and it was not moved into `replayLog`, which now produces
the demand record. The hole reopened one layer down: the backer signs an
acceptance running to a million, the ledger refuses it, the operator serves it in
the log anyway - genuine signature, correct nonce, demand standing - and
`isDishonoured` reported false forever. Demonstrated, then closed with one line
beside the lifecycle checks.

**Deliberately not done:** the `replayLog` walk re-implements the ledger's
structural rules, which is a second implementation that must stay in step with
the first. The clean end state is a shared step function used incrementally by
the ledger and from scratch by the verifier, so there is one implementation of
the law's arithmetic. It is a refactor rather than a patch, and it is more
attractive now that the replay is the only definition of state.

**Also noted, not acted on:** `issuanceLog`/`IssuanceLogEntry` and `balancesOf`
are projections used by nothing but tests, and are deletable whenever they stop
earning their place.

**Spec change:** none needed.

## 2026-08-19 - Slice 7: committed state is self-authenticating

**Question:** slice 6 left one open and named it must-settle: nothing tied
committed balances to the committed operation log, so an operator could reassign
a holding and `provesHolding` would believe it. Three candidates were on the
table - fold the log into the balances, put the authorising signatures in the
log, or have a redemption claim carry the claimant's own receipt chain. Which,
and how far?

**Decisions (Bob), each taken against a demonstrated attack rather than an
argument:**

- **Folding alone does not work, and receipt chains reduce to signatures.**
  Requiring balances to equal the fold of the log was the obvious answer, and it
  fails: the operator appends the transfers it wants and the fold agrees with
  them, while earlier receipts still prove because their positions did not move.
  Demonstrated. Receipt chains reduce to the same thing, because a holder cannot
  prove the *absence* of a spend - the dispute only resolves when somebody
  exhibits a signed operation. So the signature is the load-bearing piece, and
  the fold is needed alongside it or the operator lies in the balances line while
  keeping the log honest.

- **Each logged operation carries the signature that authorised it, served
  rather than committed.** The entry's canonical message is already inside the
  root and only the true signer can produce a signature over it, so committing
  the signature would add 64 bytes per entry without adding a property. It is
  invariant 23's own arrangement: the commitment "does not contain any of them,
  and anything checked against them has to be served". Committed bytes are
  therefore unchanged by this slice.

- **The signer comes from the terms and from the log, never from a field beside
  the entry.** The obligor for an issuance and an acceptance; the entry's own key
  for a transfer, burn or demand; and for a release or withdrawal the holder of
  the demand it names - resolvable because **a demand's hash is exactly its
  operation hash**, both being taken over the same canonical message. Nothing an
  operator writes can nominate its own authority.

- **Committed balances are kept and checked rather than dropped.** Verifying a
  state recomputes the root, and that computation runs the check, so a verifier
  that has verified the state can then read a balance directly instead of
  folding again. Redundant, but checked, so it cannot lie.

**Two more holes found by reviewing the fix, each the same shape - the fix
bounded one input and left the adjacent one open:**

- **A signature authorised unboundedly many operations.** Signature validity was
  checked; single use was not. Alice signs one transfer of 30, the operator logs
  it three times, and 90 units move - every check passing. The nonce inside the
  signed message is what makes a signature single-use, so each signer is now held
  to the sequence the ledger holds them to. That also rejects a log with a gap,
  since an operation dropped from the middle leaves the next one at a nonce
  nobody reached.

- **A served log could describe a history the ledger itself refused.** Alice
  files a demand and withdraws it; she had also signed a release the ledger
  refused outright ("no such standing demand"), which a holder who signs a
  release and a withdrawal in a race produces. The operator appends the refused
  release and 40 units move. So the demand lifecycle is part of the walk: an
  acceptance, release or withdrawal requires a demand standing at that point, and
  the committed demand record must equal what the log leaves standing - the
  sibling gap, since the demands set was no more tied to the log than the
  balances were.

  Scoped to the demand lifecycle rather than a full re-implementation of the law
  in the verifier, because a second implementation that must stay in step with
  the first is the shape slice 5 removed when two encoders had to agree. The
  cleaner alternative - drive a real `TransparentLedger` and let the law replay
  itself - is blocked by two things committed state does not carry: the backer's
  signature over the backing, needed to register it, and the witnessed index each
  operation was accepted at. Recorded as the shape to reach for if this needs
  extending.

- **Correction to my own scoping.** I justified "lifecycle only" by saying
  balance rules were already covered, since a log implying a negative balance
  cannot be committed. Wrong for the **lock**: a demand commits the units it
  names, and a log that spends them leaves balances that are perfectly
  non-negative. Demonstrated - Alice at zero with a demand for 100 still
  standing, a demand no units back, which is exactly what a redemption leg reads.
  The replay now reads the same spendable figure the ledger does, held minus
  committed.

**Consequences.** `entriesAreAuthentic` and `foldBalances` both tracked
overlapping demand state and were replaced by one `replayLog`, which answers one
question - could this log have happened, and what state does it leave - rather
than two that had to agree. `stateIsAuthentic` composes it with the commitment
check, and `provesHolding` runs through that, so slice 8's payment path is built
on state that has been checked rather than merely verified.

**The boundary, deliberately not crossed: the law's time-dependent rules are not
replayed.** Whether an acceptance was still live when released against, whether a
demand's deadline had passed when answered - the log does not record the
witnessed index each operation was accepted at, so they cannot be checked from
it. Closing that means recording an index per entry (operator-asserted, and so
only as good as the operator unless it moves into the receipt, which is
operator-signed). Slice 8 must decide whether its payment path needs it.

**Cost, accepted:** `stateIsAuthentic` verifies every signature in the log, so
checking a long-lived backing is linear in its whole history and re-checking on
every commitment is quadratic. Inherent to "somebody has to serve the trail" and
fine for a reference implementation; an incremental form would verify only from
the last checked position.

**Spec change:** none needed.

## 2026-08-19 - Slice 6: silence is a public fact, and the unspentness proof

**Question:** §C2b's snapshot redemption opens on two conditions - the operator
has gone dark past a declared duration, and the holder can prove the claim
unspent as of the last witnessed snapshot. What do those mean under transparent,
and where do the terms live?

**Decisions (Bob):**

- **Scope: the facts, not the payment path.** The claim/acceptance/release legs,
  the challenge window and a returning sequencer adopting what was witnessed
  during the gap are slice 7. Splitting was a mid-slice call once the payment
  path turned out to be comparable in size to slices 4 and 5 together. The facts
  stand on their own: both are checkable by a stranger against the published
  record, which is what makes the grade something a backer concedes rather than
  argues.

- **The silence terms live in E, under a new evidence tag 0x02.** Tag 0x01 stays
  byte-identical and declares no clause, so the slice-1 golden vector is untouched
  and a backing whose claims can go illiquid forever remains representable - a
  setting the backer chose and the holder read before accepting, not an oversight.
  A new tag rather than a version bump: the encoding was built for this ("tags not
  listed are future slices"), and bumping the version would change the name of
  every existing backing, breaking "same fields, same bytes, forever".

  **The tag carries only what this slice enforces**: the no-commitment duration
  and the challenge window. Not the non-service duration, the m-within-W
  aggregate, or the replacement rule. A backing that *declared* an aggregate no
  code checks would be worse than one that declared nothing, because a holder
  reading the terms would believe it was enforced. Tag 0x03 later is cheap.

- **No calibration is policed.** The paper is explicit that the numbers are the
  backer's to choose and the holder's to read - "set m low and one scripted wallet
  replaces an operator; set it high and the clause never fires". So a zero
  duration is representable, and means what it says.

- **Silence is measured on the venue's clock, from the operator's last
  commitment, and from the venue's genesis where it has never published.** The
  last part matters: measured only from an existing commitment, never publishing
  at all would be the way to escape the grade. The fact is the operator's; the
  threshold is each backing's own declared term, so two backings can grade one
  silent operator differently, which is the arrangement §C2b describes.

- **"Last witnessed snapshot" is load-bearing, and so is "this backing's
  operator".** `provesHolding` refuses a commitment that is not the venue's
  latest for the operator E names. Without the first, a holder who has since
  spent the units still proves the state that shows them; without the second,
  anyone can sign a valid commitment over any state they like. An adversarial
  script confirms both, plus a self-signed forged state, a re-signed honest root,
  and inflated balances - all refused.

- **Invariant 23's non-membership requirement is satisfied by serving
  everything.** Slice 3 recorded that per-element Merkle proofs were "deferred
  with the recovery path", i.e. here. Confirmed as wrong and re-deferred: under
  transparent the whole served state is rehashed against the root, which is
  already how a receipt proves, so serving everything IS the non-membership
  proof. The machinery is what a construction needs when it *cannot* serve
  everything, which is the shielded ones. §C2b names the transparent form
  directly: "a signed spend record published at the venue, checked against the
  last committed balance state, stands in for the nullifier."

**Found by the review of this slice, and fixed here:** invariant 10 binds "at
every published moment", and a committed state is a published moment - but
`encodeSnapshot` never checked it. Demonstrated: a backer-run operator issues 100
to Alice, commits a state with the balances erased while `issued` stays 100, and
goes dark. The state verified, silence fired, and nobody could prove a holding,
so redemption never opened for anyone - while Alice's receipt still proved the
issuance was in that same committed log. She could prove the operator was lying
and still not redeem. The encoder now refuses the state. Enforced there rather
than only in the ledger for the standing reason: served state may come from a
hostile operator, so the encoder decides which states are canonical. Four
synthetic fixtures asserted on states no ledger could produce and were repaired;
two of them had been passing for the wrong reason.

**Raised by the same review, and settled in slice 7 (see the entry above):
nothing tied committed balances to the committed operation log.** Conservation closes
deletion and inflation, but not reassignment: an operator can serve a state
identical to the honest one except that Alice's units are listed against Mallory,
the totals still reconcile, and `provesHolding` returns true for Mallory.
Demonstrated. Slice 2 recorded "balances remain primary state, not a fold over
the log", which was a modelling convenience then and is a safety decision now
that a predicate reads those balances.

It converges with the gap recorded after slice 5 - the operation log commits
operations without the signatures that authorised them - because folding the log
does not help while log entries are themselves unsigned assertions. **Until it is
settled, `provesHolding` must not be read as authorising payment**; it is a
precondition, and nothing in this slice pays anything. The candidates are: make
committed balances a fold over the committed log; put the authorising signatures
in the log; or have slice 7's legs require the claimant's own receipt chain
rather than the balance line.

**Spec change:** none needed.

## 2026-08-19 - The witnessed clock is the venue's, and one class of aliasing bug

**Question:** slice 5 decided "the operator needs exactly one clock: its own
latest published commitment index". Starting §C2b revealed that this hands a
stalling sequencer every deadline in its book, and that "no commitment past a
second declared duration" cannot be measured in the silent party's own
publications. Reopened.

**Decisions (Bob):**

- **Two indices, named apart.** A commitment's `sequence` is the operator's own
  count of its commitments, and equivocation is two roots signed at one sequence.
  The venue's witnessed index is the clock every deadline is read against, and it
  advances via `Venue.advance()` - the stand-in for block production, which no
  participant controls. §C2 is explicit that these are different things: "A venue
  is named together with its finality rule, the depth or gadget under which an
  index counts as witnessed there." Slice 5 read them as one, and the name
  `Commitment.index` is what made that easy, so it is now `sequence`.

  Demonstrated before the fix: the backer answers Alice's demand legally, then
  stops publishing. Forever after, withdrawal is refused ("a live acceptance
  stands"), her 100 units are unspendable, and the record says the backer is not
  in dishonour. No refusal and no signature - just silence. §C2 names the cost
  exactly: "a stall is deniable where a dishonour is recorded."

- **Slice 5's "publish a commitment first" refusal is deleted.** It was a symptom
  of the conflation rather than a rule. Time exists whether or not this operator
  has committed, so serving before its first commitment is ordinary - the
  interval simply has not elapsed.

- **The venue records when, not only what.** `publish` stores the witnessed index
  alongside each commitment and `witnessedAtFor` exposes it. "Witnessed at index
  i" is the spec's own notion (§C2b: a revocation is "effective for each backing
  at its witnessed index on that backing's declared venue"), the height is the
  venue's word rather than the operator's, and subtracted from `witnessedIndex()`
  it is how long an operator has been quiet - the input the silence clause is
  measured on. Without it, decoupling the clock would have removed the one
  accidental way to date a commitment: while the commitment index *was* the
  clock, a stale commitment was visible as an old index.

- **Copy on the way in, copy on the way out, everywhere it was not.** Reviewing
  the fix found four instances of one class, each proved with a runnable exploit
  and each a plain violation of a rule CLAUDE.md states without exception ("no
  accessor may hand out a write path into state"):

  1. `Venue.publish` stored the caller's `Commitment` and `latestFor` handed it
     back, so an operator could mutate the root of the object it published and
     retroactively deny its own commitment - the one thing the class exists to
     prevent.
  2. `Sequencer.submit` stored the `Receipt` it built and returned that object to
     the first caller and every replayer, so whoever held a receipt decided what
     every later replay was answered with. Invariant 26's "identical prior
     response" was not the operator's to control.
  3. `Sequencer.operator` was a public `Uint8Array` field. Mutating it broke
     routing and commit - loudly, and only for the operator itself.
  4. The constructor retained the caller's *secret* key array. Mutating it split
     signing from routing silently: the sequencer kept serving as the operator E
     names while co-signing as another, so its declared identity read as having
     gone quiet - the condition §C2b grades as aggravated.

  `copyCommitment` and `copyReceipt` live beside the types they copy, so a new
  field is caught at the one place that snapshots it. `signCommitment`
  deliberately does not copy its root, and says why: the sequencer retains
  receipts, while a commitment is retained only by the venue, which copies on the
  way in.

**Raised, to be settled with the recovery slice:** slice 3 recorded that
per-element Merkle membership / non-membership proofs are "deferred with the
recovery path", i.e. now. That looks wrong. Invariant 23 requires them because
"§C2b's recovery path proves a claim *not* spent as of the last commitment, which
a bare Merkle root cannot do" - but under transparent the whole state is served
and rehashed, which is already how receipts prove, so serving everything *is* the
non-membership proof. The machinery is what you need when you cannot serve
everything, which is the shielded constructions. To be confirmed when the
recovery path lands. **Confirmed in slice 6; see the entry above.**

**Next slice, agreed:** §C2b silence and snapshot redemption. E declares the
no-commitment duration and the challenge window under a **new evidence tag
0x02**, so tag 0x01 stays decodable and simply declares no silence clause - a
coherent setting where claims can go illiquid forever, the backer's choice, and
the slice-1 golden vectors and frozen v1 name format are untouched. Deferred with
reasons: non-service counting (its only remedy is replacement), successor
sequencers, and revocation on backer key theft - three separate axes.

**Spec change:** none needed.

## 2026-08-19 - Slice 5: presentation through the sequencer, and two holes it closed

**Question:** slice 4 left demand/accept/release/withdraw on
`TransparentLedger` only, with the reason recorded as a design one: a receipt
binds an operation to its position in the operation log, and those three move no
value, so they had no position. The intended answer was to extend the operation
log with presentation kinds so receipts and invariant-26 idempotency work
uniformly. What does that change touch, and what does having a real witnessed
clock make enforceable that slice 4 could not?

**Decisions (Bob):**

- **A logged entry's canonical bytes ARE the bytes the party signed.** One
  function, `opMessageOfEntry`, and everything downstream reads it: the receipt's
  op hash is its SHA-256, and the commitment commits it length-prefixed. Slice 3
  had two encoders that had to agree - `writeOpEntry` in commitment.ts described
  an entry field by field, `opHashOfEntry` in receipt.ts rebuilt the signed
  message - and "the committed entry reconstructs to the receipt's op hash" was
  true only as long as both stayed in step. It is now true by construction. The
  per-kind switch and the kind tag are gone from commitment.ts: every message
  opens with its own domain tag, and contexts.ts already asserts those are
  prefix-free, so a second tag would be a second mechanism for one property.
  Adding four operation kinds made the commitment encoder smaller.

- **Presentation entries carry their signed fields and nothing else.** A release
  names the demand it settles, not the balances it moves: the quantity and the
  holder are in that demand's own entry, earlier in the same append-only log,
  and the destination is the obligor in the backing's terms. So neither is the
  operator's to assert - an entry that declared `to` and `quantity` would be an
  operator's word about where money went, standing beside the holder's signature
  that says only "settle demand X".

- **The venue moves into the Sequencer's constructor.** Presentation turns on
  witnessed indices, and invariant 21 forbids a time a party asserts alone, so
  the operator needs exactly one clock: its own latest published commitment
  index. A venue passed per call could give one predicate two answers. `commit()`
  loses its parameter. An operator that has published nothing has no witnessed
  time and declines a time-dependent operation rather than substituting a number
  of its own - the first commitment is what starts the clock.

- **A replay never consults the clock.** The witnessed index is read inside the
  apply thunk, so a resubmitted operation is answered from the receipt store
  before any index is looked up. An acceptance replayed after its own deadline
  has passed still returns the prior receipt: invariant 26's "a crash loses
  nothing" would be false if repeating a request could be re-judged against a
  clock that had moved.

- **Invariant 24 is now fully enforced, closing the half slice 4 deferred.** A
  demand's instant must be no later than the latest witnessed index. Enforced at
  the demand alone: the acceptance must repeat that exact value, so the same
  guarantee reaches the backer's signature without a second check against a
  second clock.

**Two exploits, both demonstrated against the merged slice-4 code before the
fix, both approved for fixing here:**

- **A backer laundered its own dishonour with one free signature.**
  `isDishonoured` read only `acceptedDeadline === undefined`, so *any*
  acceptance - including one whose own deadline was already past, which moves
  nothing and can never be released against - made the demand permanently
  un-dishonourable and burned the only acceptance slot. C3 says "claims still
  live past the deadline are the backer's visible failure"; the failure was
  invisible. Fix: dishonour reads "no *live* acceptance", sharing one
  `acceptanceIsLive` predicate with release and withdrawal. An acceptance that
  arrives and expires unpaid is the same branch as one that never arrived. The
  cost is that a holder who declines to release (C3 permits it) reads as
  dishonoured until they withdraw - which is exactly the exit open to them, and
  the honest thing to do if the terms have moved.

- **The acceptance's deadline was the backer's unbounded choice.** Slice 4 fixed
  "indefinite" to "bounded by the acceptance's deadline" but left the backer
  picking that bound: answering on the last legal index with a deadline of a
  million froze the holder's claims for a million indices, unpaid. Fix: one range
  check, `atWitnessedIndex <= acceptance.deadline <= demand.deadline`. C3: "The
  window is the holder's. The deadline is the holder's own lock-up, so the party
  bearing the cost sets the term. A backer would be setting the standard by
  which its own failure is measured." The check subsumes slice 4's separate
  "a demand past its own deadline cannot be answered", because past that deadline
  no legal acceptance deadline is left.

  Two consequences. The backer **may** answer again once its own acceptance has
  expired, since re-answering is now capped by the demand's deadline and so
  cannot extend the lock-up past the holder's term - without this, a
  born-expired acceptance would grief every demand into a refile. And past the
  holder's own deadline no acceptance can be live, so **withdrawal is
  unconditionally open and dishonour unconditionally reported**. Release and
  withdrawal are complements on one predicate: exactly one exit is open at every
  index, which is now a test rather than an argument.

**Found by the review of this slice, and fixed here:** the ledger enforced
`acceptedDeadline <= demand.deadline`, but the commitment encoder did not, so an
operator could serve a demand record the ledger could never have produced. A
working exploit rooted a snapshot with `acceptedDeadline: 1_000_000` on a demand
whose deadline was 10: it verified against its own commitment, the demand hash
still recomputed from the committed fields, and `isDishonoured` returned false
forever - the laundering hole again, reached through served state instead of
through a signature, by the party §C3 names as the likely operator ("the
backing's own sequencer is frequently the backer"). `writeDemand` now rejects it.

This is not a second mechanism for one rule but the same rule applied to the
other input: served state may come from a hostile operator rather than from this
ledger, so the encoder is what decides which states are canonical - the same
reason the op-log position is pinned to its index and a duplicate holder in
balances is refused. One bound is enough: past the demand's own deadline no
in-range answer can still be live, so every state an operator *can* serve reports
the dishonour. Demonstrated by re-running the exploit across every servable
value.

**Known and not closed here: the operation log commits operations without the
signatures that authorised them.** Committed state proves the operator accepted
an operation, never that the named party authorised it, so an operator can
fabricate an acceptance, release or withdrawal entry outright. With the bound
above this can no longer hide a dishonour, and it is not new - slice 3 committed
issue/transfer/burn the same way - but presentation makes it worth stating,
because an acceptance is evidence *about the backer*. What remains is what
§C2b's recovery path answers: a published spend record checked against the last
committed balance state, and non-membership proofs over the spent set. A later
slice should not assume the committed trail is self-authenticating.

**Deferred, unchanged from slice 4:** prepare-decide-commit and the
cross-operator decision venue (needs multi-sequencer); chain-asset legs and
escrow; a payout paying in claims, settling as a swap inside the settlement
(needs C1's n-party swap); dated backings, the zero-date and the payout floating
after the deadline (needs the payout language); non-service objects and the
silence clause (C2b).

**Deliberately still not enforced:** a demand whose deadline precedes its own
instant. It is incoherent but harms only the holder - `accept` refuses it and
withdrawal is open - and C3 declines to police the window at all ("Nothing needs
adjudicating: a five-minute window is worthless evidence, thirty unanswered days
damning"). A minimum answer window belongs with the trigger, in Extensions,
which declares one as a floor rather than the core declaring a ceiling.

**Spec change:** none needed. Both fixes are readings of C3 forced by working
exploits, not departures from it; the paper's sentence "dishonour is the branch
where the acceptance never arrives" is literally satisfiable by an acceptance
that pays nothing, and the fix reads "arrives" as "stands".

## 2026-08-19 - Slice 4 scoping: presentation and dishonour, single-phase

**Question:** C3 gives two protocols - demand-accept-release for consent
between the parties, and prepare-decide-commit for atomicity across
sequencers - and says "one with only the first leaves the hole open". Which
applies here, and what is in scope?

**Decisions (Bob):**

- **Single-phase, on the spec's own terms.** C3: single-phase suffices
  "wherever every lock in the set can be taken in one atomically signed
  decision: R empty and the payout settling outside the claim layer, or the
  whole set and the paying leg inside one operator". One sequencer, with the
  backer paying in something the claim layer does not carry, is exactly that
  case. Prepare-decide-commit is not deferred for convenience; it is the
  answer to a problem this configuration does not have. It arrives with
  multi-sequencer transfers.

- **Settlement is a transfer to the backer, not a burn.** Invariant 10:
  presentation destroys nothing - presenting hands claims to the backer, who
  is then simply their holder. Only an explicit burn lowers outstanding.

- **A demand commits, it does not surrender.** The named quantity can no
  longer be transferred or burned, but it stays the holder's until settlement
  or withdrawal. The lock is derived by summing open demands rather than
  tracked in a parallel counter, so there is one source of truth and nothing
  that can desync (design rule: one mechanism per property).

- **An unanswered demand stands past its deadline.** C3 is explicit: the
  deadline "marks when non-payment becomes a public fact, and it is not the
  end of the commitment". Only withdrawal or settlement ends it, and
  withdrawal is unilateral and holder-signed - the protection against a backer
  that stalls, which it cannot wait out. An accepted demand cannot be
  withdrawn while the acceptance is live: the holder has an answer to release
  against, or may wait for it to expire and withdraw then.

- **Dishonour is a pure predicate, not a stored state.** `isDishonoured(record,
  atWitnessedIndex)` - no acceptance, and past the deadline. C3: "Dishonour is
  then not a separate mechanism. It is the branch where the acceptance never
  arrives." Instants and deadlines are witnessed indices supplied by the
  caller, never wall-clock time (invariant 21).

- **Presentation is a claim-layer operation this slice.** The four operations
  live on TransparentLedger, and the standing demand record travels in the
  snapshot so a commitment commits to it (invariant 23). They are NOT yet
  reachable through Sequencer. The reason is a design one rather than a scope
  one: a receipt binds an operation to its position in the operation log, and
  demand/acceptance/withdrawal move no value, so they have no position. Giving
  them receipts and invariant-26 idempotency means extending the operation log
  with presentation kinds - the unified answer, which should be done as its
  own considered pass rather than bolted on as a half-idempotent wrapper.
  **Done in slice 5; see the entry above.**

- **Witnessed indices are parameters, not signed fields.** Operations whose
  outcome depends on time (accept, release, withdraw) take the current
  witnessed index as an argument supplied by whoever witnesses. Invariant 21
  forbids a time the holder asserts alone, so the index is deliberately NOT
  part of the signed message. Until presentation is sequencer-mediated the
  caller supplies it; the sequencer will supply it authoritatively.

- **The acceptance deadline is enforced, or an acceptance is a trap.** An
  acceptance is free to sign and moves no value. A first cut let it lock the
  claims indefinitely: the backer could accept, never pay, and the holder could
  neither spend (locked), nor withdraw (accepted), nor do anything but release
  and hand the units over for nothing. One free signature sterilised the
  holding permanently - the exact inversion of C3's "an acceptance carries its
  own deadline, or the backer holds a free option". So: a live acceptance holds
  the claims, and past its deadline the holder may withdraw again while
  settlement is refused. Exactly one exit is open at any index.

- **A backer cannot answer a demand it has already dishonoured.** Past the
  demand's deadline the holder has earned the right to walk away; allowing a
  late acceptance would let the backer convert its own failure into a lock.

- **The commitment commits the demand's fields, not its hash.** A self-declared
  hash commits nothing - an operator could publish a genuine hash beside a
  false quantity and the state would still verify. The record carries the
  holder's nonce so a verifier can recompute the hash from the committed
  fields, and demands are ordered and deduped by (holder, nonce), both of which
  are committed, rather than by the hash.

- **Invariant 24 is only half-enforced, deliberately.** The instant is named
  in the demand and agreed by the acceptance - two signatures over one value,
  which is the part that matters for consent and is enforced. The rest of the
  invariant ("no later than the latest witnessed index at signing") is NOT
  enforced: the ledger has no clock, and witnessed indices come from the
  operator's commitments at the venue. Enforcing it belongs with
  sequencer-mediated presentation, where the current witnessed index is known.
  Until then a caller can name a future instant, and a verifier reading the
  committed record can check it themselves.

**Deferred with reasons:** prepare-decide-commit and the cross-operator
decision venue (needs multi-sequencer); chain-asset legs and escrow (needs a
real venue); a payout paying in claims, which settles as a swap inside the
settlement (needs C1's n-party swap); dated backings, the zero-date and the
payout floating after the deadline (needs the payout language); non-service
objects and the silence clause (C2b).

**Spec change:** none needed.

## 2026-08-19 — One framing rule, and the design rules it belongs to

**Question:** A whole-codebase review found that the commitment root was **not
injective**: `encodeSnapshot` wrote holder keys and backing names with `raw()`,
and adjacent unframed fields are ambiguous — a 31-byte and a 33-byte key
concatenate exactly like two 32-byte keys. Two different served states hashed
to one root, so an operator could equivocate with a single signature and no
provable fault, defeating invariant 22 precisely where the code claimed to
enforce it. Demonstrated with a working collision.

The same review found the codebase had no single rule for framing at all: some
sites length-prefixed, some wrote raw, some length-checked first. That
inconsistency was also the root of several accreted layers — encoders threw, so
`receiptProvenBy` needed a try/catch, so `Sequencer.submit` needed another one
translating `EncodingError` into `SequencerError`.

**Decision (Bob):** state the rule once and enforce it in one place.
`ByteWriter.fixed` / `ByteWriter.key32` assert width at the single point that
writes a fixed-width field; everything variable-length is length-prefixed.
Nothing is ever written raw. Honest output is byte-identical, so the slice-1
golden vectors are untouched — the change only rejects inputs that were never
representable.

The rule is written into CLAUDE.md alongside six others (one mechanism per
property; validate once at the owning boundary; copy in and copy out; verifiers
never throw; an error names the boundary that refused; domain tags in one
file). These are binding on future slices: a fix that adds a layer is a signal
that the layer below is in the wrong place.

**Consequences applied in the same pass:**

- `verifySignatureStrict` length-checks the public key. noble checks it outside
  its own try/catch, so an unchecked key made every verifier crash on hostile
  input. Length only — the small-order rejection is already inside the strict
  verify path, and repeating it cost a second point decompression per
  verification.
- `receiptProvenBy`, `verifyReceipt`, `verifyCommitment` and the new
  `stateProvesCommitment` return `false` on any malformed input.
- The UTF-8 decoder sets `ignoreBOM: true`. It was stripping a leading BOM, so
  `encode → decode` was not the identity and one backing could have two names.
- `Venue` is per operator (`latestFor`, `nextIndexFor`); a stranger's
  commitments can no longer be mistaken for the operator being checked, and the
  commitment index is derived from the record rather than sequencer memory, so
  a failed publish cannot make an honest operator sign two roots at one index.
- The backing name is a stored field computed once in `makeBacking`, replacing
  a `WeakMap` memo plus a bare warm-up call. `nameHex` is stored beside it, so
  the ledger and sequencer key registries on an immutable string.
- `NonceError extends LedgerError` lets the ledger say "this nonce is not your
  next" in its own voice, so the sequencer no longer pre-checks the nonce to
  relabel the error. A malformed operation now surfaces as `EncodingError`
  rather than being translated — it is one of the five named boundaries.
- `quantity.ts` folded into `bytes.ts` (quantity bounds are byte-encoding
  policy); domain tags moved to `contexts.ts`; the sequencer's duplicate
  registry of backings deleted in favour of the ledger's.

**Spec change:** none needed.

## 2026-08-18 — Slice 3 scoping: the transparent sequencer

**Question:** §C2 (sequencing) is large and mostly concerns the shielded and
Chaumian settings, dated instruments, revocation, and recovery. What is the
coherent transparent-only core, and how are the pieces the spec assumes
(a witnessing venue, the operator key in E) modelled?

**Decisions (Bob):**

- **Scope: the coherent core.** Witnessed indices, operator co-signed
  receipts, idempotent replay (inv 26), interval commitments over state
  (inv 22/23, transparent subset), and equivocation detection. Deferred to
  later slices: the recovery path — snapshot redemption and non-membership
  proofs (§C2b) — silence and non-service grades, key revocation, successor
  sequencers, dated instruments and standing lock requests, multi-sequencer
  transfers, and presentation/dishonour (§C3).

- **The venue is an in-memory append-only log with immediate finality.** The
  spec publishes commitments to "a widely-witnessed venue, typically a public
  chain", named with a finality rule. A reference implementation has no chain;
  `Venue` is the honest stand-in, with a seam where a real venue and its
  depth/gadget finality plug in later.

- **The commitment is over the whole served state.** Invariant 23's objects,
  transparent subset: per backing, its name, issued/burned totals, current
  balances, and the full operation log. Verifying a state against a commitment
  means being given that state and recomputing the root — the spec's
  availability point ("somebody has to serve" the trail). Per-element
  membership / non-membership proofs (the Merkle machinery) are deferred with
  the recovery path.

- **Idempotency is keyed by the operation hash.** A resubmission of the exact
  signed operation returns the identical prior receipt (inv 26). A different
  operation at an already-spent nonce is declined by the ledger's nonce
  rejection — the sequencer "refuses a second spend by declining to sign".

- **Operator-key validity is enforced at the sequencer boundary**, revisiting
  the slice-1 note that E's operator "carries no verification weight in the
  transparent core yet". `makeBacking` still validates the operator by length
  only (so the slice-1 canonical name format is untouched), but a `Sequencer`
  serves a backing only if E names a valid, non-small-order point equal to its
  own key. A backing naming a bogus operator is simply unsequenceable — the
  backer's setting, self-consistently.

**Spec change:** none needed — all are implementation stances within what the
paper leaves open for the transparent setting.

---

## 2026-08-18 — Transparent-slice scoping: nonces, replay, the operation log, and inv 7/26

**Question:** Slice 2 (the transparent claim layer) had to take several
positions the paper leaves to the sequencing and blinding slices, and a review
flagged three of them as deviating from CLAUDE.md's wording without a record.

**Decisions (Bob):**

- **Replay is a rejection, not idempotence (inv 26).** The ledger rejects a
  replayed message via a per-(signer, backing) nonce. Invariant 26's
  "identical prior response" needs the sequencer's request/response store and
  arrives with slice 3. Until then, replay is an error. Nonces are keyed per
  (signer, backing) — never a single global counter — so a stuck message on
  one backing cannot block the signer on another.

- **Inv 7 reads as issuance vs. movement here.** The transparent construction
  has issuance (backer-signed, raises outstanding) and movement
  (transfer/burn, holder-signed). Reissuance proper — the count-preserving
  denomination swap that needs no backer signature — is a blinding-era
  construction and is neither implemented nor tested in this slice.

- **The operation log records all three op kinds** (issue, transfer, burn),
  so the record is honest about what happened. But balances remain primary
  state, not a fold over the log, and there are no commitments over ledger
  state yet. Both — replayable state and commitments — arrive with the
  sequencer (slice 3). `position` is a per-backing append index, a stand-in
  for witnessed interval time.

**Spec change:** none needed — all three are implementation stances within
what the paper leaves open for the transparent setting. CLAUDE.md's inv 7 and
inv 26 bullets now point here.

## 2026-08-18 — A validated backing is frozen; raw key-byte mutation is unsupported

**Question:** `makeBacking` returns a branded, validated backing, but a review
showed its byte arrays stay mutable, so a caller could mutate a registered
backing and either brick its ledger state or (via `reliance.push`) forge a
signed name for invalid terms.

**Decision (Bob):** `makeBacking` freezes the backing object, its `reliance`
array, and each reliance entry, so structural mutation (`push`, property
reassignment) throws. `backingName` is memoized per object in a `WeakMap`, so
a backing's identity is fixed at construction and survives any later byte
mutation — a mutated backing still resolves to the state it registered.
Freezing a `Uint8Array`'s contents is not possible in JS, so mutating the raw
key bytes of a backing is unsupported behaviour, not a guarded error; every
trust boundary already copies bytes in, so this only affects a caller
mutating its own object.

**Spec change:** none needed.

## 2026-08-18 — Obligor keys are validated as non-small-order points, and verification is strict (non-ZIP215)

**Question:** `verifyBackingSignature` used noble's default `zip215: true`,
which skips the small-order-point check, and the encoder validated the
obligor key only by length. A review showed (and a runtime script confirmed)
that a backing whose obligor is the Ed25519 identity point accepts a
trivially forged signature over any name — invariant 2 is defeated by a key
nobody controls.

**Decision (Bob):** two independent guards. (1) `makeBacking` rejects an
obligor key that is not a valid, non-small-order Ed25519 point, at
construction and on decode. (2) `verifyBackingSignature` passes
`{ zip215: false }` for RFC 8032-style strict verification, which also
rejects non-canonical `R`/`S` encodings — relevant later for signature-keyed
idempotency (inv 26). The operator key in `E` is validated by length only for
now; it carries no verification weight in the transparent core yet.

**Spec change:** none needed — the paper does not mandate a verification
profile; this is an implementation obligation the paper leaves open. Recorded
here because it hardens invariant 2.

## 2026-08-18 — Signatures are over a domain-separated message, not the bare name

**Question:** CLAUDE.md states invariant 2 as "a valid signature by K over
its own name". The code actually signs `"mfp/backing-signature/v1" || name`.
A review flagged this as undocumented drift from the stated rule.

**Decision (Bob):** keep the domain separation — signing a bare 32-byte hash
invites cross-protocol signature reuse once other signature types exist
(swap authorization, issuance, holder release in invariants 26–27). The
context string is the pre-image's domain tag. CLAUDE.md's wording is
reconciled to say "over its own name, under a fixed domain-separation tag".
The name already commits to the format version (the version byte is inside
the hashed encoding), so the two do not drift; the context's own `v1` moves
only if the signing scheme itself changes.

**Spec change:** none needed.
