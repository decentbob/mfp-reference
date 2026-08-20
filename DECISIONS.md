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

## 2026-08-20 - Slice 12: E's clauses are a list, not a tag per combination

**Question:** the replacement rule is E's third optional block. Slice 10 spent
four tags on two blocks by enumerating combinations, so a third needs four more,
and the paper's E has several after it - the non-service aggregate (m, W), the
refusal aggregate (m', W'), the construction. Enumeration doubles with each
block and was already doomed; it had simply not hurt yet. Doing the replacement
rule first would mean writing four tags and then deprecating them.

**Decisions (Bob):** the encoding first, so the replacement rule lands as one
clause. E declares a canonical **list** of clauses - sorted strictly ascending by
clause tag, so duplicates are unrepresentable, which is the rule the reliance
list already follows for the same reason.

- **A clause payload is not length-prefixed, deliberately.** A reader that could
  skip a clause it did not understand would report terms it cannot check, which
  is worse than declaring nothing - the rule tag 0x02 was created under. So an
  unknown clause tag is refused exactly as an unknown evidence tag is, and the
  encoding gains no field that would make skipping possible.

- **The canonicality rule.** Two spellings of one backing would stop the name
  being a function of the terms, so an empty clause list is refused: that set is
  tag 0x01's, and tag 0x01 is what it must use.

**Changed from the plan, and it is the reason it changed.** The plan kept tags
0x01-0x04 frozen beside the new list. That does not work: with the older tags
still canonical for their own clause sets, and only two clauses existing, every
set expressible today already has a shorter tag - so the list would be
**unreachable**, its encoder half dead code, and only its refusals testable.
Building a mechanism nothing can emit is what this codebase keeps deleting.

Keeping them as decode-only legacy is worse, and not merely untidy: it breaks
`decodeBacking`'s own stated contract, that "decode(bytes) succeeding proves
bytes is THE encoding of the result". An encoder that never emits tag 0x02 makes
`encode(decode(bytes))` differ from `bytes`.

So **tags 0x02, 0x03 and 0x04 are retired**, and the sets they spelled are
written as clause lists. Their numbers are not recycled - an old decoder reading
new bytes as something else is exactly what tag numbers exist to prevent - which
is why the list is 0x05. Nothing outside this repository's own fixtures held a
name under those tags, since they were minted in slices 6 and 10. **Tag 0x01 is
byte-identical and the slice-1 golden vector is untouched**, which is the promise
those slices actually made.

**Found reviewing the implementation:** the encoder wrote the silence clause
before the witnessing clause because their tags happen to sort that way, while
the decoder enforced ascending order. Agreement by convention rather than by
construction, and the first clause added with a tag that sorted between them
would have emitted a list this decoder refuses - visible only to a test covering
that exact combination. The encoder now collects clauses and sorts them, so the
order is structural on both sides. It is the shape this codebase keeps finding,
caught this time before it shipped rather than after.

**No semantics moved.** `SilenceClause` and `WitnessingTerms` are unchanged and
every predicate above them is untouched; the only observable difference is that
a backing declaring a future clause is representable at all.

**Spec change:** none needed. The paper names E's fields and leaves the encoding
to the implementation.

## 2026-08-20 - Slice 11: what a receipt is worth, and what an operator cannot take back

**Question:** CLAUDE.md now says a payment is final when witnessed rather than
co-signed, and a payee could not ask that in code - they would hand-compose
`receiptProvenBy`, `stateProvesCommitment` and a latest-commitment check, and get
a boolean where the situation has more than two shapes. Separately, Bob's
question about an operator restoring from continuously saved state left an
artefact nobody could point at: an operator that comes back on stale data and
carries on.

**Decisions (Bob):**

- **A receipt's fate has four answers, not two.** `receiptStatus` reads a
  committed state and says `witnessed`, `pending`, `contradicted` or
  `unrelated`. The first three are the payee's question; the fourth exists
  because a proof that accuses must not accuse the wrong party, which is the
  finding slice 9 made twice. Reading a stranger's receipt as contradicted would
  name this backing's operator - the party that owes the money under §C2's
  backer-run default - for something it did not do.

- **`witnessed` does not need the latest commitment**, and that is the
  difference from `provesHolding`, where "last" is load-bearing. Positions are
  pinned and the log is append-only, so once witnessed, always witnessed: a
  holding can be spent afterwards, and an accepted operation cannot un-happen.

- **The log is not replayed.** Whether the operator committed a *lawful* history
  is `stateIsAuthentic`'s question. What `receiptStatus` asks is only what the
  operator put its own signature to, twice - which is the whole of what a
  receipt can settle, and is why it belongs beside the receipt rather than in
  recovery.

- **`isRewrittenHistory`, because a receipt alone cannot see a shrink.** An
  operator that restores stale data commits a SHORTER log, and a receipt for a
  position that log never reaches reads `pending` forever - indistinguishable
  from an operation still in flight. So the second half of the slice: an
  append-only log may grow and may not shrink, and no committed entry may
  change, so a later commitment must have the earlier one's log as a prefix.
  That also catches the quiet rewrite, where the log grows but an earlier entry
  is not what it was.

  It is the fault ACROSS sequences where `isEquivocation` is the fault at one,
  and two states at a single sequence answer false here deliberately - naming one
  artefact twice would let it be reported as two faults.

- **Which state came first is derived from the sequence, never from the argument
  order.** A caller who could label them could choose which log is the rewrite.
  The same rule `signerFromTerms` follows, applied to a different asserted fact.

**One mechanism, and it removed two copies.** Three questions always travelled
together - is this commitment signed by the key E names, is the served state the
one it commits to, does it carry this backing at all - and were asked separately
by the redemption walk and would have been asked twice more here.
`committedLogFor` in commitment.ts is now the one place, and `replayServedState`
is what is left over: that check, then the law. `ServedState` moved there with
it, since it is the pair a verifier is handed rather than a §C2b object.

`isTheOperator` moved out of fault.ts to `isOperatorReceipt` in receipt.ts for
the same reason: `receiptStatus` needs exactly it, and a private copy beside a
second caller is how one property becomes two that agree until they do not.

**Found reviewing the implementation:** the malformed-log branch of
`receiptStatus` answered `contradicted`. It is unreachable - `committedLogFor`
recomputes the root, and the encoder pins each position to its index, so a log
that reaches this point has them - but the answer was wrong in the accusing
direction, which is the one direction that matters. It answers `unrelated`.

**Found by `/code-review high` on the slice, recorded rather than patched:** an
operator can escape both predicates by dropping the backing from its committed
state entirely rather than shrinking its log. `committedLogFor` answers undefined
for a state that carries no entry for the backing, so `isRewrittenHistory` is
silent and every receipt reads `unrelated` - and `isSilent` measures whether the
OPERATOR published rather than whether it published anything carrying this
backing, so one still committing its other backings is graded perfectly live. The
claims freeze and no grade fires against anyone, which is §C2's "a stall is
deniable where a dishonour is recorded" one level down. Demonstrated in
`review-dropped-backing.mjs`, with the operator committing on schedule
throughout.

It is not fixable from the venue alone, which is why it is not patched here: a
commitment is a root, so whether it carries a backing cannot be read without the
served state. The honest form is a predicate that takes one - and that is the
same shape as everything else this round concluded, since availability is
already assumed (§C2b: the trail "replicas serve because publication was the
point"). An `OPEN:` test pins it.

**Not built, and it is the next thing:** the remedy. A payee whose receipt reads
`pending` against a dark operator, or whose operator restored stale data, can now
name the fault and cannot get their units. That needs a successor sequencer
adopting the tail it can verify, which needs §C2's replacement rule declared in E
and published as a witnessed object. It is the slice after this one, and it is
the branch this whole round has been converging on.

**Spec change:** none needed.

## 2026-08-20 - Slice 10: E declares its venue and its witness interval

**Question:** the previous round wrote two holder rules into CLAUDE.md, and one
of them was unusable. "A payment is final when witnessed, not when co-signed"
tells a payee to wait for the next commitment without telling them how long that
is. Meanwhile the glossary's own field list has E declaring "who currently
attests a claim unspent, the venue it commits to, **the witness interval**, the
replacement rule... and the silence clause", and ours declared the operator key
and the silence clause. What does the omission cost, and what can be enforced?

**Decisions (Bob):**

- **The venue is a soundness gap rather than a missing convenience, and goes in
  first.** `isSilent` measured the grade against whichever `Venue` the caller
  handed it, while §C2b makes a grade effective "for each backing at its
  witnessed index on that backing's declared venue". The whole reason a grade
  works is that it is a fact a stranger checks against the published record -
  something a backer concedes rather than argues. Measured against an undeclared
  venue it is a fact about who you asked: two holders with two records get two
  grades for one backing and neither is wrong. The interval, by contrast, only
  cost a wallet a judgement call.

- **An opaque 32-byte identity, and no finality rule.** §C2 names a venue
  "together with its finality rule, the depth or gadget under which an index
  counts as witnessed there". This venue has immediate finality and says so, so
  the rule has nothing to declare, and a tag carries only what code here enforces
  - tag 0x02's own rule. The same shape as the operator key in slice 1: E names
  an identity, the code checks it matches, and what it MEANS is elsewhere.

- **Four tags, not one.** The plan had a single tag 0x03 carrying venue,
  interval and the silence clause together. The paper treats them as independent
  - the field list names them separately, and a backer may promise a schedule
  without ever conceding a grade - so folding them together would make a coherent
  setting unrepresentable. 0x03 is the witnessing block, 0x04 is both, and 0x01
  and 0x02 are byte-identical to what they were, so the slice-1 golden vector is
  untouched again.

  *[Superseded 2026-08-20 by slice 12: two blocks cost four tags, a third would
  cost four more, so the blocks became a canonical clause list and tags
  0x02-0x04 were retired. Tag 0x01 and the golden vector are untouched, which is
  what this slice actually promised.]*

- **Lateness is a fact, not a third grade.** §C2b declares two grades and
  `isOverdue` is neither: nothing fires, nothing opens, no remedy follows. It is
  what a payee reads to decide whether to wait. Quiet for exactly the interval is
  on time, one index more is late, and it counts from the venue's genesis where
  the operator has never published - the same rule `quietFor` already uses, for
  the same reason.

- **Still no calibration policed.** An interval longer than the backing's own
  silence duration is representable and means what it says: permanently in the
  aggravated grade. Incoherent, and not this code's to refuse (slice 6). A
  relation between two declared numbers is as much the backer's choice as either
  number alone.

- **A backing that declares neither is answered by whichever record its reader
  holds**, exactly as before. That keeps tags 0x01 and 0x02 meaning what they
  meant, and it is the same shape as a backing with no silence clause never being
  silent. A backer who wants the grade pinned declares a venue.

- **One consequence, worth saying out loud: the venue is inside the name, so a
  backing cannot change venue.** That is invariant 1 and §C2's own arrangement -
  "Venue and attester are named in E and move only under its replacement rule" -
  but the replacement rule is not built, so declaring a venue today means no
  venue change at all until it is.

**One mechanism.** `venueIsDeclared` is the single definition of "the right
record", and the five predicates that read the venue's record on a backing's
behalf go through it: `isSilent`, `isOverdue`, `provesHolding` (via
`replayLatestState`), `snapshotRedemptions` and `gapLegsFor`, which is also how
`Sequencer.adopt` inherits it. `quietFor` deliberately does not - it takes an
operator rather than a backing and has no terms to consult. The sequencer asks
the same question in its own voice: `register` refuses a backing declaring a
venue this operator does not publish at, which is the second half of "is this
backing mine".

**Found reviewing the implementation, and it is a meaning rather than a bug:**
the guard makes a mismatched venue answer `false`, and a holder reading that is
told "not silent, not overdue" while the operator is in fact dark. That reads as
reassurance about the operator when it is only a statement that this record shows
nothing. Both predicates now say so, `venueIsDeclared` is exported so a caller
can ask first, and a test pins the meaning rather than leaving it remembered. It
is the same reading `provesHolding`'s false has always needed.

**Found writing the tests:** one of them asserted an empty redemption result
against a venue with nothing published, which no implementation could ever fail.
It now publishes byte-identical legs on both venues, so the declared one settles
and the stranger resolves nothing, and the difference between them is the only
thing it can be measuring.

**Not built, unchanged:** the finality rule, the replacement rule, the
non-service aggregate (m, W) and the refusal aggregate (m', W'). Each needs
something this slice does not have, and each would otherwise be a number in the
name that no code checks - which is worse than declaring nothing, because a
holder reading the terms would believe it was enforced.

**Spec change:** none needed. The implementation moves toward the paper's own
field list rather than away from it.

## 2026-08-20 - The challenge window's reach, and why no patch fits it

**Question:** Bob asked for the merged implementation to be reviewed for
inaccuracies and divergences from the paper before continuing. Two things came
out of it. One was a bug and is fixed. The other turned into a design question
that reaches further than the code: is §C2b's challenge window worth repairing
at all, and what may be built on a receipt.

**Fixed first: a publication of no known kind bricked the operator.** The venue's
one refusal is bytes that do not encode, and it did not fire for an operation
whose `kind` is not one of the seven - every switch over the kinds ran off its
end and returned `undefined` typed as bytes, so nothing threw. `Sequencer.adopt`
walks the venue's record before it applies or co-signs anything and `commit()`
adopts for every backing it serves, so one publication by a stranger holding no
keys stopped an honest operator committing at all - which is §C2b's aggravated
grade, opening snapshot redemption against every backing that operator served.
Demonstrated with a second backing that had nothing published against it, graded
silent. `unknownOpKind` is now the one place that says an unknown kind is not an
operation, and its `never` parameter keeps the compile-time exhaustiveness while
its `never` return gives the runtime the same answer.

**Then the window, and the finding that reframed it.** A challenge is folded onto
a copy of the pre-gap snapshot, and the gate is "the chain starts where the claim
leg stands, or not at all". Two demonstrated failures, and the second is what
matters:

- **The state cannot reach the claim.** The fold starts at the claimant's
  snapshot nonce, so a claim filed after any leg of her own during the gap is
  beyond every challenge. One claim, one challenge, no second claimant: she
  files a demand and withdraws it, then claims one step along, and her payee's
  evidence is refused on the nonce.
- **And she chooses where to stand.** The spend's nonce is fixed - it is
  whatever she signed when she paid. The claim's nonce is hers, because she
  chooses what else to publish first. So the obvious repair, judging each
  challenge against the state as it stood when its claim was filed, closes the
  first case and not the second. The window reaches a careless double-spender
  and never a deliberate one.

**Decision (Bob): the window is not patched, and nothing is added to reach
further.** Three reasons, and the third is the one that generalises.

- **Illiquidity is the rule, and it is the design rather than a workaround.**
  §C2b: claims "go illiquid rather than dead. Value discounts until they
  return." A transfer published at the venue is evidence, never an operation, so
  a payee who accepts during darkness is relying on the window, and the price
  was on the table. Bob's framing: liquidity resumes when the operator returns
  or a successor takes over, and not spending while illiquid already makes the
  system work.
- **A patch that does not close its own hole is not worth its permanence.** The
  state-before repair is ten lines in the most delicate function in the
  codebase, and it buys a narrower hole rather than none.
- **The repairs that would reach further do not survive blinding.** The one that
  works is a receipt chain: provenance back to committed state, handed over at
  payment time, because the middle of a chain has spent and has no stake -
  demonstrated, and without the missing link the honest payee is not merely
  unrefuted against but *unpayable*, since her own receipt debits a balance the
  last commitment never saw. Bob's objection killed it: this slice is the
  barebones of a design that must later blind, and a chain naming every past
  holder is exactly what blinding exists to destroy. Worse with age, since the
  history grows per hop - the failure invariant 20 names for accrual per
  vintage.

**So the line is: a receipt attributes an act to the operator, and never proves a
value to a holder.** That is slice 9's own conclusion when it refused
`holdingProvenByReceipt`, restated as the rule that decides what may be built.
Attribution translates as far as each construction allows - §C4 grades it
"unbounded" under Chaumian, "since the commitment buys attribution rather than
proof". Value proofs do not translate at all.

**What does translate, and is already built.** Recovery is not "show me where
this came from" but "prove the claim unspent as of the last commitment" -
invariant 23's non-membership proof over the spent set, §C2b's published
nullifier. A negative statement about committed state, with no chain and no past
holders. `provesHolding` is the transparent form of it, and the Merkle machinery
is the same predicate proved differently where the whole state cannot be served.

**The uncommitted tail is not a transparent problem and is not rescued.** An
operation accepted after the last commitment lives only in the operator's
unpublished log and in its receipt, and a Chaumian token signed but never
committed is exactly as unprovable. It is a finality question, and the spec
answers it: "Finality means witnessed rather than co-signed" (§C2), "a release
nobody witnessed did not happen" (§C3). The exposure is the interval since the
last commitment, which is why §C2 makes the interval "a signed field rather than
operational discretion".

**Two rules into CLAUDE.md, beside the two operator ones**, because they are the
actual defence and no code here enforces either: claims go illiquid while the
operator is dark, so do not accept one; and a payment is final when witnessed,
not when co-signed.

**Recorded as open, in tests rather than in prose.** Two `OPEN:` tests in
c2b-redemption-legs pin what the window does not reach - the nonce dodge, and
the second of two claims in one gap - so an assumption that it works fails
loudly. They sit beside the slice-8 one that pins the pre-emption hole.

**Noted, not built, in the order they look worth doing:**

- **The witness interval belongs in E.** The glossary's own field list has E
  declaring "who currently attests a claim unspent, the venue it commits to,
  **the witness interval**, the replacement rule..." and ours declares the
  operator key and the silence clause. A payee told to wait for finality cannot
  tell a fast operator running late from a slow one running on time. A tag 0x03
  on tag 0x02's own reasoning: a new tag rather than a version bump, declaring
  only what code enforces. Construction-independent, which is now the test a
  candidate has to pass.
- **`contradictsOwnReceipt`.** An operator that restores a stale state and keeps
  serving will commit a log whose entry at position P is not the operation it
  receipted at P. Today `receiptProvenBy` answers `false`, which also means "not
  committed yet"; the undeniable form is that the log is long enough to have
  contained it and does not. `isDoublePosition`'s missing sibling, and on the
  right side of the line above - it attributes an act to the operator.
- **Successor sequencers and the uncommitted tail**, unchanged from slice 9, and
  now with a reason to prefer succession over recovery: a successor adopting
  what it can verify is where the honest payee gets units rather than a share of
  somebody's redemption.

**Also in this round, five inaccuracies with no behaviour behind them**, each a
place a reader was told something the code had stopped doing: `IssuanceLogEntry`
outliving `issuanceLog`; ledger.ts still calling balances primary state after
the alignment made them the fold; commitment.ts still deferring non-membership
proofs "with the recovery path" that landed in slice 6; presentability.ts
looking wired up when invariant 13 is enforced by refusing reliance-bearing
demands instead; and CLAUDE.md's invariant 16 bullet claiming a closure
expansion `makeBacking` does not do.

**Spec change: one to raise.** §C3: "the demand names specific claims, and
spending them voids it, checkable under transparent, accumulator and pooled,
since nullifiers are public where amounts are not." Under transparent there are
no specific claims to name - §C1 makes it "a per-token public ledger of
key-controlled balances", and a balance is fungible. The implementation
substitutes the claimant's nonce as the proxy for "which claims", and the nonce
dodge above is exactly what that proxy costs: a nullifier is the claim's own
identity and cannot be moved, while a nonce is a position its signer chooses. So
the sentence lists transparent alongside constructions whose mechanism it then
gives, and the transparent case has no equivalent. Proposed: either scope the
clause to accumulator and pooled, or say what the transparent check actually
keys on and that it is weaker for it.

*[Made the same day, in money-from-first-principles@2ac2e85, taking the second
option: §C3's clause scopes to the accumulator and pooled and then says what
transparent falls back on, and §C2b's "stands in for the nullifier" carries the
same qualifier. The same commit closes money-from-first-principles#1 with the
payee reading the implementation already followed, so no code change follows
from either.]*

## 2026-08-19 - Slice 9: the holder can be at fault too

**Question:** slice 8 left §C2b's challenge window defeatable by the claimant.
She knows about her own double-spend before her payee does, so she reaches the
venue first with a transfer to a key she generated for the purpose, and the
honest payee finds the nonce spent. Bob asked whether the payee can at least
come away with **proof of fraud**, since the system needs trust in the operator
regardless.

**Decision (Bob): yes, and the proof needs nothing from the operator.**

Bob holds the claimant's signature over the transfer that paid him. The venue
carries her signature over the redemption claim. Both are at one point in her
own nonce sequence, and a nonce is per (signer, backing) with the law consuming
exactly one per operation - so only one of them can ever have been applied, and
she knew that when she signed the second. That is checkable by any stranger,
forever, with no commitment, no venue and no operator asked.

It closes a gap in the system's own posture rather than adding a new idea.
Misbehaviour is made **provable** rather than prevented everywhere here -
invariant 22 on two roots at one sequence, §C2b's grades on facts a stranger
checks, §C3's "publicly checkable... with nobody reporting anything" - and that
posture covered the operator and never the holder.

Three predicates, in a new `fault.ts` collecting them on one screen the way
`contexts.ts` collects domain tags, because "what can be proven against whom" is
exactly what an auditor wants in one place:

- **`equivocatingSigner`** - one key authorised two operations at one nonce.
  Returns the key rather than a boolean: the key is derived here, so the caller
  does not otherwise have it, and naming the party is what a proof is for.
- **`isDoubleAcceptance`** - an operator co-signed both halves of that.
- **`isDoublePosition`** - an operator co-signed two operations into one log
  position, so one of its receipts misdescribes its own log.

**The signer is derived, never asserted.** A caller who could name the signer
could choose who is at fault, so it comes from the law's own rule and the
signature must verify under it. `signerOf` in ledger.ts was split rather than
copied: `signerFromTerms` is its state-free half and both callers read it, so
there is one definition instead of two that agree until they do not. The price
is that a release or withdrawal cannot be proved by a pair of operations alone -
the law reads their signer from the demand they name - and it is refused rather
than guessed.

**A resubmission is not a fault.** Invariant 26 exists so that repeating a
request is safe, so the canonical messages are compared rather than the objects:
equivocation is two different operations, never one sent twice.

**Not built, deliberately:** a `holdingProvenByReceipt`. It was in the plan
until Bob pointed out that claims travel - Alice pays Bob, Bob pays Carol, and
both hold a receipt for what they received while only Carol still holds
anything. An incoming receipt proves **acceptance, not a holding**, and a
function with that name would have baked the error into the API. `receiptCovers`
says only what it can: this operator co-signed this exact operation. Its doc
comment says the rest.

**What this does not do:** pay Bob. The evidence that would - which of the two
signatures the operator accepted - exists only in the dark operator's
uncommitted state. §15 prices the fault instead: a revealed double-spender loses
its key's accumulated history, and the key at fault is the one that accepted the
backing's terms, so a fresh payee key evades nothing.

**Operator constructions, recorded in CLAUDE.md rather than built:** Bob's, and
better than the hot standby I proposed.

- A **threshold** operator key (t-of-n, aggregating to one Ed25519 key) makes
  the replication a fact rather than a promise: a co-signature existing proves t
  servers saw the operation. With t > n/2 two disjoint quorums cannot exist, so
  the operator **cannot equivocate** - prevented rather than recorded, which is
  stronger than this system's usual posture. It is invisible below the signing
  boundary, so E, the name and `verifySignatureStrict` are all untouched.
  (Unverified here: whether a given aggregation scheme's signatures pass strict
  non-ZIP215 verification. To confirm before anyone relies on it.)
- Failing that, **one writer at a time**. Two live servers holding one operator
  key produce exactly the artefacts above, and the protocol cannot tell a
  botched failover from malice - the same standard it already applies to a
  self-framing commitment equivocation. Note that `nextSequenceFor` deriving the
  next sequence from the venue guarantees the collision rather than softening
  it, which is right for its own case and worth knowing here.
- **The payee obtains the receipt at payment time.** A holder with no receipt
  has no evidence the operator ever accepted the operation, so the operator can
  deny having seen it. `submitTransfer` returns the receipt to whoever submitted,
  normally the payer, which makes this a wallet-protocol obligation.

**Two branches parked, with reasons.** Successor sequencers (§C2's replacement
object) matter for replacing an operator deliberately, not for outages, since a
standby or a threshold covers those; and it is the correct form of "rotate the
operator key", which cannot be done by editing E - E is inside the name, so a
new operator key is a **new backing** and the outstanding claims do not follow
(`check-rotate-e.mjs`). Gathering the uncommitted tail from holders' receipts
covers only an operator that ran neither construction, and its ordering comes
free from the positions receipts already carry.

**Rejected:** several sequencers serving one backing with "first anchoring
decides". Alice submits conflicting spends to two of them, both co-sign, and two
payees hold valid receipts of which one is worthless - the double-spend the
sequencer exists to prevent (§C2: "it co-signs, and refuses a second spend by
declining to sign"), with invariant 22 losing its singular "this backing's
operator" as well. Making it work means a consensus protocol between them, at
which point they are one logical sequencer with extra round trips.

**Found by `/code-review high`, and both the same shape - a proof that names
the wrong party:**

- **A receipt from another backing covered the operation.** `isDoubleAcceptance`
  derived the operations' messages from its `backing` argument while
  `receiptCovers` derived its own from `receipt.backingName`, and nothing checked
  the two agreed. An operation object carries no backing name, so a receipt the
  operator had issued perfectly correctly on a second backing - and one operator
  serves many (§C2) - covered the operation here exactly. Demonstrated in
  `review-false-accusation.mjs`: an honest operator proved at fault for something
  it did not do. The backing is now a parameter of `receiptCovers`, as it already
  is of `opMessageOfEntry`, so the binding is structural rather than remembered.
- **The split lost a compile-time guarantee.** `signerOf` had been exhaustive
  over the seven kinds and returned `Uint8Array`, so a missing case was a compile
  error. `signerFromTerms` returns `Uint8Array | undefined`, which absorbs a
  missing case silently - the new kind would compile and be refused at runtime
  for no visible reason. Confirmed by deleting a case and watching it build. A
  `never` assertion after the switch puts the error back at the place that has to
  decide.

**And two more found reviewing those fixes, which is six rounds out of six, and
again the recurring shape: the fix bound one input and left the adjacent one
open.** Binding the backing NAME left the operator IDENTITY unbound, so a
stranger who signs receipts over both halves of somebody's real equivocation read
as a fault by *this backing's* operator - which is what a caller takes the
predicate to mean, and under backer-run names the party that owes the money.
`isTheOperator` now asks both questions in one place, and `isDoublePosition`
takes the backing for the same reason rather than trusting whichever key its
receipts happen to name.

**Spec change:** none needed. The wording fix from slice 8 is filed as
money-from-first-principles#1. *[Landed 2026-08-20 in
money-from-first-principles@2ac2e85; the issue is closed.]*

## 2026-08-19 - Slice 8: the redemption legs are operations, published elsewhere

**Question:** §C2b's payment path - the claim/acceptance/release legs, the
challenge window, and a returning sequencer adopting what was witnessed during
the gap. Two things had to be settled first, because both change what a
redemption claim is: does a standing demand block redemption (open since slice
6), and do the legs need the law's time-dependent rules replayed, which would
need a witnessed index per log entry.

**The finding that answered both.** §C2b says redemption "publishes the claim's
nullifier at the witness venue as the release leg, after the backer's
acceptance", and §C2 that "the venue-published nullifier stands in for the
sequencer's lock". So it is not a second protocol beside §C3's
demand-accept-release. It is that protocol with the legs published at the venue
because there is no sequencer to submit them to - and under transparent a signed
spend record IS an operation-log entry. One law, one replay, one nonce sequence:
the legs go through the same `applyEntry`, and adoption is appending them in the
order the venue witnessed them.

**Decisions (Bob):**

- **A standing demand is continued, not blocked - and that needed no new rule.**
  Where the holder filed before the darkness, the claim leg has happened and only
  the answer and the release are left, which is §C2b's sentence read literally.
  Where they had not, the claim leg is an ordinary demand, and a demand needs
  *spendable* units, held minus what open demands commit, so the same units
  cannot back two claims. The two alternatives both failed: blocking deadlocks
  the holder, because ending a demand takes a withdrawal and a withdrawal takes
  the sequencer that is dark; ignoring it lets one holding back a venue
  redemption and a sequencer demand at once, and the backer concedes two
  payments for one lot of units.

  It has a structural consequence worth having in view: a demand standing in the
  snapshot cannot be challenged at all, because its units were locked and its
  nonce spent before the darkness. The lock had already done the challenge
  window's job. Only a claim filed *during* the gap is challengeable.

- **No witnessed index per log entry.** A leg published at the venue is stamped
  by the venue, so it is applied with the venue's own index as its clock and
  every TIME-marked rule in `applyEntry` is checkable with nobody asserting when.
  What stays unreplayable is the historic log, and that is safe here because
  every TIME rule refuses an entry signed by the party it protects: the demand's
  instant is agreed by two signatures, a dead acceptance deadline costs only the
  backer, a late release and a premature withdrawal are the holder's own
  signature, and dishonour cannot be laundered because the acceptance deadline is
  structurally bounded by the demand's. The alternative - an operator-asserted,
  committed, monotone index per entry - buys a timeline the operator still
  chooses inside, for 8 bytes an entry and two replay checks. **Reopen it if a
  TIME rule ever protects someone who did not sign the entry.**

- **The challenge pays the payee named in the request, not whoever published
  it.** §C2b says "pays the request's presenter", and the next clause explains
  why they are normally the same party ("the payee already holds that request").
  Read literally, anyone who merely saw a holder-signed transfer could publish it
  and take the payment from the party it was made out to. Flagged as a wording
  bug rather than built around silently.

- **A transfer published at the venue is evidence, never an operation.** §C2b
  promises claims "go illiquid rather than dead" while a sequencer is dark, and
  illiquid means the transfers stop. Applying them would make the venue a second
  sequencer with no operator, order or receipt. Only the four presentation legs
  are adopted; issue and burn at the venue do nothing at all.

- **Adoption is enforced structurally, not by a flag.** `submit` adopts before it
  applies anything and `commit` before it snapshots, so there is no order of
  calls in which the operator co-signs while ignoring the venue. It is idempotent
  for the reason a resubmission is - an operation already in the log fails on its
  own spent nonce - and each leg is adopted at the index the venue stamped it
  with, so adoption is reproducible by anyone holding the same record.

**Five holes, each demonstrated by running it rather than argued, and four of
them one question: WHICH RECORD is a publication judged against.**

Found reviewing the implementation (`exploit-gap-veto.mjs`):

- **The veto.** A commitment at the same index as a leg was ending the gap for
  it, so an operator watching the venue stripped the force from any leg by
  committing at the index it appeared - one commitment for a veto over the whole
  clause. The rule now is that **a publication is judged against the record as it
  stood strictly before its own index**: the venue witnessed both at one index,
  so neither precedes the other, and the tie must not go to the party watching.
- **The erasure.** Judged against whatever commitment is latest *now*, an
  operator killed a settled redemption by publishing one more. Under backer-run -
  the spec's cold-start default - that is the party that owes the money.
- **The free challenge.** A request the snapshot could never have served counted
  as a spend, so a claimant signed a transfer for units they never held and sent
  their own payment wherever they liked. A request is now put to the law against
  the snapshot: if the operator would have refused it, it spent nothing.

Found by `/code-review high` (`review-challenge-window.mjs`), both robberies:

- **The window shut when the operator returned.** Requests were gated like legs,
  so a prompt return decided how long anyone had to object. A request is evidence
  rather than an operation: the declared window bounds it, and nothing else does.
- **Only the first spend could be exhibited.** Where the operator served several
  of the claimant's spends and committed none, the second payee's units were paid
  to the claimant who had signed them away.

**And two more found reviewing the fixes, which is now five rounds out of five.**
Both are the recurring shape - the fix bounded one input and left the adjacent
one open:

- Generalising "one challenge" to "fold the claimant's spends" relaxed the nonce
  test from `=` to `>=`, and a spend of the claimant's *other* units - free of
  the demand's lock, so nothing to do with the claimed ones - redirected the
  payment. **The chain starts where the claim leg stands, or not at all.**
- The fold read requests in publication order, so a payee who reached the venue
  ahead of the one before them in the chain was passed over and never
  reconsidered: whoever was quickest decided who was paid. Folded in sequence
  order now, with the witnessed index settling the case it is actually for, which
  is two requests at one nonce - the claimant equivocating, earliest wins.
- And reviewing *that*: a claimant who pre-empts a genuine request by publishing
  at the contested nonce first shuts the window against the party it exists for.
  The claimant knows about her own double-spend before her payee does, so she is
  always first. **I closed the wrong half of this and said so wrongly.** A
  request that pays the claimant is no evidence of a spend and no longer folds -
  which is true, and buys nothing: Bob pointed out that a keypair is free, so she
  pays a key generated for the purpose and the check sees an ordinary transfer.
  Demonstrated in `check-sybil.mjs`; the redemption pays `alice2`. The check is
  kept as a true statement about what evidence is, and is no longer described as
  a defence. What the attack actually needs is below.

**Consequences.** `OpLogEntry` is now `PublishedOp & { position }`: an operation
and where it landed, separated because §C2b needs the operation before it has a
log to be in, and because no signed message ever contained the position. The
ledger's seven named methods became adapters over one `apply`, which is the door
adoption comes through as well. The venue records two kinds of thing now -
commitments, which operators publish, and operations, which anyone may - and
judges neither beyond refusing bytes that do not encode.

**Scoped out, with reasons:**

- **Chains beyond one hop.** Alice pays Bob, Bob pays Dave, both during the gap:
  Bob is paid and Dave is not. The claimant's own spends are folded however many
  there are; a spend by the payee is a different signer's sequence, and §C2b
  describes one substitution.
- **The residue.** A request for more than was claimed redirects only what the
  redemption pays, so a payee owed more than the claim is short the difference,
  and the claim layer cannot make it up because the request's nonce is spent.
- **A claimant still picks which of her own two signatures counts**, by
  publishing a transfer at the contested nonce before the honest payee reaches
  the venue. The redemption pays the key she named and the honest payee finds the
  nonce spent. That is not a defect in implementing §C2b's rule but the reach of
  the rule itself: where a double-signature is resolved by publication order, the
  party who signed both knows first, and nothing about her is scarce - the payee
  key costs one line of wallet code.

  Closing it needs evidence of which signature the operator actually served, and
  that evidence exists in exactly one place outside the dark operator: the
  **receipt** it co-signed for the request it accepted. Bob has one; a request
  invented during the gap cannot have one. Ranking a receipt-backed challenge
  above a bare one is the fix, and it is sound under a trust the system already
  extends - and the backer has no motive to collude, since the redemption pays
  out the same either way and only the claimant gains.

  Not built here, and it is a slice rather than a patch: a receipt names a
  position in a log that was never committed, so what it proves has to be settled
  on the signature alone; the payee has to actually hold it, which is a wallet
  protocol; and the case where neither party has one needs an answer.
  *[Closed 2026-08-20, and not by building it: the window reaches a careless
  double-spender and never a deliberate one, because the claimant chooses which
  nonce her claim stands at. See "The challenge window's reach, and why no patch
  fits it" for what a receipt may and may not be made to prove.]*
- **`snapshotRedemptions` stops resolving once the operator has adopted and
  committed the legs**, because they are then in the log and the ordinary
  presentation record covers them. The redemption is still a fact; it is the
  committed log that carries it.

**Spec change:** the "pays the request's presenter" wording, above. Otherwise
none needed. *[Landed 2026-08-20 in money-from-first-principles@2ac2e85: "pays
the payee the request names instead". The implementation already read it that
way, so nothing here changed.]*

## 2026-08-19 - Aligning the decisions: the law is applied once

**Question:** Bob asked which recorded decisions no longer serve the goal -
simplicity, security, and enforcement exactly where it is necessary. Three came
out of the review, and all three are acted on here.

**Decisions (Bob):**

- **Reopened: "balances remain primary state, not a fold over the log"**
  (slice 2). It was a modelling convenience then. It had become the last place
  the law's arithmetic existed twice - the ledger mutating its own book, and
  `replayLog` folding a served one - and written twice they drifted. Twice, both
  caught only after shipping: the acceptance-deadline range enforced in the
  ledger and not the replay, and invariant 27's "settlement takes two
  signatures", demonstrated by serving a release the ledger had refused with no
  acceptance anywhere and watching 40 units settle on one signature.

  `applyEntry` is now the whole law in one function: the ledger applies entries
  as operations arrive, a verifier folds a served log through the same function.
  Each operation method becomes "build the entry, append it". The ledger's
  checkOp, checkBalance, lockedIn, debit, credit, consumeNonce and
  standingDemand all collapse into it.

  **The clock is an explicit parameter, never an optional one.** The rules that
  read it are exactly the rules a served log cannot answer - the log does not
  record the index each operation was accepted at - and they are the only ones
  marked TIME. That makes the one place a replay is weaker than the ledger
  visible in one place, instead of being a property of two diverging copies.

- **Reopened: the operator key is validated at the sequencer** (slices 1 and 3).
  The obligor was point-checked in `makeBacking`, the operator length-checked
  there and point-checked in `Sequencer.register`: one property, two boundaries.
  The recorded reason was that checking it at construction "would change which
  backings are representable, and the slice-1 name format is frozen" - but the
  golden vector's own operator key is a valid non-small-order point, so the
  format is untouched and the reason had lapsed. The sequencer keeps the only
  question that was ever its own: is this operator me.

- **Two over-enforcements removed with them.** A valid strict signature already
  proves the signer key is a valid non-small-order point, because verification
  decompresses it and rejects small order - so the ledger's `isValidPublicKey` on
  signer keys checked nothing new. It is kept for recipients and destinations,
  which sign nothing and which no signature vouches for. And pre-checking a
  malformed signer key so the caller got a `LedgerError` was the exact
  anti-pattern CLAUDE.md names ("does not pre-check in order to relabel an
  error"); it also made the ledger disagree with the sequencer, which encodes
  first and always surfaced the encoder's refusal. Both paths now agree, and the
  error names the boundary that actually saw the malformed field.

- **Stale entries are marked rather than rewritten.** Six decisions that later
  slices reversed or closed now carry a one-line pointer to where. The file is
  newest-first and later entries do supersede, but its own preamble asks that
  reopening happen "with the earlier reasoning in view", and a reader landing on
  the slice-3 entry was getting a confidently wrong picture of what is committed.
  Nothing is deleted: the earlier reasoning is the point.

**Consequences.** `oplog.ts` returns to what its header always claimed - the
entry and its canonical bytes, knowing nothing of the law. `issuanceLog` was a
filter over `opLog` and is gone. src is 2698 lines, from 2968 before the design
review began.

**Still open, and slice 8 pays money against it:** whether a standing demand
blocks redemption (recorded in slice 6). *[Closed in slice 8: it is continued,
not blocked, and the law's spendable check was already the whole rule.]*

**Spec change:** none needed.

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
*[Decided in slice 8: it does not. A leg published at the venue carries the
venue's own stamp, so the rules are checkable without anybody asserting an
index; see that entry for the condition that would reopen this.]*

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

- **Presentation is a claim-layer operation this slice.** *[Done in slice 5.]*
  The four operations
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

- **Invariant 24 is only half-enforced, deliberately.** *[Closed in slice 5:
  the sequencer supplies the witnessed index, and the other half is enforced.]*
  The instant is named
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

- **The commitment is over the whole served state.** *[Superseded by the design
  review: the commitment is over the log alone, because the log determines the
  rest.]* Invariant 23's objects,
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
  transparent core yet". *[Reopened: `makeBacking` point-checks it, one boundary
  for both keys a backing names - see "One boundary owns both keys".]* `makeBacking` still validates the operator by length
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

- **Replay is a rejection, not idempotence (inv 26).** *[Superseded: the
  sequencer returns the identical prior receipt from slice 3, and for
  presentation from slice 5.]* The ledger rejects a
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
  so the record is honest about what happened. *[Reopened: the log carries all
  seven kinds from slice 5, and balances became a fold in "The law is applied
  once" - see that entry.]* But balances remain primary
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
