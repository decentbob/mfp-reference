# mfp-reference

TypeScript reference implementation of **Money from First Principles**:
one object `B = (K, P, R, E)`, claims held against it, wallets, and the law.

## The spec is a reference, not gospel

- Spec: https://github.com/decentbob/money-from-first-principles
  (the derivation is in `money-from-first-principles.md`, the build machinery
  in `construction.md`, optional profiles in `extensions.md`).
- The code tracks the spec as it stands, not a snapshot. When the spec
  changes in a way that touches implemented code, the code changes to match;
  divergence between the two is a bug in one of them. Check the spec repo for
  recent changes when starting a work session.
- The spec can contain mistakes. When implementation work reveals a
  contradiction, an ambiguity, or something that cannot work as written:
  **stop, quote the exact passage, explain the problem in plain language, and
  propose a fix to the spec.** Never silently build around a spec bug, and
  never pick one of several possible readings without flagging the choice.
- The spec is corrected upstream (issue or edit on the paper repo), then the
  code follows the corrected spec. Resolved questions are logged in
  `DECISIONS.md` — not to lock them forever, but so that reopening one is
  done knowingly, with the earlier reasoning in view.

## Scope (current)

Transparent setting only. In scope: canonical encoding of backings, hashing,
signatures, issuance, swaps (transfer), presentation, the conservation
arithmetic. **Out of scope for now:** blinding, the accumulator and pooled
constructions, the Chaumian profile, shielded anything, external references,
triggers, pro-rata. Cryptography is limited to hashes and signatures
(`@noble/hashes`, `@noble/curves` — no other crypto dependencies).

## Binding rules

Construction.md §C0 says: an implementation that violates an invariant is a
different system. These are the ones that bind every line of code here.

None of them is sacred. Any rule below can change — but a change needs a
very good reason, stated explicitly and agreed with Bob, and it happens by
editing this file (and the spec, where the spec is the source). What is never
acceptable is silent drift: code that quietly stops following a rule while
the rule still stands.

- **All quantities, counts, and payout arithmetic use `bigint`.** The
  JavaScript `number` type is a float; a rounding error in this system is a
  counterfeit. `number` may appear only for things that are genuinely not
  quantities (array indices, lengths).
- **A backing's name is the hash of a canonical encoding of (K, P, R, E)**
  (inv 1). The encoding must be byte-deterministic: same fields, same bytes,
  on every machine, forever. No `JSON.stringify` of objects with unordered
  keys.
- **A backing exists only with a valid signature by K over its own name**,
  under a fixed domain-separation tag (inv 2; see [[DECISIONS.md]]). K must be
  a valid, non-small-order Ed25519 point, and verification is strict
  (non-ZIP215).
- **Issuance and reissuance never share a code path** (inv 7). Issuance
  changes the outstanding count and needs the backer's signature; reissuance
  preserves the count and needs none. In the transparent slice this reads as
  issuance vs. movement (transfer/burn); reissuance proper (denomination
  swaps) arrives with blinding. See [[DECISIONS.md]].
- **No clawback, no reversal, no privileged party who can move claims**
  (inv 8). The rule is not "don't call it" — the code path must not exist.
- **Fees are ordinary transfers alongside a swap, never a shaved reissue**
  (inv 9).
- **Do not write cycle detection** (inv 5). A reliance cycle would need a
  hash cycle; it cannot be built.
- **`outstanding = issued − burned`, in claim quantity, per backing, at every
  published moment** (inv 10). Presentation destroys nothing; only a burn
  lowers the count.
- **Presentability** (inv 13–15, 18): a holding is presentable at *b* for *q*
  iff it contains *q* units of *b* and *q·cᵢ* units of each *(bᵢ, cᵢ)* in
  R(b). Units, never claims. One level, no traversal. **A demand reserves each
  leg with a `lock` in that leg's own log**, so every backing stays replayable
  alone, and the sequencer takes the demand and its locks as one act or none
  (§C3's single-phase, "the whole set and the paying leg inside one operator").
  **Two-phase across operators is `submitLock` + `settle`** (§C3's
  prepare-decide-commit, generalised to any bundle): the holder reserves at each
  sequencer, then publishes ONE commit at a decision venue, and each sequencer
  settles its own half against that witnessed object without hearing from the
  others. **§C1's n-party exchange is the same mechanism**: each lock names its
  parties, one object carries every signature, and a sequencer converts its lock
  only when every party its lock names has signed — so a partial object settles
  nothing anywhere, and 24b's bundle is the one-party case. **Where P pays in
  claims** (§C3: "a payout paying in claims settles as a swap inside the
  settlement"), the backer's acceptance reserves the payout — its lock on the
  paying backing, to the holder, convertible by the holder alone — and the
  holder's release settles surrendered set and payout as one act; `payoutOf` is
  the holder's read of it, as `accompanimentOf` is the backer's. A lock names who
  may convert it: one party converts on their release or their commit, several
  only on the witnessed object — and **a set leg names no decision venue**
  (`NO_DECISION_VENUE`), so no commit reaches it and it settles only with its set. Which branch a trade uses is the parties' choice — §C2's other honest
  answer, partial-and-retry, is the ordinary transfer path and covers every trade
  where both sides have recourse. The law stays per backing, so whether
  a demand's legs were locked is read across the served state by
  `accompanimentOf`, which the backer asks before it signs an acceptance. **A
  lock carries §C3's timeout**, and it is the one predicate both exits read
  (`lockIsLive`): at or before it a commit can still settle the set and no
  withdrawal is accepted; a commit witnessed past it does not reach it, and
  withdrawal is then the exit — unless the record already shows a commit
  witnessed in time, which every reader asks before freeing anything
  (`committedInTime`: the sequencer before it co-signs a withdrawal, on the
  submit path and the gap path alike, and the verifier's gap fold). Exactly one
  exit is open at every index **per record**, as for a demand on its acceptance
  (a set of records can have both closed, within the holder's own declared
  window). A lock and a demand never share a hash on one backing, and a lock is
  prepared only where the sequencer can read the commits it may settle on and
  only for an attempt the record does not already show committed. Every TIME
  rule is a refusal and never a balance, because the clock is undefined on a
  replay and a lock that freed its own units would make an honest history
  unreplayable. Quantities are whole
  numbers of the backing's declared unit; counts in R are whole. Reliance is
  a conjunction over a fixed list with constant counts — no disjunction, no
  computed membership. Reliance names backings and chain assets only.
- **`closure(S)` expands deterministically before hashing**; counts sum where
  paths meet; the stored object is flat; cap closure size (inv 16). `closureOf`
  in `src/closure.ts` is that macro, and it is a **tool for writing terms, not a
  rule about them**: §8b makes an unclosed R a readable setting — "the backer
  takes in a set it cannot fully unwind, usually because it means to sell it" —
  so `makeBacking` stores what it is handed and `closureStatus` is what a reader
  asks. Expansion needs the targets' own terms, so it takes a resolver, and every
  answer is checked against the name it was asked for; that check is also what
  makes the walk terminate without the cycle detection inv 5 forbids. **A direct
  count is a floor, not a second contribution** — see [[DECISIONS.md]] for why the
  other reading cannot be right.
- **An unaccompanied claim is inert, never invalid, and still transferable**
  (inv 17).
- **Time is a witnessed index, never a clock** (inv 21, 24). Every instant a
  party asserts is an index in the **venue's** witnessed history, never in the
  operator's own commitment history — a clock an operator could stop by going
  quiet would hand it every deadline in its book; no code reads wall-clock time.
  The venue stamps what it witnesses, commitments and published operations
  alike, and that stamp is the clock each is judged against. One witnessed
  evaluation instant per presentation, named in the demand and agreed by the
  acceptance — two signatures over one value — and no later than the latest
  witnessed index at signing. See [[DECISIONS.md]].
- **Every state a sequencer asserts proves against its latest published
  commitment** (inv 22), and the commitment commits to the issuance log, the
  spent set, running totals and the standing demand record (inv 23). The root
  must be injective, or one signature covers two states and equivocation is
  unprovable.
- **Every operation is signed by the party the law names, over that backing's
  own message, at that signer's next nonce — except the commit.** §C3's commit
  names no backing, carries no nonce, and is signed by **every party the lock
  names** (§C1's "all sign") rather than by one signer the law names, because one
  object has to be valid in every log of an exchange at once and a nonce is per
  (signer, backing). Those are the only departures in the system, they are what
  "one object" costs, and they are safe only here: a repeat is a no-op because
  the lock it settles is gone, and it can only reach an attempt its own parties
  named in a lock. Do not
  add a third without the same kind of reason. See [[DECISIONS.md]].
- **Swaps and presentation are idempotent** (inv 26). A repeated request
  returns the identical prior response. A crash must lose nothing. The
  sequencer is where this holds: it returns the identical prior receipt for any
  resubmitted operation, presentation included, and a different operation at an
  already-spent nonce is declined. The ledger alone rejects a replay (per
  (signer, backing) nonce) rather than answering it. See [[DECISIONS.md]].
- **Settling a published demand voids the exact claims offered, and only on
  the holder's release signature** (inv 27). A backer must never void
  unilaterally. Dishonour is the branch where no *live* acceptance answers, so
  an acceptance that expires unpaid is dishonour too — and an acceptance may
  not outlast the demand's own deadline, because the lock-up is the holder's
  term to set. See [[DECISIONS.md]].

Invariants not listed here (3–4, 6, 11–12, 19–20, 25) still bind; several only
become implementable with the shielded constructions. Read §C0 of
construction.md before touching anything they govern.

## What the parties must do, that no code here enforces

Six rules the protocol cannot check but the reference implementation must not
leave unsaid. Each was reached by asking what a failing sequencer costs
somebody, and each is recorded in [[DECISIONS.md]] with the reasoning.

The three holder rules are load-bearing. §C2b's recovery path does not protect a
holder who ignores them, and every mechanism that would reach further either
fails to close its own hole or does not survive the move to a blinded
construction — which is why they are rules here rather than code.

- **One writer at a time**, or a threshold key. Two live servers holding one
  operator key co-sign conflicting operations, and `fault.ts` proves that
  against the operator exactly as if it were malice — the protocol cannot tell a
  botched failover from collusion and does not try. A **t-of-n threshold with
  t > n/2** removes the possibility rather than recording it, since two disjoint
  quorums cannot exist; aggregated to one Ed25519 key it is invisible here, so
  the name, E and strict verification are untouched.
- **A threshold K, or theft is unbounded.** §C2b: a stolen backer key does
  damage that is "unbounded and permanent, since K alone authorises issuance and
  nothing expires", and revocation is a stop-loss rather than a remedy — a thief
  issues fast and a backer notices slowly, so the fraudulent supply is already
  witnessed and stands. The paper calls this "the strongest argument for a
  threshold K". Like the operator rule above it is **invisible here**: t-of-n
  aggregated to one Ed25519 key leaves the name, E and strict verification
  untouched, so nothing in this repository can check that a backer took it.
- **The payee obtains the receipt at payment time.** During a §C2b gap the
  operator's log is unpublished, so its receipt is the only evidence outside it
  that an operation was accepted at all. A payee without one has the payer's
  signature and nothing that says the operator ever saw it. `submitTransfer`
  returns the receipt to whoever submitted, which is normally the payer.
- **Claims go illiquid while the operator is dark. Do not accept one.** §C2b:
  claims "go illiquid rather than dead. Value discounts until they return." A
  transfer published at the venue is evidence, never an operation, so nothing
  moves until the operator returns or a successor takes over. A presentation
  with legs — reliance or a claims payout — neither opens nor settles in a gap:
  the venue holds operations one at a time, never a set. One predicate
  (`admittedInGap`) says so for the operator's adoption and the verifier's fold
  alike. A payee who
  accepts anyway is relying on §C2b's challenge window, and that window reaches
  a careless double-spender and never a deliberate one: the spend's nonce is
  fixed, the claim's nonce is the claimant's to choose, and she moves the claim
  off the contested position for two signatures (the OPEN tests in
  c2b-redemption-legs). What the payee does get is a fault proof — two of the
  payer's signatures at one nonce, checkable by any stranger forever, needing no
  operator and no commitment (`fault.ts`).
- **Keep the last committed state that carries your backing.** An operator that
  drops one backing from its commitments and keeps publishing the rest looks
  perfectly live: §C2b's aggravated grade reads "no commitment past a second
  declared duration", and a stranger reading a root cannot tell which backings it
  covers. Every path against that operator runs through the last state that *did*
  carry the backing — the non-service grade is counted against it (`isNonServing`),
  the fault is proved against it (`isRewrittenHistory`), and the successor takes
  over from it (`takeOver`). The party who would otherwise serve it on request is
  the one with the motive not to, which is the same shape as the receipt rule
  above: obtain the evidence while the party holding it still has a reason to give
  it to you. §C2 names no grade for it — nothing declares the object, duration or
  aggregate that would make failing to serve the trail checkable — so the paper's
  own answer is this rule: the non-service grade is "read against the last state a
  holder was given, so a holder keeps one".
- **A payment is final when witnessed, not when co-signed.** §C2: "Finality
  means witnessed rather than co-signed", and §C3 applies it to the release: "a
  release nobody witnessed did not happen." An operation accepted after the
  operator's last commitment lives only in its unpublished log and in the
  receipt, and dies with it — in **every** construction, since a Chaumian token
  signed but never committed is exactly as unprovable. So the exposure is the
  interval since the last commitment, which is why §C2 makes the interval "a
  signed field rather than operational discretion". E carries it, with the venue
  it is read on, under evidence tags 0x03 and 0x04 — so a payee can tell a fast
  operator running late from a slow one running on time (`isOverdue`), and a
  grade is read on the venue the backing itself declares. A backing that declares
  neither is answered by whichever record its reader holds, which is a setting
  its backer chose.

A receipt proves **acceptance, not a holding**: a payee who was paid and paid
onward still holds the receipt for what they received. Reading it as a holding
is how a redemption pays a party that has already spent. The durable form of
that line, and the one that decides what may be built on a receipt: **it
attributes an act to the operator, and never proves a value to a holder.** A
chain of receipts back to committed state would prove the value — and it is
provenance, which is precisely what blinding exists to destroy, so it is ruled
out here rather than deferred. See [[DECISIONS.md]].

## Design rules

The invariants above say *what* must be true. These say *how* to build it. The
goal is a reference implementation an auditor can read once and be convinced by:
**smallest, then most secure, then fastest — in that order when they conflict,
except that security never loses to size.**

**One mechanism per property.** If a property is enforced in three places, an
auditor must check three places and a maintainer can break it in three ways.
When a fix is needed, first ask whether an existing mechanism should be
generalized. Never layer a second mechanism on a first to patch its gap: that
is how a review finding becomes permanent complexity. A fix that adds a layer
is a signal the layer below is in the wrong place.

**Bytes are framed, not concatenated.** Every field written into a signed or
hashed message is either fixed-width and asserted to be, or length-prefixed.
Never write a variable-length field raw. Two different values must never
produce one byte string — hashed identity and commitment roots depend on it,
and adjacent unframed fields silently destroy it. Use `ByteWriter.key32` /
`ByteWriter.fixed` for fixed-width fields; they assert the width at the one
place that writes it.

**Validate once, at the boundary that owns the rule.** `makeBacking` owns
backing well-formedness; the ledger owns the law and funds; the sequencer owns
routing and refusal. A layer does not re-check what a layer below will check
anyway, and does not pre-check in order to relabel an error — give the lower
layer a distinguishable error type instead.

**Copy on the way in, copy on the way out.** Bytes entering validated state are
copied once at construction; every accessor returns a copy. `readonly` is
erased at runtime and is not a boundary. This is deliberate cost paid for
invariant 8: no accessor may hand out a write path into state.

**Verifiers never throw.** Anything that answers a question about
adversary-supplied data (`verify*`, `*ProvenBy`, `isEquivocation`, decoders)
returns `false` or a typed rejection on *any* malformed input — wrong lengths,
non-integer positions, out-of-range quantities. A verifier that throws is a
denial-of-service hole and tempts a caller to read "no exception" as "checked".

**But a venue's refusal is not malformed input.** A real venue holds a partial
view and refuses what it was not synced for, and answering `false`, `undefined`
or `"unrelated"` there states a fact about a party built out of not having
looked: an honest operator reads as inauthentic, a punctual successor as silent,
a stolen key as live. So a `VenueError` propagates where everything else is
caught. That is one rule, in one place — `answering` in `src/venue.ts` — because
it was written by hand three times and forgotten four, each time one layer above
the last. `venue-refusal.test.ts` holds every verifier that takes a `Venue` to
it; a new one belongs in that list.

**An error names the boundary that refused.** `EncodingError` = these bytes or
fields are not well-formed. `SigningError` = you asked me to sign with a key
that is not yours. `LedgerError` = the law refuses (`NonceError` = this nonce
is not the signer's next). `SequencerError` = this operator declines to serve
you. `VenueError` = the record will not accept this. Do not add a sixth
without a new boundary to name.

**Domain tags live in one file.** Every context string that separates one
signed message type from another is declared in `src/contexts.ts`. A tag
collision is a signature-forgery class; the full list must be readable on one
screen.

**Efficiency where it is free.** Prefer the direct algorithm over a clever one,
and the allocation-free form over the allocating one, when it is no less
readable — exact-integer arithmetic over string round-trips, one buffer over
per-item allocation, a keyed lookup over a linear scan. Do not trade clarity
for speed anywhere else; this is a reference implementation, not a product.

## Workflow

- **Plan before code.** For each slice: propose the approach, wait for Bob's
  approval, then build.
- **Tests first, named for invariants.** Test files follow
  `invariant-07.issuance-paths.test.ts`. Each test carries a one-line
  plain-language statement of what it checks. Bob reviews the tests; the
  implementation is judged by the tests.
- **Prove it, don't argue it.** A bug is demonstrated by a script that runs the
  exploit, and the fix by that same script failing to exploit it. An argument
  that code is wrong is a hypothesis; only a run settles it. Scratch scripts are
  gitignored root `.mjs` files.
- **Regression-review the fixes.** After fixing review findings, review the
  fixes themselves. Every round so far has found a real bug there, and the
  recurring shape is a fix that bounded one input and left the other open.
- **Explain, don't just produce.** Bob is learning TypeScript and git. When
  asked to explain, walk through the code in plain language. Prefer readable
  code over clever code everywhere.
- **Small commits, one slice per branch.** Run `/code-review` before merging
  to main. Never push without asking.

## Toolchain

Node 24, TypeScript (strict), Vitest.

```
npm test           # run all tests
npm run typecheck  # tsc --noEmit
```
