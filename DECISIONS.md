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
