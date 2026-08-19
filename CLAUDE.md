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
  R(b). Units, never claims. One level, no traversal. Quantities are whole
  numbers of the backing's declared unit; counts in R are whole. Reliance is
  a conjunction over a fixed list with constant counts — no disjunction, no
  computed membership. Reliance names backings and chain assets only.
- **`closure(S)` expands deterministically before hashing**; counts sum where
  paths meet; the stored object is flat; cap closure size (inv 16).
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
