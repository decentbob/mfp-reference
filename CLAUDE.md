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
- **Swaps and presentation are idempotent** (inv 26). A repeated request
  returns the identical prior response. A crash must lose nothing. Until the
  sequencer slice, the transparent ledger rejects a replayed message (per
  (signer, backing) nonce) rather than returning the prior response;
  idempotent replay arrives with the sequencer. See [[DECISIONS.md]].
- **Settling a published demand voids the exact claims offered, and only on
  the holder's release signature** (inv 27). A backer must never void
  unilaterally.

Invariants not listed here (3–4, 6, 11–12, 19–25) still bind; several only
become implementable with sequencing and the shielded constructions. Read
§C0 of construction.md before touching anything they govern.

## Workflow

- **Plan before code.** For each slice: propose the approach, wait for Bob's
  approval, then build.
- **Tests first, named for invariants.** Test files follow
  `invariant-07.issuance-paths.test.ts`. Each test carries a one-line
  plain-language statement of what it checks. Bob reviews the tests; the
  implementation is judged by the tests.
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
