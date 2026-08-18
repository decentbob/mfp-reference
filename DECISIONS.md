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
