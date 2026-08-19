// Presentability (invariant 13): a holding is presentable at b for q iff it
// contains q units of b and q·cᵢ units of each (bᵢ, cᵢ) in R(b).
//
// Units, never claims, so the answer cannot depend on packing. One level, no
// traversal: a reliance target's own reliance is that target's presentation
// problem (invariant 17 keeps the unaccompanied claim inert, never invalid).
//
// **Nothing in src calls this, deliberately.** The single-phase presentation
// §C3 licenses is the case where R is empty, so the ledger enforces invariant 13
// by refusing a demand on a backing that HAS reliance — the presentation whose
// legs it cannot move (applyEntry, ledger.ts). This is the condition itself,
// kept as the definition the legs will be checked against when they land, and
// exercised by its own tests until then. See DECISIONS.md.

import { backingName, type Backing } from "./backing.js";

/** Units held against a backing name. Unknown names hold zero. */
export type HoldingView = (name: Uint8Array) => bigint;

export function presentableFor(view: HoldingView, backing: Backing, quantity: bigint): boolean {
  if (quantity < 1n) return false;
  if (view(backingName(backing)) < quantity) return false;
  for (const entry of backing.reliance) {
    if (view(entry.target) < quantity * entry.count) return false;
  }
  return true;
}
