// Presentability (invariant 13): a holding is presentable at b for q iff it
// contains q units of b and q·cᵢ units of each (bᵢ, cᵢ) in R(b).
//
// Units, never claims, so the answer cannot depend on packing. One level, no
// traversal: a reliance target's own reliance is that target's presentation
// problem (invariant 17 keeps the unaccompanied claim inert, never invalid).

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
