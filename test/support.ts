import { ed25519 } from "@noble/curves/ed25519.js";
import {
  makeBacking,
  signBacking,
  type Backing,
  type RelianceEntry,
} from "../src/backing.js";
import { TransparentLedger } from "../src/ledger.js";

// Shared fixtures for the claim-layer tests. Every key is a real Ed25519
// point (makeBacking and the ledger reject anything else), and each role has
// a distinct secret so two roles never collide on the per-(signer, backing)
// nonce counter.

export const SECRETS = {
  backer: new Uint8Array(32).fill(0x01),
  backer2: new Uint8Array(32).fill(0x02),
  alice: new Uint8Array(32).fill(0x03),
  bob: new Uint8Array(32).fill(0x04),
  carol: new Uint8Array(32).fill(0x05),
  mallory: new Uint8Array(32).fill(0x06),
  operator: new Uint8Array(32).fill(0x07),
} as const;

export function pub(secret: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secret);
}

export const KEYS = {
  backer: pub(SECRETS.backer),
  backer2: pub(SECRETS.backer2),
  alice: pub(SECRETS.alice),
  bob: pub(SECRETS.bob),
  carol: pub(SECRETS.carol),
  mallory: pub(SECRETS.mallory),
  operator: pub(SECRETS.operator),
} as const;

/** Build a transparent backing obligated by `secret`, paying `thing`. */
export function makeTransparentBacking(
  secret: Uint8Array,
  thing = "EUR",
  reliance: readonly RelianceEntry[] = [],
): Backing {
  return makeBacking({
    obligor: pub(secret),
    payout: { thing, quantumExponent: -2, perUnit: 100n },
    reliance,
    evidence: { setting: "transparent", operator: KEYS.operator },
  });
}

/** Build a backing and register it into `ledger` with the obligor's signature. */
export function register(
  ledger: TransparentLedger,
  secret: Uint8Array,
  thing = "EUR",
  reliance: readonly RelianceEntry[] = [],
): Backing {
  const backing = makeTransparentBacking(secret, thing, reliance);
  ledger.register(backing, signBacking(secret, backing));
  return backing;
}
