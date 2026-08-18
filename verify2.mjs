import { ed25519 } from "@noble/curves/ed25519.js";
import { makeBacking, signBacking } from "./src/backing.ts";
import { LedgerError, TransparentLedger } from "./src/ledger.ts";
import { encodeIssuance, encodeTransfer } from "./src/messages.ts";

const BACKER_SECRET = new Uint8Array(32).fill(0x01);
const ALICE_SECRET = new Uint8Array(32).fill(0x03);
const BACKER = ed25519.getPublicKey(BACKER_SECRET);
const ALICE = ed25519.getPublicKey(ALICE_SECRET);
const OPERATOR = new Uint8Array(32).fill(0x22);

function setup(thing = "EUR") {
  const backing = makeBacking({
    obligor: BACKER,
    payout: { thing, quantumExponent: -2, perUnit: 100n },
    reliance: [],
    evidence: { setting: "transparent", operator: OPERATOR },
  });
  const ledger = new TransparentLedger();
  ledger.register(backing, signBacking(BACKER_SECRET, backing));
  return { ledger, backing };
}

// 1. Live-map mutation: mint units with no signature via balancesOf.
{
  const { ledger, backing } = setup();
  ledger.balancesOf(backing).set(Buffer.from(ALICE).toString("hex"), 10n ** 9n);
  const held = ledger.balance(backing, ALICE);
  console.log("1 LIVE-MAP MINT: alice holds", held, "with