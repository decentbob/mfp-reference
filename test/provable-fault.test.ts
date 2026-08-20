import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { signBacking, type Backing } from "../src/backing.js";
import { compareBytes } from "../src/bytes.js";
import { equivocatingSigner, isDoubleAcceptance, isDoublePosition } from "../src/fault.js";
import { encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import { opHashOfEntry, type PublishedOp } from "../src/oplog.js";
import { encodeDemandMessage, encodeReleaseMessage } from "../src/presentation.js";
import { receiptCovers, signReceipt, type Receipt } from "../src/receipt.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { KEYS, makeTransparentBacking, pub, SECRETS } from "./support.js";

// What can be proven, against whom, without trusting anybody.
//
// The system's posture everywhere is that misbehaviour is made PROVABLE rather
// than prevented: invariant 22 makes two roots at one sequence an operator's
// provable fault, §C2b grades silence on facts a stranger can check, and §C3
// makes dishonour "publicly checkable... with nobody reporting anything". That
// posture had a hole: it covered the operator and never the holder.
//
// §C2b's challenge window is where it bites. A claimant who has signed her
// holding away and then redeems the stale snapshot has signed TWO operations at
// one point in her own nonce sequence, and the protocol cannot tell which one
// her dark operator accepted — so it cannot always pay the right party. What it
// can do is name the fault, and these are the predicates that do it:
//
//   - a signer authorised two operations at one nonce (the holder's fault)
//   - an operator co-signed both halves of that (the operator's fault, which is
//     the backer's under the backer-run default)
//   - an operator co-signed two operations into one log position
//
// The last two also catch a botched failover, where two live servers hold one
// operator key: the protocol cannot distinguish that from malice, and treats it
// the same way it treats a self-framing commitment equivocation.
//
// Every one is a verifier over adversary-supplied bytes, so none of them throws.

function op(kind: "transfer" | "demand", secret: Uint8Array, backing: Backing, opts: {
  to?: Uint8Array;
  quantity?: bigint;
  nonce: bigint;
}): PublishedOp {
  const quantity = opts.quantity ?? 100n;
  if (kind === "transfer") {
    const to = opts.to as Uint8Array;
    const message = encodeTransferMessage(backing.name, pub(secret), to, quantity, opts.nonce);
    return {
      kind: "transfer",
      from: pub(secret),
      to,
      quantity,
      nonce: opts.nonce,
      signature: ed25519.sign(message, secret),
    };
  }
  const message = encodeDemandMessage(backing.name, pub(secret), quantity, 0n, 40n, opts.nonce);
  return {
    kind: "demand",
    holder: pub(secret),
    quantity,
    instant: 0n,
    deadline: 40n,
    nonce: opts.nonce,
    signature: ed25519.sign(message, secret),
  };
}

function issueOp(backing: Backing, recipient: Uint8Array, quantity: bigint, nonce: bigint): PublishedOp {
  const message = encodeIssuanceMessage(backing.name, recipient, quantity, nonce);
  return { kind: "issue", recipient, quantity, nonce, signature: ed25519.sign(message, SECRETS.backer) };
}

const backing = makeTransparentBacking(SECRETS.backer);

describe("a signer who authorised two operations at one nonce", () => {
  it("names the claimant who redeemed a holding she had signed away", () => {
    // §C2b's case: Alice pays Bob at nonce 0, then files a redemption claim at
    // nonce 0. Bob holds one signature, the venue carries the other.
    const spend = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const claim = op("demand", SECRETS.alice, backing, { nonce: 0n });
    const at = equivocatingSigner(backing, spend, claim);
    expect(at).toBeDefined();
    expect(compareBytes(at as Uint8Array, KEYS.alice)).toBe(0);
  });

  it("is not evaded by paying a key made up for the purpose", () => {
    // The proof names the key that SIGNED both, and a fresh payee key changes
    // nothing about that — which is the whole point, since keys are free.
    const alice2 = pub(new Uint8Array(32).fill(0x09));
    const a = op("transfer", SECRETS.alice, backing, { to: alice2, nonce: 0n });
    const b = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    expect(compareBytes(equivocatingSigner(backing, a, b) as Uint8Array, KEYS.alice)).toBe(0);
  });

  it("names the obligor for two issuances at one nonce", () => {
    // The signer comes from the terms, so the fault is not the holder's alone.
    const a = issueOp(backing, KEYS.alice, 100n, 0n);
    const b = issueOp(backing, KEYS.bob, 100n, 0n);
    expect(compareBytes(equivocatingSigner(backing, a, b) as Uint8Array, KEYS.backer)).toBe(0);
  });

  it("is not a resubmission: the identical operation twice is no fault", () => {
    // Invariant 26 exists so a repeat is safe. Equivocation is two DIFFERENT
    // operations, never one sent twice.
    const spend = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    expect(equivocatingSigner(backing, spend, { ...spend })).toBeUndefined();
  });

  it("refuses two operations at different nonces", () => {
    const a = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const b = op("transfer", SECRETS.alice, backing, { to: KEYS.carol, nonce: 1n });
    expect(equivocatingSigner(backing, a, b)).toBeUndefined();
  });

  it("refuses two operations by different signers at one nonce", () => {
    // Nonces are per (signer, backing), so one nonce shared by two signers is
    // ordinary rather than a fault.
    const a = op("transfer", SECRETS.alice, backing, { to: KEYS.carol, nonce: 0n });
    const b = op("transfer", SECRETS.bob, backing, { to: KEYS.carol, nonce: 0n });
    expect(equivocatingSigner(backing, a, b)).toBeUndefined();
  });

  it("refuses an operation whose signature does not verify", () => {
    // Nobody is framed by bytes anyone could have written.
    const a = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const forged = op("demand", SECRETS.mallory, backing, { nonce: 0n });
    const framed: PublishedOp = { ...forged, holder: KEYS.alice } as PublishedOp;
    expect(equivocatingSigner(backing, a, framed)).toBeUndefined();
  });

  it("refuses a release or withdrawal, whose signer is not in the operation", () => {
    // The law reads their signer from the demand they name, so proving one
    // needs that demand too. Asserting the signer instead would let an accuser
    // choose who is at fault.
    const spend = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const message = encodeReleaseMessage(backing.name, sha256(new Uint8Array(1)), 0n);
    const release: PublishedOp = {
      kind: "release",
      demandHash: sha256(new Uint8Array(1)),
      nonce: 0n,
      signature: ed25519.sign(message, SECRETS.alice),
    };
    expect(equivocatingSigner(backing, spend, release)).toBeUndefined();
  });

  it("refuses operations naming a different backing", () => {
    const other = makeTransparentBacking(SECRETS.backer, "USD");
    const a = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const b = op("transfer", SECRETS.alice, other, { to: KEYS.carol, nonce: 0n });
    expect(equivocatingSigner(backing, a, b)).toBeUndefined();
  });

  it("never throws on malformed operations", () => {
    const spend = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const broken = { ...spend, to: new Uint8Array(3) } as PublishedOp;
    expect(() => equivocatingSigner(backing, spend, broken)).not.toThrow();
    expect(equivocatingSigner(backing, spend, broken)).toBeUndefined();
  });
});

describe("an operator that co-signed a history one nonce cannot hold", () => {
  /**
   * Two live servers holding one operator key — a failover with no leader
   * election, which is also exactly what collusion looks like from outside.
   * Each takes one of Alice's two spends at nonce 0 and co-signs it.
   */
  function splitBrain() {
    const venue = new Venue();
    const one = new Sequencer(SECRETS.operator, venue);
    const two = new Sequencer(SECRETS.operator, venue);
    const alice2 = pub(new Uint8Array(32).fill(0x09));
    for (const server of [one, two]) {
      server.register(backing, signBacking(SECRETS.backer, backing));
      server.submitIssue(
        { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n },
        ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
      );
    }
    const toBob = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 100n, nonce: 0n };
    const toAlice2 = { backing, from: KEYS.alice, to: alice2, quantity: 100n, nonce: 0n };
    return {
      a: {
        op: op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n }),
        receipt: one.submitTransfer(
          toBob,
          ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 100n, 0n), SECRETS.alice),
        ),
      },
      b: {
        op: op("transfer", SECRETS.alice, backing, { to: alice2, nonce: 0n }),
        receipt: two.submitTransfer(
          toAlice2,
          ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, alice2, 100n, 0n), SECRETS.alice),
        ),
      },
      venue,
    };
  }

  it("proves the operator accepted both halves of the claimant's equivocation", () => {
    const { a, b, venue } = splitBrain();
    expect(isDoubleAcceptance(backing, venue, a, b)).toBe(true);
  });

  it("proves it whichever order the two are exhibited in", () => {
    const { a, b, venue } = splitBrain();
    expect(isDoubleAcceptance(backing, venue, b, a)).toBe(true);
  });

  it("proves the same servers put two operations at one log position", () => {
    // The narrower fault, and it needs no operations at all: one operator, one
    // backing, one position, two operation hashes.
    const { a, b, venue } = splitBrain();
    expect(a.receipt.position).toBe(b.receipt.position);
    expect(isDoublePosition(backing, venue, a.receipt, b.receipt)).toBe(true);
  });

  it("refuses a receipt paired with an operation it does not cover", () => {
    // Or anyone could pin any operator's signature to any operation.
    const { a, b, venue } = splitBrain();
    expect(isDoubleAcceptance(backing, venue, { op: b.op, receipt: a.receipt }, b)).toBe(false);
  });

  it("refuses receipts the operator issued on another backing", () => {
    // One operator serves many backings (§C2), and an operation object carries
    // no backing name — the name comes from whoever encodes it. So a receipt
    // from a DIFFERENT backing covers the operation just as well, and pairing
    // one with an equivocation here accuses an operator that did nothing.
    const venue = new Venue();
    const server = new Sequencer(SECRETS.operator, venue);
    const other = makeTransparentBacking(SECRETS.backer, "USD");
    for (const b of [backing, other]) {
      server.register(b, signBacking(SECRETS.backer, b));
      server.submitIssue(
        { backing: b, recipient: KEYS.alice, quantity: 100n, nonce: 0n },
        ed25519.sign(encodeIssuanceMessage(b.name, KEYS.alice, 100n, 0n), SECRETS.backer),
      );
    }
    const alice2 = pub(new Uint8Array(32).fill(0x09));
    // Alice equivocates on `backing`; the operator correctly takes only one.
    const toBob = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const toAlice2 = op("transfer", SECRETS.alice, backing, { to: alice2, nonce: 0n });
    const here = server.submitTransfer(
      { backing, from: KEYS.alice, to: KEYS.bob, quantity: 100n, nonce: 0n },
      ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 100n, 0n), SECRETS.alice),
    );
    // And makes an ordinary, honest payment on the other backing.
    const elsewhere = server.submitTransfer(
      { backing: other, from: KEYS.alice, to: alice2, quantity: 100n, nonce: 0n },
      ed25519.sign(encodeTransferMessage(other.name, KEYS.alice, alice2, 100n, 0n), SECRETS.alice),
    );

    expect(equivocatingSigner(backing, toBob, toAlice2)).toBeDefined();
    expect(
      isDoubleAcceptance(backing, venue, { op: toBob, receipt: here }, { op: toAlice2, receipt: elsewhere }),
    ).toBe(false);
  });

  it("refuses receipts signed by a key E does not name as the operator", () => {
    // "The operator is at fault" is what a caller reads off these, so the key
    // has to be the one the backing declares. A stranger co-signing both halves
    // of a real equivocation has framed nobody but themselves, and must not
    // read as a fault against the operator of this backing.
    const { venue } = splitBrain();
    const alice2 = pub(new Uint8Array(32).fill(0x09));
    const a = op("transfer", SECRETS.alice, backing, { to: KEYS.bob, nonce: 0n });
    const b = op("transfer", SECRETS.alice, backing, { to: alice2, nonce: 0n });
    const ra = signReceipt(SECRETS.mallory, backing.name, opHashOfEntry(backing.name, a), 1n);
    const rb = signReceipt(SECRETS.mallory, backing.name, opHashOfEntry(backing.name, b), 1n);

    expect(equivocatingSigner(backing, a, b)).toBeDefined();
    expect(isDoubleAcceptance(backing, venue, { op: a, receipt: ra }, { op: b, receipt: rb })).toBe(false);
    expect(isDoublePosition(backing, venue, ra, rb)).toBe(false);
  });

  it("refuses two receipts by different operators", () => {
    const { a, b, venue } = splitBrain();
    const stranger = signReceipt(SECRETS.mallory, backing.name, b.receipt.opHash, b.receipt.position);
    expect(isDoubleAcceptance(backing, venue, a, { op: b.op, receipt: stranger })).toBe(false);
    expect(isDoublePosition(backing, venue, a.receipt, stranger)).toBe(false);
  });

  it("refuses operations that are not an equivocation", () => {
    // An honest operator co-signs many operations; only a conflicting pair is
    // a fault, and that judgement is the signer predicate's, not a second one.
    const venue = new Venue();
    const server = new Sequencer(SECRETS.operator, venue);
    server.register(backing, signBacking(SECRETS.backer, backing));
    const issue = { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n };
    const first = server.submitIssue(
      issue,
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
    );
    const transfer = { backing, from: KEYS.alice, to: KEYS.bob, quantity: 30n, nonce: 0n };
    const second = server.submitTransfer(
      transfer,
      ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 30n, 0n), SECRETS.alice),
    );
    const a = { op: issueOp(backing, KEYS.alice, 100n, 0n), receipt: first };
    const b = { op: op("transfer", SECRETS.alice, backing, { to: KEYS.bob, quantity: 30n, nonce: 0n }), receipt: second };
    expect(isDoubleAcceptance(backing, venue, a, b)).toBe(false);
    expect(isDoublePosition(backing, venue, a.receipt, b.receipt)).toBe(false);
  });

  it("refuses a receipt whose signature does not verify", () => {
    const { a, b, venue } = splitBrain();
    const torn: Receipt = { ...b.receipt, signature: new Uint8Array(64) };
    expect(isDoubleAcceptance(backing, venue, a, { op: b.op, receipt: torn })).toBe(false);
    expect(isDoublePosition(backing, venue, a.receipt, torn)).toBe(false);
  });

  it("refuses one receipt exhibited against itself", () => {
    const { a, venue } = splitBrain();
    expect(isDoubleAcceptance(backing, venue, a, { ...a })).toBe(false);
    expect(isDoublePosition(backing, venue, a.receipt, { ...a.receipt })).toBe(false);
  });

  it("never throws on malformed receipts", () => {
    const { a, b, venue } = splitBrain();
    const broken: Receipt = { ...b.receipt, opHash: new Uint8Array(2) };
    expect(() => isDoubleAcceptance(backing, venue, a, { op: b.op, receipt: broken })).not.toThrow();
    expect(() => isDoublePosition(backing, venue, a.receipt, broken)).not.toThrow();
    expect(isDoublePosition(backing, venue, a.receipt, broken)).toBe(false);
  });
});

describe("a receipt covers exactly one operation", () => {
  function accepted() {
    const venue = new Venue();
    const server = new Sequencer(SECRETS.operator, venue);
    server.register(backing, signBacking(SECRETS.backer, backing));
    const receipt = server.submitIssue(
      { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
    );
    return { receipt, op: issueOp(backing, KEYS.alice, 100n, 0n) };
  }

  it("holds for the operation the sequencer accepted", () => {
    const { receipt, op: accepted_ } = accepted();
    expect(receiptCovers(backing.name, accepted_, receipt)).toBe(true);
  });

  it("fails for a different operation", () => {
    const { receipt } = accepted();
    expect(receiptCovers(backing.name, issueOp(backing, KEYS.bob, 100n, 0n), receipt)).toBe(false);
  });

  it("fails where the receipt names another backing", () => {
    const { receipt, op: accepted_ } = accepted();
    const other = makeTransparentBacking(SECRETS.backer, "USD");
    const elsewhere = signReceipt(SECRETS.operator, other.name, receipt.opHash, receipt.position);
    expect(receiptCovers(backing.name, accepted_, elsewhere)).toBe(false);
    // And the operation it really does cover is still refused against the
    // backing the caller asked about.
    expect(receiptCovers(other.name, accepted_, elsewhere)).toBe(false);
  });

  it("fails on an invalid operator signature", () => {
    const { receipt, op: accepted_ } = accepted();
    expect(receiptCovers(backing.name, accepted_, { ...receipt, signature: new Uint8Array(64) })).toBe(false);
  });

  it("never throws on malformed input", () => {
    const { receipt } = accepted();
    const broken = { ...receipt, backingName: new Uint8Array(1) };
    expect(() => receiptCovers(backing.name, issueOp(backing, KEYS.alice, 100n, 0n), broken)).not.toThrow();
    expect(receiptCovers(backing.name, issueOp(backing, KEYS.alice, 100n, 0n), broken)).toBe(false);
  });
});
