import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { signBacking, type Backing } from "../src/backing.js";
import { compareBytes } from "../src/bytes.js";
import { isDishonoured } from "../src/ledger.js";
import { encodeBurnMessage, encodeIssuanceMessage, encodeTransferMessage } from "../src/messages.js";
import { type PublishedOp } from "../src/oplog.js";
import {
  encodeAcceptanceMessage,
  encodeDemandMessage,
  encodeReleaseMessage,
  encodeWithdrawalMessage,
} from "../src/presentation.js";
import { receiptProvenBy, verifyReceipt } from "../src/receipt.js";
import { isSilent, snapshotRedemptions, type ServedState } from "../src/recovery.js";
import { Sequencer } from "../src/sequencer.js";
import { Venue } from "../src/venue.js";
import { advanceWitnessedIndex, KEYS, makeTransparentBacking, pub, SECRETS } from "./support.js";

// §C2b's payment path: the claim, acceptance and release legs, the challenge
// window, and a returning sequencer adopting what was witnessed during the gap.
//
//   "Snapshot redemption publishes the claim's nullifier at the witness venue
//   as the release leg, after the backer's acceptance, and a sequencer
//   returning from silence adopts every nullifier witnessed during the gap
//   before co-signing again. A snapshot redemption also stands for a declared
//   challenge window, during which anyone may publish at the venue the
//   holder-signed transfer request that spent the named claim. On publication
//   the redemption pays the request's presenter instead... Under transparent, a
//   signed spend record published at the venue, checked against the last
//   committed balance state, stands in for the nullifier."
//
// So redemption is not a second protocol. It is §C3's demand-accept-release
// with the legs published at the venue instead of submitted to the dark
// sequencer, and under transparent a signed spend record IS an operation-log
// entry. One law, one replay, one nonce sequence: the legs are ordinary
// operations, applied through the same applyEntry, and adoption is appending
// them in the order the venue witnessed them.
//
// The clock every leg is judged against is the index the VENUE stamped it with
// — the venue's word, never the operator's — so no leg needs an operator to
// assert when it happened. See DECISIONS.md.

const SILENCE = { noCommitmentDuration: 10n, challengeWindow: 5n };

function setup(quantity = 100n) {
  const venue = new Venue();
  const sequencer = new Sequencer(SECRETS.operator, venue);
  const backing = makeTransparentBacking(SECRETS.backer, "EUR", [], SILENCE);
  sequencer.register(backing, signBacking(SECRETS.backer, backing));
  const issue = { backing, recipient: KEYS.alice, quantity, nonce: 0n };
  sequencer.submitIssue(issue, ed25519.sign(encodeIssuanceMessage(
    backing.name, KEYS.alice, quantity, 0n), SECRETS.backer));
  return { venue, sequencer, backing };
}

/** Commit the state a redemption runs against, then let the silence elapse. */
function goDark(venue: Venue, sequencer: Sequencer): ServedState {
  const snapshots = sequencer.snapshot();
  const commitment = sequencer.commit();
  venue.advance(SILENCE.noCommitmentDuration + 1n);
  return { snapshots, commitment };
}

// The four legs and the challenge, as signed operations. Each is exactly what
// the sequencer would have been handed; the only difference is where it is put.

function demand(
  backing: Backing,
  secret: Uint8Array,
  holder: Uint8Array,
  quantity: bigint,
  instant: bigint,
  deadline: bigint,
  nonce: bigint,
): { op: PublishedOp; hash: Uint8Array; signature: Uint8Array } {
  const message = encodeDemandMessage(backing.name, holder, quantity, instant, deadline, nonce);
  const signature = ed25519.sign(message, secret);
  return {
    op: { kind: "demand", holder, quantity, instant, deadline, nonce, signature },
    hash: sha256(message),
    signature,
  };
}

function acceptance(
  backing: Backing,
  secret: Uint8Array,
  demandHash: Uint8Array,
  instant: bigint,
  deadline: bigint,
  nonce: bigint,
): PublishedOp {
  const message = encodeAcceptanceMessage(backing.name, demandHash, instant, deadline, nonce);
  return { kind: "acceptance", demandHash, instant, deadline, nonce, signature: ed25519.sign(message, secret) };
}

function release(
  backing: Backing,
  secret: Uint8Array,
  demandHash: Uint8Array,
  nonce: bigint,
): PublishedOp {
  const message = encodeReleaseMessage(backing.name, demandHash, nonce);
  return { kind: "release", demandHash, nonce, signature: ed25519.sign(message, secret) };
}

function withdrawal(
  backing: Backing,
  secret: Uint8Array,
  demandHash: Uint8Array,
  nonce: bigint,
): PublishedOp {
  const message = encodeWithdrawalMessage(backing.name, demandHash, nonce);
  return { kind: "withdrawal", demandHash, nonce, signature: ed25519.sign(message, secret) };
}

function transfer(
  backing: Backing,
  secret: Uint8Array,
  from: Uint8Array,
  to: Uint8Array,
  quantity: bigint,
  nonce: bigint,
): PublishedOp {
  const message = encodeTransferMessage(backing.name, from, to, quantity, nonce);
  return { kind: "transfer", from, to, quantity, nonce, signature: ed25519.sign(message, secret) };
}

/** The `to` key of a transfer, for the tests that only care about the payee. */
function payeeOf(op: PublishedOp): Uint8Array {
  if (op.kind !== "transfer") throw new Error("not a transfer");
  return op.to;
}

/** Publish an operation at the venue at exactly witnessed index `at`. */
function publishAt(venue: Venue, at: bigint, backing: Backing, op: PublishedOp): void {
  advanceWitnessedIndex(venue, at);
  venue.publishOp(backing.name, op);
}

/**
 * The whole happy path: Alice claims, the backer answers, Alice releases — all
 * at the venue, while the operator is dark. Indices 11/12/13, so the challenge
 * window (5) closes at 18.
 */
function redeemAtVenue(venue: Venue, backing: Backing, quantity = 100n) {
  const claim = demand(backing, SECRETS.alice, KEYS.alice, quantity, 11n, 40n, 0n);
  publishAt(venue, 11n, backing, claim.op);
  publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 40n, 1n));
  publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
  return claim;
}

describe("§C2b: the legs are ordinary operations, published at the venue", () => {
  it("settles a claim the dark operator never saw, and pays the claimant", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = redeemAtVenue(venue, backing);

    const redemptions = snapshotRedemptions(venue, backing, served);
    expect(redemptions).toHaveLength(1);
    const redemption = redemptions[0]!;
    expect(compareBytes(redemption.demandHash, claim.hash)).toBe(0);
    expect(redemption.quantity).toBe(100n);
    expect(redemption.payments).toHaveLength(1);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.alice)).toBe(0);
    expect(redemption.payments[0]!.quantity).toBe(100n);
  });

  it("opens no redemption without the release leg — a demand alone pays nothing", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 40n, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("refuses a release the backer never answered — settlement still takes two signatures", () => {
    // Invariant 27 does not weaken because the operator is dark.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("ignores a leg signed by anyone but the party the law names", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.mallory, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("ignores a claim for more than the snapshot shows the claimant holding", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 101n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });
});

describe("§C2b: the venue's stamp is the clock every leg is judged against", () => {
  it("gives no force to a leg published before the silence — 'during the gap'", () => {
    // The venue path is not a second sequencer. While the operator is serving,
    // publishing a leg at the venue does nothing at all.
    const { venue, sequencer, backing } = setup();
    const snapshots = sequencer.snapshot();
    const commitment = sequencer.commit();
    const served = { snapshots, commitment };
    // Only three indices quiet: the declared duration is ten.
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 1n, 40n, 0n);
    publishAt(venue, 1n, backing, claim.op);
    publishAt(venue, 2n, backing, acceptance(backing, SECRETS.backer, claim.hash, 1n, 40n, 1n));
    publishAt(venue, 3n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("refuses a claim whose instant is later than the index that witnessed it", () => {
    // Invariant 24, checked against the venue's own stamp rather than against
    // anything the operator asserts.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 12n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 12n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("gives a silent operator no veto by committing at the index a leg appears", () => {
    // The venue witnesses both at one index, so neither precedes the other. Let
    // the commitment win that tie and an operator watching the venue strips the
    // force from any leg it does not like, at the cost of one commitment.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    sequencer.commit();
    expect(venue.witnessedAtFor(sequencer.operator)).toBe(13n);

    const redemptions = snapshotRedemptions(venue, backing, served);
    expect(redemptions).toHaveLength(1);
    expect(redemptions[0]!.releasedAt).toBe(13n);
  });

  it("refuses a release published after the acceptance it names has expired", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 20n, 1n));
    publishAt(venue, 21n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("refuses an acceptance that would outlast the holder's own deadline", () => {
    // The window is the holder's: a dark operator does not hand the backer the
    // right to set the standard its own failure is measured by.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 41n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });
});

describe("§C2b: a standing demand is continued, not blocked", () => {
  it("answers and releases at the venue a demand filed before the operator went dark", () => {
    // This is §C2b read literally: "publishes the claim's nullifier at the
    // witness venue as the release leg, after the backer's acceptance". The
    // claim leg already happened, at the sequencer.
    const { venue, sequencer, backing } = setup();
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 0n, 40n, 0n);
    sequencer.submitDemand(
      { backing, holder: KEYS.alice, quantity: 100n, instant: 0n, deadline: 40n, nonce: 0n },
      claim.signature,
    );
    const served = goDark(venue, sequencer);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 0n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));

    const redemptions = snapshotRedemptions(venue, backing, served);
    expect(redemptions).toHaveLength(1);
    expect(compareBytes(redemptions[0]!.payments[0]!.payee, KEYS.alice)).toBe(0);
    expect(redemptions[0]!.payments[0]!.quantity).toBe(100n);
  });

  it("refuses a second claim over units a standing demand already commits", () => {
    // The answer to 'does a standing demand block redemption' needs no new
    // rule: a demand needs SPENDABLE units, held minus committed, and that is
    // the law wherever it is applied.
    const { venue, sequencer, backing } = setup();
    const first = demand(backing, SECRETS.alice, KEYS.alice, 100n, 0n, 40n, 0n);
    sequencer.submitDemand(
      { backing, holder: KEYS.alice, quantity: 100n, instant: 0n, deadline: 40n, nonce: 0n },
      first.signature,
    );
    const served = goDark(venue, sequencer);
    const second = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 1n);
    publishAt(venue, 11n, backing, second.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, second.hash, 11n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, second.hash, 2n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("redeems only the units no demand commits, and leaves the rest to their own demand", () => {
    const { venue, sequencer, backing } = setup();
    const first = demand(backing, SECRETS.alice, KEYS.alice, 60n, 0n, 40n, 0n);
    sequencer.submitDemand(
      { backing, holder: KEYS.alice, quantity: 60n, instant: 0n, deadline: 40n, nonce: 0n },
      first.signature,
    );
    const served = goDark(venue, sequencer);
    const second = demand(backing, SECRETS.alice, KEYS.alice, 40n, 11n, 40n, 1n);
    publishAt(venue, 11n, backing, second.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, second.hash, 11n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, second.hash, 2n));

    const redemptions = snapshotRedemptions(venue, backing, served);
    expect(redemptions).toHaveLength(1);
    expect(redemptions[0]!.quantity).toBe(40n);
  });

  it("lets the holder withdraw at the venue and keep the units", () => {
    const { venue, sequencer, backing } = setup();
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 0n, 40n, 0n);
    sequencer.submitDemand(
      { backing, holder: KEYS.alice, quantity: 100n, instant: 0n, deadline: 40n, nonce: 0n },
      claim.signature,
    );
    goDark(venue, sequencer);
    publishAt(venue, 11n, backing, withdrawal(backing, SECRETS.alice, claim.hash, 1n));
    sequencer.adopt(backing);
    expect(sequencer.openDemands(backing)).toHaveLength(0);
    expect(sequencer.availableBalance(backing, KEYS.alice)).toBe(100n);
  });
});

describe("§C2b: the challenge window substitutes the payee, and voids nothing", () => {
  /** Alice signed a transfer the dark operator never committed. Bob holds it. */
  function challengeOf(backing: Backing, quantity: bigint, nonce = 0n): PublishedOp {
    return transfer(backing, SECRETS.alice, KEYS.alice, KEYS.bob, quantity, nonce);
  }

  it("pays the payee named in the request, for the whole claim", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, challengeOf(backing, 100n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments).toHaveLength(1);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(redemption.payments[0]!.quantity).toBe(100n);
  });

  it("does not void the redemption: the claim still settles and the units still move", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, challengeOf(backing, 100n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(compareBytes(redemption.demandHash, claim.hash)).toBe(0);
    expect(redemption.quantity).toBe(100n);
    const paid = redemption.payments.reduce((sum, p) => sum + p.quantity, 0n);
    expect(paid).toBe(100n);
    // And the claim layer settles exactly as it would have without a challenge.
    sequencer.adopt(backing);
    expect(sequencer.balance(backing, KEYS.alice)).toBe(0n);
    expect(sequencer.balance(backing, KEYS.backer)).toBe(100n);
  });

  it("splits the payment where the request spent only part of the claim", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, challengeOf(backing, 30n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments).toHaveLength(2);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(redemption.payments[0]!.quantity).toBe(30n);
    expect(compareBytes(redemption.payments[1]!.payee, KEYS.alice)).toBe(0);
    expect(redemption.payments[1]!.quantity).toBe(70n);
  });

  it("caps the substitution at the claim, where the request spent more than was claimed", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing, 60n);
    publishAt(venue, 15n, backing, challengeOf(backing, 100n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments).toHaveLength(1);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(redemption.payments[0]!.quantity).toBe(60n);
  });

  it("hears a challenge on the last index of the window and not the one after", () => {
    // Released at 13, window 5, so 18 is heard and 19 is not.
    for (const [at, payee] of [
      [18n, KEYS.bob],
      [19n, KEYS.alice],
    ] as const) {
      const { venue, sequencer, backing } = setup();
      const served = goDark(venue, sequencer);
      redeemAtVenue(venue, backing);
      publishAt(venue, at, backing, challengeOf(backing, 100n));
      const redemption = snapshotRedemptions(venue, backing, served)[0]!;
      expect(compareBytes(redemption.payments[0]!.payee, payee)).toBe(0);
    }
  });

  it("hears a challenge published before the release as well as after it", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, challengeOf(backing, 100n));
    publishAt(venue, 13n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 40n, 1n));
    publishAt(venue, 14n, backing, release(backing, SECRETS.alice, claim.hash, 1n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
  });

  it("ignores a request at a nonce the claim did not use", () => {
    // The claim leg and the spend it conflicts with sit at ONE point in the
    // holder's sequence. A request anywhere else is not a spend of this claim.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, challengeOf(backing, 100n, 5n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.alice)).toBe(0);
  });

  it("ignores a request the claimant did not sign", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(
      venue,
      15n,
      backing,
      transfer(backing, SECRETS.mallory, KEYS.alice, KEYS.mallory, 100n, 0n),
    );

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.alice)).toBe(0);
  });

  it("ignores a request that moves someone else's units", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, transfer(backing, SECRETS.bob, KEYS.bob, KEYS.bob, 100n, 0n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.alice)).toBe(0);
  });

  it("takes the earliest witnessed request where the claimant signed two", () => {
    // Two conflicting requests at one nonce is the claimant equivocating.
    // Witnessing pins order, which is the venue's whole job (§C2).
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, transfer(backing, SECRETS.alice, KEYS.alice, KEYS.carol, 100n, 0n));
    publishAt(venue, 16n, backing, challengeOf(backing, 100n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments).toHaveLength(1);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.carol)).toBe(0);
  });

  it("ignores a request the snapshot could never have served", () => {
    // Otherwise a claimant redirects their own redemption at will: sign a
    // transfer for units they never held, exhibit it, and the payment goes
    // wherever they chose. A request the operator would have REFUSED spent
    // nothing, so it is not evidence that anything was spent.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, challengeOf(backing, 101n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments).toHaveLength(1);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.alice)).toBe(0);
  });

  it("hears a challenge after the operator has returned, while the window stands", () => {
    // The window is a declared period, not a property of the gap. Shut it when
    // the operator returns and an operator that comes back promptly hands the
    // double-spender the money — and under backer-run it is the backer's own
    // operator deciding how long anyone gets to object.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    advanceWitnessedIndex(venue, 14n);
    sequencer.commit();
    publishAt(venue, 15n, backing, challengeOf(backing, 100n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(redemption.payments[0]!.quantity).toBe(100n);
  });

  it("pays every payee the claimant spent to, not only the first", () => {
    // The operator served two of Alice's spends and committed neither. Hear
    // only the first and the second payee's units are paid to the claimant who
    // signed them away.
    const { venue, sequencer, backing } = setup();
    const served = { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
    for (const [to, quantity, nonce] of [
      [KEYS.bob, 30n, 0n],
      [KEYS.carol, 20n, 1n],
    ] as const) {
      sequencer.submitTransfer(
        { backing, from: KEYS.alice, to, quantity, nonce },
        ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, to, quantity, nonce), SECRETS.alice),
      );
    }
    venue.advance(SILENCE.noCommitmentDuration + 1n);
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, challengeOf(backing, 30n, 0n));
    publishAt(venue, 16n, backing, transfer(backing, SECRETS.alice, KEYS.alice, KEYS.carol, 20n, 1n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments.map((p) => p.quantity)).toEqual([30n, 20n, 50n]);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(compareBytes(redemption.payments[1]!.payee, KEYS.carol)).toBe(0);
    expect(compareBytes(redemption.payments[2]!.payee, KEYS.alice)).toBe(0);
  });

  it("reads a request that pays the claimant as no evidence of a spend", () => {
    // It moved nothing away from them. Folded it would consume the contested
    // nonce and leave every genuine request behind it finding that nonce spent.
    //
    // This is NOT a defence against a claimant who pre-empts — see the test
    // below, which is the same attack with a key made up for the purpose.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    publishAt(venue, 14n, backing, transfer(backing, SECRETS.alice, KEYS.alice, KEYS.alice, 100n, 0n));
    publishAt(venue, 15n, backing, challengeOf(backing, 100n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments).toHaveLength(1);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(redemption.payments[0]!.quantity).toBe(100n);
  });

  it("OPEN: a claimant who publishes first still picks who is paid", () => {
    // Pinning a hole, not a property. The claimant knows about her own
    // double-spend before her payee does, so she reaches the venue first with a
    // transfer to a key she generated for the purpose — nothing about her is
    // scarce — and the genuine request behind it finds the nonce spent.
    //
    // It is the reach of §C2b's rule rather than a defect in implementing it:
    // where a double-signature is resolved by publication order, the party who
    // signed both knows first. Closing it needs evidence of which signature the
    // operator actually served, which is its receipt. **When that lands, this
    // test should fail and be rewritten to expect bob.** See DECISIONS.md.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const alice2 = pub(new Uint8Array(32).fill(0x09));
    publishAt(venue, 11n, backing, transfer(backing, SECRETS.alice, KEYS.alice, alice2, 100n, 0n));
    redeemAtVenue(venue, backing);
    publishAt(venue, 15n, backing, challengeOf(backing, 100n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(compareBytes(redemption.payments[0]!.payee, alice2)).toBe(0);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).not.toBe(0);
  });

  it("hears the claimant's spends in sequence order, however they were published", () => {
    // Publication order across DIFFERENT nonces is whoever got to the venue
    // first, and must not decide who is paid. Only two requests at ONE nonce
    // are a race, and there the earlier witnessed one wins.
    const { venue, sequencer, backing } = setup();
    const served = { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
    for (const [to, quantity, nonce] of [
      [KEYS.bob, 30n, 0n],
      [KEYS.carol, 20n, 1n],
    ] as const) {
      sequencer.submitTransfer(
        { backing, from: KEYS.alice, to, quantity, nonce },
        ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, to, quantity, nonce), SECRETS.alice),
      );
    }
    venue.advance(SILENCE.noCommitmentDuration + 1n);
    redeemAtVenue(venue, backing);
    // Carol gets to the venue first, with the LATER nonce.
    publishAt(venue, 15n, backing, transfer(backing, SECRETS.alice, KEYS.alice, KEYS.carol, 20n, 1n));
    publishAt(venue, 16n, backing, challengeOf(backing, 30n, 0n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments.map((p) => p.quantity)).toEqual([30n, 20n, 50n]);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(compareBytes(redemption.payments[1]!.payee, KEYS.carol)).toBe(0);
  });

  it("does not let a spend of the claimant's OTHER units redirect the payment", () => {
    // Alice has 100, commits 60 to a demand before the darkness, and signs the
    // free 40 away during it. Those 40 are not the demanded units — the lock
    // saw to that — so exhibiting the transfer must not take 40 of her 60.
    const { venue, sequencer, backing } = setup();
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 60n, 0n, 40n, 0n);
    sequencer.submitDemand(
      { backing, holder: KEYS.alice, quantity: 60n, instant: 0n, deadline: 40n, nonce: 0n },
      claim.signature,
    );
    const served = goDark(venue, sequencer);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 0n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    publishAt(venue, 15n, backing, challengeOf(backing, 40n, 1n));

    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.payments).toHaveLength(1);
    expect(compareBytes(redemption.payments[0]!.payee, KEYS.alice)).toBe(0);
    expect(redemption.payments[0]!.quantity).toBe(60n);
  });

  it("does not let one spend challenge a later claim in the same gap", () => {
    // Alice files twice in one gap, at nonces 0 and 2. A request at nonce 0
    // displaces the FIRST claim; reading it against the second would pay one
    // spend twice.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const first = demand(backing, SECRETS.alice, KEYS.alice, 40n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, first.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, first.hash, 11n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, first.hash, 1n));
    const second = demand(backing, SECRETS.alice, KEYS.alice, 60n, 14n, 40n, 2n);
    publishAt(venue, 14n, backing, second.op);
    publishAt(venue, 15n, backing, acceptance(backing, SECRETS.backer, second.hash, 14n, 40n, 2n));
    publishAt(venue, 16n, backing, release(backing, SECRETS.alice, second.hash, 3n));
    publishAt(venue, 17n, backing, challengeOf(backing, 40n, 0n));

    const [one, two] = snapshotRedemptions(venue, backing, served);
    expect(compareBytes(one!.payments[0]!.payee, KEYS.bob)).toBe(0);
    expect(one!.payments[0]!.quantity).toBe(40n);
    expect(two!.payments).toHaveLength(1);
    expect(compareBytes(two!.payments[0]!.payee, KEYS.alice)).toBe(0);
    expect(two!.payments[0]!.quantity).toBe(60n);
  });

  it("is unsettled while the window stands and settled once it closes", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);

    advanceWitnessedIndex(venue, 18n);
    expect(snapshotRedemptions(venue, backing, served)[0]!.settled).toBe(false);
    advanceWitnessedIndex(venue, 19n);
    expect(snapshotRedemptions(venue, backing, served)[0]!.settled).toBe(true);
  });

  it("reports the window's own bounds so a backer can wait it out", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.releasedAt).toBe(13n);
    expect(redemption.challengeClosesAt).toBe(18n);
  });
});

describe("§C2b: the venue carries evidence, never a second claim layer", () => {
  it("never moves units on a transfer published at the venue", () => {
    // "Claims go illiquid rather than dead" — illiquid means transfers stop.
    // A published request is evidence about a claim, not an operation on one.
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    publishAt(venue, 11n, backing, transfer(backing, SECRETS.alice, KEYS.alice, KEYS.bob, 40n, 0n));
    sequencer.adopt(backing);
    expect(sequencer.balance(backing, KEYS.alice)).toBe(100n);
    expect(sequencer.balance(backing, KEYS.bob)).toBe(0n);
  });

  it("never issues or burns on a publication at the venue", () => {
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    const issueMessage = encodeIssuanceMessage(backing.name, KEYS.mallory, 500n, 1n);
    publishAt(venue, 11n, backing, {
      kind: "issue",
      recipient: KEYS.mallory,
      quantity: 500n,
      nonce: 1n,
      signature: ed25519.sign(issueMessage, SECRETS.backer),
    });
    const burnMessage = encodeBurnMessage(backing.name, KEYS.alice, 100n, 0n);
    publishAt(venue, 12n, backing, {
      kind: "burn",
      holder: KEYS.alice,
      quantity: 100n,
      nonce: 0n,
      signature: ed25519.sign(burnMessage, SECRETS.alice),
    });
    sequencer.adopt(backing);
    expect(sequencer.outstanding(backing)).toBe(100n);
    expect(sequencer.balance(backing, KEYS.mallory)).toBe(0n);
    expect(sequencer.balance(backing, KEYS.alice)).toBe(100n);
  });

  it("refuses a publication whose bytes do not encode", () => {
    const { venue, backing } = setup();
    expect(() =>
      venue.publishOp(backing.name, {
        kind: "release",
        demandHash: new Uint8Array(31),
        nonce: 0n,
        signature: new Uint8Array(64),
      }),
    ).toThrow();
  });

  it("hands out copies, in and out", () => {
    // The publisher keeps a reference to what it handed over, and a reader must
    // not be able to poison the record for the next one.
    const { venue, backing } = setup();
    // A copy of the payee key, because this test mutates what it hands over and
    // KEYS is shared across every test in the file.
    const payee = Uint8Array.from(KEYS.bob);
    const op = transfer(backing, SECRETS.alice, KEYS.alice, payee, 40n, 0n);
    venue.publishOp(backing.name, op);
    payeeOf(op).fill(0xff);
    const first = venue.publishedOpsFor(backing.name)[0]!.op;
    expect(compareBytes(payeeOf(first), KEYS.bob)).toBe(0);
    payeeOf(first).fill(0xff);
    const second = venue.publishedOpsFor(backing.name)[0]!.op;
    expect(compareBytes(payeeOf(second), KEYS.bob)).toBe(0);
  });

  it("keeps one backing's publications out of another's", () => {
    const { venue, backing } = setup();
    const other = makeTransparentBacking(SECRETS.backer2, "USD", [], SILENCE);
    venue.publishOp(backing.name, transfer(backing, SECRETS.alice, KEYS.alice, KEYS.bob, 40n, 0n));
    expect(venue.publishedOpsFor(other.name)).toHaveLength(0);
  });
});

describe("§C2b: a returning sequencer adopts what was witnessed during the gap", () => {
  it("adopts the legs before co-signing again", () => {
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    redeemAtVenue(venue, backing);

    // Alice's next operation is co-signed only after the gap is adopted, so the
    // log carries the three legs ahead of it.
    const spend = { backing, from: KEYS.backer, to: KEYS.carol, quantity: 100n, nonce: 2n };
    sequencer.submitTransfer(
      spend,
      ed25519.sign(encodeTransferMessage(backing.name, KEYS.backer, KEYS.carol, 100n, 2n), SECRETS.backer),
    );
    const log = sequencer.opLog(backing);
    expect(log.map((entry) => entry.kind)).toEqual([
      "issue",
      "demand",
      "acceptance",
      "release",
      "transfer",
    ]);
    expect(sequencer.balance(backing, KEYS.carol)).toBe(100n);
  });

  it("adopts before publishing a commitment, so the committed state carries the gap", () => {
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    sequencer.commit();
    expect(sequencer.snapshot()[0]!.opLog).toHaveLength(4);
  });

  it("is idempotent: adopting twice applies each leg once", () => {
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    sequencer.adopt(backing);
    sequencer.adopt(backing);
    expect(sequencer.opLog(backing)).toHaveLength(4);
    expect(sequencer.balance(backing, KEYS.backer)).toBe(100n);
  });

  it("co-signs what it adopted, so a holder can still get a receipt for it", () => {
    // Invariant 26: repeating the request cannot change the answer. A leg the
    // holder had to publish at the venue is still an accepted operation.
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    const claim = redeemAtVenue(venue, backing);
    sequencer.adopt(backing);
    const receipt = sequencer.submitRelease({ backing, demandHash: claim.hash, nonce: 1n }, new Uint8Array(64));
    expect(verifyReceipt(receipt)).toBe(true);
    expect(receipt.position).toBe(3n);
    expect(receiptProvenBy(receipt, sequencer.snapshot()[0]!)).toBe(true);
  });

  it("adopts nothing published outside a gap", () => {
    const { venue, sequencer, backing } = setup();
    sequencer.commit();
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 1n, 40n, 0n);
    publishAt(venue, 1n, backing, claim.op);
    sequencer.adopt(backing);
    expect(sequencer.opLog(backing)).toHaveLength(1);
  });

  it("lets a redemption whose operator returns mid-flight finish at the sequencer", () => {
    // The gap's legs and the sequencer's are one log on one nonce sequence, so
    // a claim filed at the venue is settled by a release submitted the ordinary
    // way once service resumes. Nothing needs carrying across.
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, claim.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, claim.hash, 11n, 40n, 1n));
    sequencer.commit();
    expect(sequencer.openDemands(backing)).toHaveLength(1);

    const message = encodeReleaseMessage(backing.name, claim.hash, 1n);
    sequencer.submitRelease(
      { backing, demandHash: claim.hash, nonce: 1n },
      ed25519.sign(message, SECRETS.alice),
    );
    expect(sequencer.balance(backing, KEYS.backer)).toBe(100n);
  });
});

describe("§C2b: what the record shows when redemption cannot complete", () => {
  it("records dishonour where a backer-run operator never answers", () => {
    // Backer-run is the spec's cold-start default, and there redemption opens
    // but stalls at the acceptance leg: "without co-signature" is without the
    // SEQUENCER's, not without the backer's. What is left is the public fact.
    const { venue, sequencer, backing } = setup();
    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 0n, 20n, 0n);
    sequencer.submitDemand(
      { backing, holder: KEYS.alice, quantity: 100n, instant: 0n, deadline: 20n, nonce: 0n },
      claim.signature,
    );
    const served = goDark(venue, sequencer);
    advanceWitnessedIndex(venue, 21n);
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
    const record = sequencer.openDemands(backing)[0]!;
    expect(isDishonoured(record, venue.witnessedIndex())).toBe(true);
  });

  it("resolves nothing against a commitment that is not the operator's latest", () => {
    // Against an older commitment a holder who has since spent the units still
    // proves the state that shows them — the same reason provesHolding demands
    // the last witnessed snapshot, and here it would be paid for.
    const { venue, sequencer, backing } = setup();
    const stale = { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
    sequencer.submitTransfer(
      { backing, from: KEYS.alice, to: KEYS.bob, quantity: 100n, nonce: 0n },
      ed25519.sign(encodeTransferMessage(backing.name, KEYS.alice, KEYS.bob, 100n, 0n), SECRETS.alice),
    );
    venue.advance();
    sequencer.commit();
    venue.advance(SILENCE.noCommitmentDuration + 1n);

    const claim = demand(backing, SECRETS.alice, KEYS.alice, 100n, 12n, 40n, 0n);
    publishAt(venue, 12n, backing, claim.op);
    publishAt(venue, 13n, backing, acceptance(backing, SECRETS.backer, claim.hash, 12n, 40n, 1n));
    publishAt(venue, 14n, backing, release(backing, SECRETS.alice, claim.hash, 1n));
    expect(snapshotRedemptions(venue, backing, stale)).toHaveLength(0);
  });

  it("cannot be erased by the operator publishing one more commitment", () => {
    // The snapshot a leg is judged against is the one that was last WHEN THE LEG
    // WAS PUBLISHED. Read as "whatever is latest now" instead, an operator that
    // would rather a settled redemption were unresolvable makes it so by
    // committing — and under backer-run, the party with that motive is the party
    // that owes the money.
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(1);

    sequencer.commit();
    const after = snapshotRedemptions(venue, backing, served);
    expect(after).toHaveLength(1);
    expect(compareBytes(after[0]!.payments[0]!.payee, KEYS.alice)).toBe(0);
    expect(after[0]!.payments[0]!.quantity).toBe(100n);
  });

  it("refuses a second redemption of one holding across two gaps", () => {
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    // The operator returns, adopts, commits — then goes dark a second time.
    sequencer.commit();
    const served = { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
    venue.advance(SILENCE.noCommitmentDuration + 1n);

    const again = demand(backing, SECRETS.alice, KEYS.alice, 100n, 30n, 60n, 2n);
    publishAt(venue, 30n, backing, again.op);
    publishAt(venue, 31n, backing, acceptance(backing, SECRETS.backer, again.hash, 30n, 60n, 2n));
    publishAt(venue, 32n, backing, release(backing, SECRETS.alice, again.hash, 3n));
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("refuses a redemption on a backing that declares no silence clause", () => {
    const venue = new Venue();
    const sequencer = new Sequencer(SECRETS.operator, venue);
    const backing = makeTransparentBacking(SECRETS.backer, "EUR");
    sequencer.register(backing, signBacking(SECRETS.backer, backing));
    sequencer.submitIssue(
      { backing, recipient: KEYS.alice, quantity: 100n, nonce: 0n },
      ed25519.sign(encodeIssuanceMessage(backing.name, KEYS.alice, 100n, 0n), SECRETS.backer),
    );
    const served = { snapshots: sequencer.snapshot(), commitment: sequencer.commit() };
    venue.advance(SILENCE.noCommitmentDuration + 1n);
    redeemAtVenue(venue, backing);
    expect(isSilent(venue, backing)).toBe(false);
    expect(snapshotRedemptions(venue, backing, served)).toHaveLength(0);
  });

  it("never throws on a served state a hostile operator built", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    const poisoned: ServedState = {
      snapshots: [{ name: backing.name, opLog: [{ position: 0, kind: "release", demandHash: new Uint8Array(0), nonce: -1n, signature: new Uint8Array(0) }] }],
      commitment: served.commitment,
    };
    expect(() => snapshotRedemptions(venue, backing, poisoned)).not.toThrow();
    expect(snapshotRedemptions(venue, backing, poisoned)).toHaveLength(0);
  });
});

describe("§C2b: the redemption's own arithmetic", () => {
  it("pays exactly what the claim named, never what the holder held", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    redeemAtVenue(venue, backing, 40n);
    const redemption = snapshotRedemptions(venue, backing, served)[0]!;
    expect(redemption.quantity).toBe(40n);
    expect(redemption.payments[0]!.quantity).toBe(40n);
    sequencer.adopt(backing);
    expect(sequencer.balance(backing, KEYS.alice)).toBe(60n);
    expect(sequencer.balance(backing, KEYS.backer)).toBe(40n);
  });

  it("destroys nothing: outstanding is unchanged by a redemption", () => {
    // Invariant 10. Presentation hands claims to the backer, who is then
    // simply their holder, and that does not change because it happened at the
    // venue.
    const { venue, sequencer, backing } = setup();
    goDark(venue, sequencer);
    redeemAtVenue(venue, backing);
    sequencer.adopt(backing);
    expect(sequencer.outstanding(backing)).toBe(100n);
    expect(sequencer.balance(backing, KEYS.alice) + sequencer.balance(backing, KEYS.backer)).toBe(100n);
  });

  it("reports every redemption the gap settled, in the order they were released", () => {
    const { venue, sequencer, backing } = setup();
    const served = goDark(venue, sequencer);
    const first = demand(backing, SECRETS.alice, KEYS.alice, 40n, 11n, 40n, 0n);
    publishAt(venue, 11n, backing, first.op);
    publishAt(venue, 12n, backing, acceptance(backing, SECRETS.backer, first.hash, 11n, 40n, 1n));
    publishAt(venue, 13n, backing, release(backing, SECRETS.alice, first.hash, 1n));
    const second = demand(backing, SECRETS.alice, KEYS.alice, 60n, 14n, 40n, 2n);
    publishAt(venue, 14n, backing, second.op);
    publishAt(venue, 15n, backing, acceptance(backing, SECRETS.backer, second.hash, 14n, 40n, 2n));
    publishAt(venue, 16n, backing, release(backing, SECRETS.alice, second.hash, 3n));

    const redemptions = snapshotRedemptions(venue, backing, served);
    expect(redemptions.map((r) => r.quantity)).toEqual([40n, 60n]);
    expect(redemptions.map((r) => bytesToHex(r.demandHash))).toEqual([
      bytesToHex(first.hash),
      bytesToHex(second.hash),
    ]);
  });
});
