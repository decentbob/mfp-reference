import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { makeBacking, signBacking, type Backing } from "../src/backing.js";
import { replayLog } from "../src/ledger.js";
import { encodeIssuanceMessage } from "../src/messages.js";
import {
  commitSatisfies,
  countersignCommit,
  decodeCommit,
  encodeCommit,
  encodeLock,
  signCommit,
  type Commit,
  type LockOp,
} from "../src/presentation.js";
import { Sequencer, SequencerError } from "../src/sequencer.js";
import { LocalVenue } from "../src/venue.js";
import { KEYS, SECRETS } from "./support.js";

// §C1's swap: "The n-party atomic exchange is first-class, and the paper quietly
// needs it: bilateral netting (a gift if either burns first), clearing a cycle,
// set-for-set reassembly trades, atomic multi-hop routing. It is presentation's
// machinery. Every participant locks what it gives, all sign, commit converts
// every lock at once, any refusal to prepare aborts, and the timeout unlocks
// everywhere. The fully signed exchange object is the release, publishable by
// any participant, and read against the same timeout predicate."
//
// 24b's bundle is the one-party case: the holder locks, the holder commits. Here
// each lock names its PARTIES — the keys whose signatures on the commit convert
// it — and one object carries every signature. A sequencer still matches one
// object against its own lock and knows nothing else; what it reads off the lock
// is who must have signed. A partial object therefore settles nothing anywhere,
// which is the whole of what "all sign" buys.

const TIMEOUT = 50n;
const ATTEMPT = new Uint8Array(32).fill(0x51);

/** Two backings at two operators, one venue. Alice holds EUR, Bob holds GOLD. */
function setup() {
  const venue = new LocalVenue();
  const mk = (thing: string, operator: Uint8Array) =>
    makeBacking({
      obligor: KEYS.backer,
      payout: { thing, quantumExponent: -2, perUnit: 100n },
      reliance: [],
      evidence: { setting: "transparent", operator, witnessing: { venue: venue.id, interval: 5n } },
    });
  const eur = mk("EUR", KEYS.operator);
  const gold = mk("GOLD", KEYS.carol);
  const one = new Sequencer(SECRETS.operator, venue);
  const two = new Sequencer(SECRETS.carol, venue);
  one.register(eur, signBacking(SECRETS.backer, eur));
  two.register(gold, signBacking(SECRETS.backer, gold));
  const issue = (sequencer: Sequencer, backing: Backing, holder: Uint8Array) => {
    const nonce = sequencer.nextNonce(KEYS.backer, backing);
    sequencer.submitIssue(
      { backing, recipient: holder, quantity: 200n, nonce },
      ed25519.sign(encodeIssuanceMessage(backing.name, holder, 200n, nonce), SECRETS.backer),
    );
  };
  issue(one, eur, KEYS.alice);
  issue(two, gold, KEYS.bob);
  return { venue, one, two, eur, gold };
}

const sorted = (...keys: Uint8Array[]) => [...keys].sort((a, b) => Buffer.compare(a, b));

/** `holder` reserves `quantity` of `backing` for `beneficiary`, in an exchange among `parties`. */
function lock(
  sequencer: Sequencer,
  backing: Backing,
  venue: LocalVenue,
  holder: keyof typeof SECRETS,
  beneficiary: Uint8Array,
  quantity: bigint,
  parties: Uint8Array[],
  attempt = ATTEMPT,
) {
  const op: LockOp = {
    backing,
    attemptId: attempt,
    holder: KEYS[holder],
    beneficiary,
    quantity,
    timeout: TIMEOUT,
    decisionVenue: venue.id,
    parties,
    nonce: sequencer.nextNonce(KEYS[holder], backing),
  };
  return sequencer.submitLock(op, ed25519.sign(encodeLock(op), SECRETS[holder]));
}

/** Alice gives 40 EUR for Bob's 90 GOLD: two locks, two parties each. */
function prepare(f: ReturnType<typeof setup>) {
  const parties = sorted(KEYS.alice, KEYS.bob);
  lock(f.one, f.eur, f.venue, "alice", KEYS.bob, 40n, parties);
  lock(f.two, f.gold, f.venue, "bob", KEYS.alice, 90n, parties);
}

describe("§C1: two parties, one object", () => {
  it("both sign, anyone publishes, each sequencer settles its own lock", () => {
    const f = setup();
    prepare(f);
    const object = countersignCommit(signCommit(SECRETS.alice, ATTEMPT), SECRETS.bob);
    f.venue.advance(3n);
    f.venue.publishCommit(object);
    f.one.settle(f.eur, ATTEMPT);
    f.two.settle(f.gold, ATTEMPT);
    expect(f.one.balance(f.eur, KEYS.bob)).toBe(40n);
    expect(f.two.balance(f.gold, KEYS.alice)).toBe(90n);
    expect(f.one.balance(f.eur, KEYS.alice)).toBe(160n);
    expect(f.two.balance(f.gold, KEYS.bob)).toBe(110n);
  });

  it("a partial object settles nothing anywhere", () => {
    // Alice signs and publishes before Bob does. Bob's lock is Bob's to convert
    // and Alice's names Bob too, so neither half moves: there is no order in
    // which one party can take the other's half.
    const f = setup();
    prepare(f);
    f.venue.advance(3n);
    f.venue.publishCommit(signCommit(SECRETS.alice, ATTEMPT));
    expect(() => f.one.settle(f.eur, ATTEMPT)).toThrow(SequencerError);
    expect(() => f.two.settle(f.gold, ATTEMPT)).toThrow(SequencerError);
    expect(f.one.balance(f.eur, KEYS.bob)).toBe(0n);
    expect(f.two.balance(f.gold, KEYS.alice)).toBe(0n);
  });
});

describe("§C1: a ring of three, and what the object tolerates", () => {
  it("clearing a cycle: three locks, three signatures, one object; one signature short, nothing", () => {
    // A gives to B, B to C, C to A — "clearing is the n-party case with nobody".
    // Three backings at one operator keeps the fixture small; the law is per
    // backing regardless, so each lock is read alone.
    const venue = new LocalVenue();
    const mk = (thing: string) =>
      makeBacking({
        obligor: KEYS.backer,
        payout: { thing, quantumExponent: -2, perUnit: 100n },
        reliance: [],
        evidence: { setting: "transparent", operator: KEYS.operator, witnessing: { venue: venue.id, interval: 5n } },
      });
    const [a, b, c] = [mk("A"), mk("B"), mk("C")];
    const sequencer = new Sequencer(SECRETS.operator, venue);
    const holders = [["alice", a, KEYS.bob], ["bob", b, KEYS.carol], ["carol", c, KEYS.alice]] as const;
    for (const [who, backing] of holders) {
      sequencer.register(backing, signBacking(SECRETS.backer, backing));
      const nonce = sequencer.nextNonce(KEYS.backer, backing);
      sequencer.submitIssue(
        { backing, recipient: KEYS[who], quantity: 100n, nonce },
        ed25519.sign(encodeIssuanceMessage(backing.name, KEYS[who], 100n, nonce), SECRETS.backer),
      );
    }
    const parties = sorted(KEYS.alice, KEYS.bob, KEYS.carol);
    for (const [who, backing, to] of holders) lock(sequencer, backing, venue, who, to, 10n, parties);

    const twoOfThree = countersignCommit(signCommit(SECRETS.alice, ATTEMPT), SECRETS.bob);
    venue.advance(2n);
    venue.publishCommit(twoOfThree);
    for (const [, backing] of holders) expect(() => sequencer.settle(backing, ATTEMPT)).toThrow(SequencerError);

    venue.advance(1n);
    venue.publishCommit(countersignCommit(twoOfThree, SECRETS.carol));
    for (const [, backing] of holders) sequencer.settle(backing, ATTEMPT);
    expect(sequencer.balance(a, KEYS.bob)).toBe(10n);
    expect(sequencer.balance(b, KEYS.carol)).toBe(10n);
    expect(sequencer.balance(c, KEYS.alice)).toBe(10n);
    // And each backing's log replays on its own: the commit entry carries every
    // signature, and the lock it settled says which had to be there.
    for (const [, backing] of holders) expect(replayLog(backing, sequencer.opLog(backing))).toBeDefined();
  });

  it("a stranger's signature on the object changes nothing, and signing twice is the same object", () => {
    const f = setup();
    prepare(f);
    const both = countersignCommit(signCommit(SECRETS.alice, ATTEMPT), SECRETS.bob);
    const noisy = countersignCommit(countersignCommit(both, SECRETS.mallory), SECRETS.bob);
    expect(commitSatisfies(noisy, sorted(KEYS.alice, KEYS.bob))).toBe(true);
    expect(noisy.signatures).toHaveLength(3);
    f.venue.advance(2n);
    f.venue.publishCommit(noisy);
    f.one.settle(f.eur, ATTEMPT);
    f.two.settle(f.gold, ATTEMPT);
    expect(f.one.balance(f.eur, KEYS.bob)).toBe(40n);
  });

  it("a lock whose holder is not among its parties is refused by the law", () => {
    const f = setup();
    expect(() => lock(f.one, f.eur, f.venue, "alice", KEYS.bob, 40n, [KEYS.bob])).toThrow(/one of its parties/);
  });

  it("a party set has one spelling: sorted, no repeats, one to sixteen", () => {
    const f = setup();
    const [lo, hi] = sorted(KEYS.alice, KEYS.bob) as [Uint8Array, Uint8Array];
    const bad = (parties: Uint8Array[]) => () => lock(f.one, f.eur, f.venue, "alice", KEYS.bob, 1n, parties);
    expect(bad([hi, lo])).toThrow(/ascending/);
    expect(bad([lo, lo])).toThrow(/ascending/);
    expect(bad([])).toThrow(/1\.\.16/);
    expect(bad(Array.from({ length: 17 }, (_, i) => new Uint8Array(32).fill(i + 1)))).toThrow(/1\.\.16/);
  });

  it("the object is bytes with one spelling, and settling twice is one payment", () => {
    const f = setup();
    prepare(f);
    const object: Commit = countersignCommit(signCommit(SECRETS.bob, ATTEMPT), SECRETS.alice);
    expect(decodeCommit(encodeCommit(object))).toEqual(object);
    expect(encodeCommit(object)).toHaveLength(32 + 1 + 2 * 96);
    f.venue.advance(2n);
    f.venue.publishCommit(object);
    const first = f.one.settle(f.eur, ATTEMPT);
    expect(f.one.settle(f.eur, ATTEMPT)).toEqual(first);
    expect(f.one.balance(f.eur, KEYS.bob)).toBe(40n);
  });
});
