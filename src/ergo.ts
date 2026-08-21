// Ergo as a witness venue (§C2).
//
// The chain **witnesses, and adjudicates nothing**. No contract here verifies a
// signature; a commitment is a record in box registers, and everything that
// judges it — equivocation, the silence grade, the redemption walk — is done by
// whoever reads. That is why this needs no ErgoScript and no change of curve.
//
// **Reads are a materialised view, and that is structural rather than a
// workaround.** `Venue` is synchronous and every caller through recovery, fault
// and the sequencer is synchronous with it; making it async to accommodate HTTP
// would ripple through the codebase for nothing. So this syncs asynchronously
// and answers synchronously: fetch the record, then reason over it offline.
// §C0b says what that is — "Published means retrievable by a stranger...
// Content-addressed storage gives integrity, not availability" — a holder
// obtains the trail and the checking never touches the network again.
//
// The layout, and the one line of it that is a security property:
//
//   commitment box   R4 operator key (32) || R5 root (32)
//                    || R6 sequence (Long) || R7 signature (64)
//   publication box  R4 backing name (32, a scan key)
//                    || R5 the record bytes (authoritative)
//
// **The witnessed index is the box's `inclusionHeight`, never its
// `creationHeight`.** The latter is written by whoever builds the transaction:
// consensus stops it exceeding the including block's height, but it may be set
// LOWER. An operator backdating a commitment would put it before a redemption
// leg it actually followed, which is precisely the veto slice 8 closed — a
// publication is judged against the record as it stood strictly before its own
// index, and the tie must not go to the party watching the venue.
//
// **Every read is taken at `height − depth`**, because `inclusionHeight` is
// reorg-sensitive and a venue answering from the tip would change its mind about
// the past. The depth is not a client setting: §C2 names a venue "together with
// its finality rule... That is a floor under the interval, or two sequencers
// answer §C3's release predicate differently." So the venue's own id commits to
// it (see `ergoVenueId`), and naming the venue is agreeing the depth.
//
// Reading requires a node with `extraIndex` enabled, since the /blockchain
// routes exist only then. That is a real floor under "retrievable by a
// stranger", and it is said here rather than discovered later.
//
// NOT here, deliberately: publishing. Building and submitting a transaction
// needs an Ergo library, and this repository's dependencies are @noble/hashes
// and @noble/curves. A verifier never publishes — only an operator does — so the
// read surface is the whole of what a holder needs, and publication is injected
// by whoever has a wallet. See DECISIONS.md.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { ByteWriter, compareBytes, copyBytes, EncodingError } from "./bytes.js";
import {
  decodeCommitment,
  encodeCommitment,
  verifyCommitment,
  type Commitment,
} from "./commitment.js";
import { utf8Encoder } from "./contexts.js";
import { decodePublishedOp, type PublishedOp } from "./oplog.js";
import { decodeReplacement, type Replacement, type WitnessedReplacement } from "./replacement.js";
import {
  decodeRevocation,
  isSignedRevocation,
  type Revocation,
  type WitnessedRevocation,
} from "./revocation.js";
import { successionOf } from "./replacement.js";
import { UNNAMED_VENUE, VenueError, type Venue, type WitnessedOp } from "./venue.js";
import { type Backing } from "./backing.js";

/**
 * One box, as the node's indexed API returns it, reduced to what a venue reads.
 *
 * `inclusionHeight` is the field this whole module turns on: "height of the block
 * in which the creating transaction was included", which is the chain's word
 * rather than the publisher's. The box's own `creationHeight` is deliberately not
 * modelled, so it cannot be reached for by mistake.
 */
export interface ErgoBoxView {
  readonly inclusionHeight: bigint;
  /** Registers R4..R9, by name, as raw bytes. Absent registers are omitted. */
  readonly registers: Readonly<Record<string, Uint8Array>>;
}

/**
 * The node, reduced to the reads a venue needs. Four calls, all of them
 * `/blockchain/*` routes that exist only with `extraIndex` enabled.
 *
 * An interface rather than an HTTP client, because the client is the one part
 * that cannot be checked without a node, and everything above it can.
 */
export interface ErgoNode {
  /** `/blockchain/indexedHeight` — how far the index has reached. */
  indexedHeight(): Promise<bigint>;
  /**
   * `/blockchain/box/byAddress` — every box at an address, **spent or not**, in
   * the order the chain saw them. The spent-inclusive route is the one a venue
   * needs: a commitment's history has to survive its box being spent.
   */
  boxesByAddress(address: string): Promise<ErgoBoxView[]>;
}

/**
 * Where a backing's records live. Address derivation and spend policy are
 * injected rather than fixed here: they turn on Ergo economics — storage rent,
 * minimum box value, whether a spend guard needs a secp256k1 key E does not name
 * — which wants a node and experiments rather than a decision from reading. None
 * of the logic below depends on the answer.
 */
export interface ErgoAddressing {
  /** Where this operator publishes its commitments. */
  commitments(operator: Uint8Array): string;
  /** Where anyone publishes operations and replacements for this backing. */
  publications(backingName: Uint8Array): string;
  /**
   * Where K publishes its own revocation. Keyed by the obligor key rather than
   * by a backing, because §C2b's revocation is about a key and one K obligates
   * many backings.
   */
  revocations(obligor: Uint8Array): string;
}

/**
 * A venue's identity, committing to its finality rule.
 *
 * §C2 names a venue together with the depth under which an index counts as
 * witnessed there, and warns why: a floor under the interval, "or two sequencers
 * answer §C3's release predicate differently". If each backing declared its own
 * depth for one chain, two backings would disagree about when a block counts as
 * witnessed — exactly that divergence. Deriving the id from the depth instead
 * makes naming the venue the same act as agreeing the depth.
 *
 * Still 32 bytes in E's witnessing clause; only what they denote has changed.
 */
export function ergoVenueId(chain: string, depth: bigint, publicationScript: string): Uint8Array {
  const w = new ByteWriter();
  // Length-prefixed, not written raw. ByteWriter.context is the one legitimate
  // raw write and its licence is narrow: contexts.ts asserts its tags are
  // prefix-free, and this one is not among them. Borrowing the escape hatch
  // outside the condition that justifies it is how a checked invariant turns
  // into a convention.
  w.lengthPrefixed(utf8Encoder.encode("mfp/venue/ergo/v1"));
  w.lengthPrefixed(utf8Encoder.encode(chain));
  w.u64(depth);
  w.lengthPrefixed(utf8Encoder.encode(publicationScript));
  return sha256(w.finish());
}

/**
 * Which window of a commitment's canonical record goes in which register.
 *
 * **The one definition of the layout**, read by both directions: the registers
 * are windows onto the record rather than a second encoding of it, so there is
 * nothing here that can drift out of step with `encodeCommitment`. Written as a
 * table for the same reason ByteWriter asserts widths at the point that writes —
 * the first version of this file spelled the offsets out twice and the two
 * spellings disagreed about R4 and R5.
 */
const COMMITMENT_LAYOUT: readonly (readonly [string, number, number])[] = [
  ["R6", 0, 8], // sequence
  ["R5", 8, 40], // root
  ["R4", 40, 72], // operator key
  ["R7", 72, 136], // signature
];

/** A record the venue read, and the index the chain witnessed it at. */
interface Witnessed<T> {
  readonly value: T;
  readonly at: bigint;
}

function register(box: ErgoBoxView, name: string): Uint8Array {
  const bytes = box.registers[name];
  if (bytes === undefined) throw new EncodingError(`box has no ${name}`);
  return bytes;
}

/**
 * The Ergo chain, read as a venue.
 *
 * Empty until `sync` is called, and answering only from what the last sync
 * gathered. A holder syncs once and then checks a grade, a redemption or a
 * receipt without touching the network — which is the shape §C2b assumes when it
 * says the unspentness proof "runs against the published trail, which replicas
 * serve because publication was the point".
 */
export class ErgoVenue implements Venue {
  private readonly venueId: Uint8Array;
  private readonly depth: bigint;
  private readonly addressing: ErgoAddressing;
  private height = 0n;
  /** Operator hex -> its commitments, in witnessed order. */
  private readonly commitments = new Map<string, Witnessed<Commitment>[]>();
  /** Backing name hex -> operations, in witnessed order. */
  private readonly ops = new Map<string, Witnessed<PublishedOp>[]>();
  /** Backing name hex -> replacements, in witnessed order. */
  private readonly replacements = new Map<string, Witnessed<Replacement>[]>();
  /** The backings this view was gathered for. Anything else it will not answer. */
  private readonly covered = new Set<string>();
  /** The operators it fetched — every one in a covered backing's chain. */
  private readonly fetched = new Set<string>();
  /** Obligor key hex -> that key's revocation records. */
  private readonly revocations = new Map<string, Witnessed<Revocation>[]>();
  /** The obligor keys it fetched revocations for. */
  private readonly revoked = new Set<string>();

  constructor(id: Uint8Array, depth: bigint, addressing: ErgoAddressing) {
    if (!(id instanceof Uint8Array) || id.length !== 32) {
      throw new VenueError("a venue id must be 32 bytes");
    }
    if (depth < 0n) throw new VenueError("a finality depth cannot be negative");
    this.venueId = copyBytes(id);
    this.depth = depth;
    this.addressing = addressing;
  }

  get id(): Uint8Array {
    return copyBytes(this.venueId);
  }

  /**
   * Take the chain's current word on every target this venue answers for.
   *
   * The height is the indexed height less the declared depth, and **nothing
   * deeper than that is read at all**: a box whose inclusion height is inside the
   * unfinalised zone is not yet witnessed, so admitting it would let the venue
   * change its mind about the past when the chain reorganises.
   *
   * **The whole view is replaced, and it takes every target at once.** A venue
   * has one height, because `witnessedIndex` answers without being asked about a
   * backing — so it must have one coherent set of records to go with it.
   * Refreshing part of the view while the height moved for all of it grades a
   * punctual operator silent: its records stop where the last partial sync left
   * them while the clock runs on, which opens snapshot redemption against
   * somebody who committed seven blocks ago. A grade is meant to be a fact a
   * stranger checks, not an artefact of the order somebody synced in.
   *
   * A box that does not decode is skipped rather than fatal. Anyone may create a
   * box at these addresses, so noise there is ordinary — the same posture the
   * local venue takes toward a publication it cannot read.
   */
  async sync(node: ErgoNode, backings: readonly Backing[]): Promise<void> {
    const indexed = await node.indexedHeight();
    this.height = indexed > this.depth ? indexed - this.depth : 0n;
    this.commitments.clear();
    this.ops.clear();
    this.replacements.clear();
    this.covered.clear();
    this.fetched.clear();
    this.revocations.clear();
    this.revoked.clear();

    for (const backing of backings) {
      await this.syncPublications(node, backing.name);
      this.covered.add(backing.nameHex);
      // Each covered backing's obligor, because a revocation is read per key.
      // Not answering for one that was never fetched is worth more here than
      // anywhere else: absence of a revocation record reads as NOT revoked,
      // which is the direction that gets a holder paid in units nobody backs.
      await this.syncRevocations(node, backing.obligor);
      this.revoked.add(bytesToHex(backing.obligor));
    }
    // Then every operator the backing has had, not only the key E names. The
    // chain is only walkable once the replacements are in, and each successor's
    // commitments have to be in before the walk can tell whether it took force —
    // so the frontier widens until it stops revealing anyone new. Bounded by the
    // chain's own length, which is bounded by the replacements published.
    for (const backing of backings) {
      for (;;) {
        const chain = successionOf(backing, this);
        const missing = chain
          .map((link) => link.operator)
          .filter((operator) => !this.fetched.has(bytesToHex(operator)));
        if (missing.length === 0) break;
        for (const operator of missing) {
          this.fetched.add(bytesToHex(operator));
          await this.syncCommitments(node, operator);
        }
      }
    }
  }

  /**
   * The boxes this venue will read at all: finalised, decodable, in the order
   * the chain witnessed them. Everything else is skipped rather than fatal,
   * since anyone may create a box at these addresses.
   */
  private finalised<T>(boxes: ErgoBoxView[], read: (box: ErgoBoxView) => T): Witnessed<T>[] {
    const out: Witnessed<T>[] = [];
    for (const box of boxes) {
      if (box.inclusionHeight > this.height) continue;
      try {
        out.push({ value: read(box), at: box.inclusionHeight });
      } catch {
        continue;
      }
    }
    return out.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  }

  /**
   * Whether this view was gathered for a backing. **False is not an answer about
   * the backing**, it is the absence of one: a venue asked about something it
   * never synced would report no commitments, and no commitments reads as
   * silence — an accusation built out of not having looked.
   */
  private requireCovered(backingName: Uint8Array): void {
    if (!this.covered.has(bytesToHex(backingName))) {
      throw new VenueError("this view was not synced for that backing");
    }
  }

  /**
   * The same rule for an operator. It has to be here as well as on the backing
   * reads: a backing declaring no replacement rule never reaches
   * replacementsFor at all, so the grade would be computed from an operator this
   * view never fetched — no commitments, which reads as silence since genesis.
   * Every operator in a covered backing's chain is fetched, so succession is
   * unaffected.
   */
  private requireFetched(operator: Uint8Array): void {
    if (!this.fetched.has(bytesToHex(operator))) {
      throw new VenueError("this view was not synced for that operator");
    }
  }

  private async syncCommitments(node: ErgoNode, operator: Uint8Array): Promise<void> {


    const commitmentBoxes = await node.boxesByAddress(this.addressing.commitments(operator));
    this.commitments.set(
      bytesToHex(operator),
      this.finalised(commitmentBoxes, (box) => {
        // Reassembled in the record's own order, which the table gives.
        const record = new Uint8Array(136);
        for (const [name, start, end] of COMMITMENT_LAYOUT) {
          const bytes = register(box, name);
          if (bytes.length !== end - start) throw new EncodingError(`${name} is the wrong width`);
          record.set(bytes, start);
        }
        const commitment = decodeCommitment(record);
        // The box says whose it is; the signature says whether that is true.
        // Anyone may create a box at this address, so nothing here rests on the
        // address alone.
        if (compareBytes(commitment.operator, operator) !== 0) {
          throw new EncodingError("box is not this operator's");
        }
        if (!verifyCommitment(commitment)) throw new EncodingError("commitment does not verify");
        return commitment;
      }),
    );

  }

  private async syncRevocations(node: ErgoNode, obligor: Uint8Array): Promise<void> {
    const boxes = await node.boxesByAddress(this.addressing.revocations(obligor));
    this.revocations.set(
      bytesToHex(obligor),
      this.finalised(boxes, (box) => {
        const revocation = decodeRevocation(register(box, "R5"));
        // The box says whose it is; the signature says whether that is true.
        if (compareBytes(revocation.obligor, obligor) !== 0) {
          throw new EncodingError("box is not this key's revocation");
        }
        if (!isSignedRevocation(revocation)) {
          throw new EncodingError("revocation does not verify");
        }
        return revocation;
      }),
    );
  }

  private async syncPublications(node: ErgoNode, backingName: Uint8Array): Promise<void> {
    const publicationBoxes = await node.boxesByAddress(this.addressing.publications(backingName));
    const key = bytesToHex(backingName);
    this.ops.set(
      key,
      this.finalised(publicationBoxes, (box) => {
        const decoded = decodePublishedOp(register(box, "R5"));
        if (compareBytes(decoded.backingName, backingName) !== 0) {
          throw new EncodingError("record is not this backing's");
        }
        return decoded.op;
      }),
    );
    this.replacements.set(
      key,
      this.finalised(publicationBoxes, (box) => {
        const decoded = decodeReplacement(register(box, "R5"));
        if (compareBytes(decoded.backingName, backingName) !== 0) {
          throw new EncodingError("record is not this backing's");
        }
        return decoded.replacement;
      }),
    );
  }

  witnessedIndex(): bigint {
    return this.height;
  }

  publish(): void {
    throw new VenueError("this venue reads the chain; publishing is the operator's wallet");
  }

  publishOp(): void {
    throw new VenueError("this venue reads the chain; publishing is the operator's wallet");
  }

  publishReplacement(): void {
    throw new VenueError("this venue reads the chain; publishing is the operator's wallet");
  }

  publishRevocation(): void {
    throw new VenueError("this venue reads the chain; publishing is the backer's wallet");
  }

  publishCommit(): void {
    throw new VenueError("this venue reads the chain; publishing is the holder's wallet");
  }

  /**
   * Commits are not synced, and this refuses rather than answering empty.
   *
   * A commit is read to settle an atomic bundle, and no commits reads as "the
   * attempt did not commit" — which frees a reservation that may in fact have
   * settled elsewhere, splitting the bundle. That is the direction this venue
   * guards against everywhere else, so it guards here by not pretending: a
   * cross-operator bundle over an Ergo venue needs the box layout for a commit,
   * which is the write path this module deliberately does not build.
   */
  commitsFor(): never {
    throw new VenueError("this view does not sync commits");
  }

  /**
   * Every revocation this key published here, in witnessed order.
   *
   * The guard is the same rule as the other two, and it bites hardest here: a
   * view never synced for a key would report no revocation, and no revocation
   * reads as a live backer whose issuance is good. The other absences read as an
   * accusation against an operator; this one reads as a clean bill of health for
   * a stolen key.
   */
  revocationsFor(obligor: Uint8Array): WitnessedRevocation[] {
    this.requireRevoked(obligor);
    const log = this.revocations.get(bytesToHex(obligor)) ?? [];
    return log.map((w) => ({ revocation: w.value, at: w.at }));
  }

  private requireRevoked(obligor: Uint8Array): void {
    if (!this.revoked.has(bytesToHex(obligor))) {
      throw new VenueError("this view was not synced for that obligor key");
    }
  }

  publishedOpsFor(backingName: Uint8Array): WitnessedOp[] {
    this.requireCovered(backingName);
    const log = this.ops.get(bytesToHex(backingName)) ?? [];
    return log.map((w) => ({ op: w.value, at: w.at }));
  }

  replacementsFor(backingName: Uint8Array): WitnessedReplacement[] {
    this.requireCovered(backingName);
    const log = this.replacements.get(bytesToHex(backingName)) ?? [];
    return log.map((w) => ({ replacement: w.value, at: w.at }));
  }

  latestFor(operator: Uint8Array, asOf?: bigint): Commitment | undefined {
    this.requireFetched(operator);
    return this.latestWitnessedFor(operator, asOf)?.value;
  }

  witnessedAtFor(operator: Uint8Array, asOf?: bigint): bigint | undefined {
    this.requireFetched(operator);
    return this.latestWitnessedFor(operator, asOf)?.at;
  }

  firstCommitmentFor(operator: Uint8Array, notBefore = 0n): bigint | undefined {
    this.requireFetched(operator);
    for (const witnessed of this.commitments.get(bytesToHex(operator)) ?? []) {
      if (witnessed.at >= notBefore) return witnessed.at;
    }
    return undefined;
  }

  nextSequenceFor(operator: Uint8Array): bigint {
    this.requireFetched(operator);
    const latest = this.latestWitnessedFor(operator);
    return latest === undefined ? 0n : latest.value.sequence + 1n;
  }

  private latestWitnessedFor(
    operator: Uint8Array,
    asOf?: bigint,
  ): Witnessed<Commitment> | undefined {
    const log = this.commitments.get(bytesToHex(operator)) ?? [];
    const limit = asOf ?? this.height;
    for (let i = log.length - 1; i >= 0; i--) {
      const witnessed = log[i] as Witnessed<Commitment>;
      if (witnessed.at <= limit) return witnessed;
    }
    return undefined;
  }
}

/**
 * The registers a commitment goes into, for whoever builds the transaction.
 *
 * Written here rather than left to a wallet, so that the layout has one
 * definition and the venue above is reading back exactly what this wrote.
 */
export function commitmentRegisters(commitment: Commitment): Record<string, Uint8Array> {
  const bytes = encodeCommitment(commitment);
  const registers: Record<string, Uint8Array> = {};
  for (const [name, start, end] of COMMITMENT_LAYOUT) {
    registers[name] = bytes.slice(start, end);
  }
  return registers;
}

export { UNNAMED_VENUE };
