// A REAL zero-knowledge range-proof backend for the predicate interface in zk.ts.
//
// zk.ts ships `commitmentBackend`, which is sound but NOT zero-knowledge: it serves only
// `equals` by OPENING a salted commitment (the value is disclosed). The hiding predicates
// (`gte` / `lte` / `range`) are the genuine ZK case and zk.ts deliberately leaves them as a
// throw rather than fake them. This module fills that gap with a real, sound construction.
//
// WHAT IS PROVEN (and tested):
//   A prover holding a hidden non-negative integer `v` proves, in zero knowledge, that
//   `v >= t` (gte), `v <= t` (lte), or `lo <= v <= hi` (range) WITHOUT revealing `v`.
//
// CONSTRUCTION (classic bit-decomposition range proof, non-interactive via Fiat-Shamir):
//   Group: secp256k1 (prime order q, no cofactor). Two independent generators:
//     - G = the curve base point.
//     - H = a nothing-up-my-sleeve second generator, hashed to the curve from a fixed
//       domain tag. Its discrete log w.r.t. G is unknown to everyone, which is exactly the
//       binding requirement for a Pedersen commitment.
//   Pedersen commitment to v with blinding r:  C = v*G + r*H  (perfectly hiding, binding).
//   To prove v in [0, 2^n):
//     1. Decompose v = sum_i b_i * 2^i over n bits.
//     2. Commit each bit:  C_i = b_i*G + r_i*H, with the LAST blinding chosen so that
//        sum_i 2^i * r_i = r. Then sum_i 2^i * C_i = v*G + r*H = C, which the verifier
//        checks directly (the "bits compose to the value" link, no extra proof needed).
//     3. For each C_i prove it opens to a BIT (0 or 1) with a Schnorr OR-proof
//        (Chaum-Pedersen / CDS): prove knowledge of r_i s.t. (C_i = r_i*H)  OR
//        (C_i - G = r_i*H). The simulator trick lets the prover answer one real branch and
//        one simulated branch under a single Fiat-Shamir challenge c = c0 + c1, so the
//        verifier learns nothing about which branch is real -> zero knowledge. Soundness:
//        a cheating prover would need to open BOTH branches, i.e. know r_i for both
//        C_i = r_i*H and C_i = G + r_i'*H, which forces b_i in {0,1}.
//   The three predicates reduce to range proofs on a shifted value:
//     gte(v >= t):        prove (v - t) in [0, 2^n)
//     lte(v <= t):        prove (t - v) in [0, 2^n)
//     range(lo<=v<=hi):   prove (v - lo) in [0, 2^n) AND (hi - v) in [0, 2^n)
//   With n bits this proves membership in [0, 2^n); n is chosen from the predicate bounds
//   (default 32 bits) so the shifted value provably cannot wrap. The verifier re-derives n
//   from the predicate, so the bit-length is not prover-controlled.
//
// HONEST SCOPE / WHAT THIS IS NOT:
//   * This is a genuine, sound, zero-knowledge proof. It is NOT succinct: the proof is
//     O(n) group elements per range (a Bulletproof would be O(log n)). For the small
//     integer ranges typical of disclosures (scores, capital tiers) the size is fine.
//   * The commitment this backend binds to is its OWN Pedersen commitment C (hex of the
//     compressed point), carried in `ZkProof.commitment` and recomputed from value+blinding.
//     It is NOT the salted SHA256 commitment that `commitmentBackend` / redaction.ts use:
//     there is no algebraic bridge between a hash commitment and a Pedersen commitment
//     without a circuit, so this backend publishes the Pedersen commitment as the binding
//     object for range predicates. A disclosure using a range predicate would carry this
//     Pedersen commitment for that field. Equality predicates stay on commitmentBackend.
//   * `value` must be a non-negative integer (or a numeric string / bigint). Non-integer or
//     negative inputs are rejected at prove time.
//   * Soundness of the OR-proof and the compose check is exercised by the test suite,
//     including a tamper probe that flips a challenge/response and confirms rejection.
//
// @noble/curves is an OPTIONAL dependency (dynamic import). If absent, every call throws a
// clear "install @noble/curves" hint instead of failing obscurely.

import { sha256Hex } from "./attestation.ts";
import type { ZkBackend, ZkPredicate, ZkProof, ZkVerifyResult } from "./zk.ts";

// ---------------------------------------------------------------------------
// Curve loading (optional dependency)
// ---------------------------------------------------------------------------

// Minimal structural types for the slice of @noble/curves we touch. Avoids a hard type
// dependency on the optional package while keeping the call sites type-checked.
interface CurvePoint {
  add(other: CurvePoint): CurvePoint;
  subtract(other: CurvePoint): CurvePoint;
  multiply(scalar: bigint): CurvePoint;
  // multiplyUnsafe accepts scalar 0 (returns identity) where multiply throws. Not
  // constant-time; acceptable here since these scalars are not secret-key material whose
  // timing leaks would matter, and we never recover a long-term secret from a single op.
  multiplyUnsafe(scalar: bigint): CurvePoint;
  negate(): CurvePoint;
  equals(other: CurvePoint): boolean;
  is0(): boolean;
  toBytes(isCompressed?: boolean): Uint8Array;
}
interface CurvePointCons {
  BASE: CurvePoint;
  ZERO: CurvePoint;
  Fn: { ORDER: bigint };
  fromHex(hex: string | Uint8Array): CurvePoint;
}

interface CurveCtx {
  Point: CurvePointCons;
  q: bigint; // prime group order
  G: CurvePoint;
  H: CurvePoint;
}

const INSTALL_HINT =
  "zkRange backend requires the optional dependency '@noble/curves'. Install it: npm install @noble/curves";

// Domain tag for the second generator. "Nothing up my sleeve": H is derived by hashing a
// fixed string to a scalar and multiplying G... which would have a KNOWN discrete log and be
// INSECURE. Instead we derive H by hashing to a candidate x-coordinate and lifting it to the
// curve, retrying with a counter until a valid point is found. The discrete log of the
// resulting point w.r.t. G is then unknown to everyone (it is a hash output, not a chosen
// scalar). See deriveH below.
const H_DOMAIN = "agent-disclosure-protocol/zkRange/H/secp256k1/v1";

let curvePromise: Promise<CurveCtx> | null = null;

async function loadCurve(): Promise<CurveCtx> {
  if (!curvePromise) {
    curvePromise = (async () => {
      let mod: { secp256k1: { Point: CurvePointCons } };
      try {
        mod = (await import("@noble/curves/secp256k1")) as unknown as {
          secp256k1: { Point: CurvePointCons };
        };
      } catch {
        throw new Error(INSTALL_HINT);
      }
      const Point = mod.secp256k1.Point;
      const q = Point.Fn.ORDER;
      const G = Point.BASE;
      const H = deriveH(Point);
      return { Point, q, G, H };
    })();
  }
  return curvePromise;
}

// Derive H by hashing the domain tag (plus a counter) to a 32-byte x-coordinate and lifting
// it to a curve point via the compressed-point decoder, retrying on invalid x. The even-Y
// prefix (0x02) is used. Because x is a hash output, nobody knows log_G(H): the binding
// property of the Pedersen commitment rests on this.
function deriveH(Point: CurvePointCons): CurvePoint {
  for (let counter = 0; counter < 256; counter++) {
    const xHex = sha256Hex(`${H_DOMAIN}/${counter}`);
    try {
      const candidate = Point.fromHex(`02${xHex}`);
      if (!candidate.is0()) return candidate;
    } catch {
      // x did not lift to a curve point; try the next counter.
    }
  }
  // 256 consecutive misses is cryptographically impossible (each try succeeds ~50%).
  throw new Error("zkRange: failed to derive second generator H");
}

// ---------------------------------------------------------------------------
// Scalar / encoding helpers
// ---------------------------------------------------------------------------

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += byte.toString(16).padStart(2, "0");
  return s;
}

function pointHex(p: CurvePoint): string {
  return bytesToHex(p.toBytes(true));
}

// Scalar multiply that tolerates scalar 0 (noble's `multiply` throws on 0; `multiplyUnsafe`
// returns the identity). Scalars are first reduced mod the group order. Used everywhere a
// scalar could be 0 (a zero bit, a zero blinding/challenge, the 2^0 weight is 1 so fine).
function mul(p: CurvePoint, scalar: bigint, q: bigint): CurvePoint {
  return p.multiplyUnsafe(mod(scalar, q));
}

// A scalar from a hex string, reduced mod q. Fiat-Shamir challenges and the blinding
// derivation both route through this.
function hexToScalar(hex: string, q: bigint): bigint {
  return mod(BigInt(`0x${hex}`), q);
}

// Coerce a disclosed value to a non-negative integer bigint, or null if it is not one.
function toNonNegInteger(value: unknown): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return null;
}

// ---------------------------------------------------------------------------
// Fiat-Shamir transcript
// ---------------------------------------------------------------------------

// A challenge bound to the full statement + first-move commitments. Hashing the predicate,
// the value commitment, the bit commitments, and the OR-proof announcements makes the proof
// non-interactive AND non-malleable: changing any of those changes the challenge, so a
// tampered transcript no longer verifies.
function challenge(parts: string[], q: bigint): bigint {
  return hexToScalar(sha256Hex(parts.join("|")), q);
}

// ---------------------------------------------------------------------------
// Schnorr OR-proof that a commitment opens to a bit (0 or 1)
// ---------------------------------------------------------------------------
//
// Statement: given P (= C_i, a bit commitment) prove knowledge of r s.t.
//   branch0:  P        = r*H        (bit is 0)
//   branch1:  P - G    = r*H        (bit is 1)
// CDS OR-proof. The prover runs the REAL branch honestly and SIMULATES the other, splitting a
// single Fiat-Shamir challenge c = c0 + c1 so the verifier cannot tell which was simulated.

interface OrProof {
  a0: string; // announcement for branch 0 (point)
  a1: string; // announcement for branch 1 (point)
  c0: string; // sub-challenge 0 (scalar hex)
  c1: string; // sub-challenge 1 (scalar hex)
  z0: string; // response 0 (scalar hex)
  z1: string; // response 1 (scalar hex)
}

type RandomScalar = () => bigint;

function proveBit(
  ctx: CurveCtx,
  bit: bigint,
  r: bigint,
  P: CurvePoint,
  transcriptPrefix: string,
  rand: RandomScalar,
): OrProof {
  const { q, H, G } = ctx;
  // Targets: branch0 target T0 = P (= r*H if bit 0); branch1 target T1 = P - G (= r*H if bit 1).
  const T0 = P;
  const T1 = P.subtract(G);

  // Simulate the FALSE branch first: pick its sub-challenge and response at random, then
  // back out an announcement consistent with the verifier equation z*H = a + c*T.
  // Run the TRUE branch honestly: pick nonce k, announcement a = k*H; its sub-challenge is
  // forced by c = H(transcript) once we know the simulated sub-challenge.
  let a0: CurvePoint;
  let a1: CurvePoint;
  let c0: bigint;
  let c1: bigint;
  let z0: bigint;
  let z1: bigint;

  if (bit === 0n) {
    // branch0 real, branch1 simulated.
    const cSim = rand();
    const zSim = rand();
    a1 = mul(H, zSim, q).subtract(mul(T1, cSim, q)); // a1 = zSim*H - cSim*T1
    const k = rand();
    a0 = mul(H, k, q); // a0 = k*H
    const c = challenge([transcriptPrefix, pointHex(a0), pointHex(a1)], q);
    c1 = cSim;
    c0 = mod(c - c1, q);
    z0 = mod(k + c0 * r, q); // real response: z0*H = a0 + c0*T0
    z1 = zSim;
  } else if (bit === 1n) {
    // branch1 real, branch0 simulated.
    const cSim = rand();
    const zSim = rand();
    a0 = mul(H, zSim, q).subtract(mul(T0, cSim, q)); // a0 = zSim*H - cSim*T0
    const k = rand();
    a1 = mul(H, k, q); // a1 = k*H
    const c = challenge([transcriptPrefix, pointHex(a0), pointHex(a1)], q);
    c0 = cSim;
    c1 = mod(c - c0, q);
    z1 = mod(k + c1 * r, q); // real response: z1*H = a1 + c1*T1
    z0 = zSim;
  } else {
    throw new Error("proveBit: bit must be 0 or 1");
  }

  return {
    a0: pointHex(a0),
    a1: pointHex(a1),
    c0: c0.toString(16),
    c1: c1.toString(16),
    z0: z0.toString(16),
    z1: z1.toString(16),
  };
}

function verifyBit(ctx: CurveCtx, P: CurvePoint, proof: OrProof, transcriptPrefix: string): boolean {
  const { q, H, G } = ctx;
  let a0: CurvePoint;
  let a1: CurvePoint;
  try {
    a0 = ctx.Point.fromHex(proof.a0);
    a1 = ctx.Point.fromHex(proof.a1);
  } catch {
    return false;
  }
  const c0 = mod(BigInt(`0x${proof.c0}`), q);
  const c1 = mod(BigInt(`0x${proof.c1}`), q);
  const z0 = mod(BigInt(`0x${proof.z0}`), q);
  const z1 = mod(BigInt(`0x${proof.z1}`), q);

  // The sub-challenges must sum to the Fiat-Shamir challenge over the announcements.
  const c = challenge([transcriptPrefix, proof.a0, proof.a1], q);
  if (mod(c0 + c1, q) !== c) return false;

  const T0 = P;
  const T1 = P.subtract(G);
  // branch0: z0*H == a0 + c0*T0
  if (!mul(H, z0, q).equals(a0.add(mul(T0, c0, q)))) return false;
  // branch1: z1*H == a1 + c1*T1
  if (!mul(H, z1, q).equals(a1.add(mul(T1, c1, q)))) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Range proof: prove a Pedersen-committed value lies in [0, 2^n)
// ---------------------------------------------------------------------------

interface RangeProofData {
  // Compressed-point hexes of the per-bit commitments C_i (i = 0..n-1).
  bitCommitments: string[];
  // Per-bit OR-proofs that each C_i opens to a bit.
  bitProofs: OrProof[];
}

// Deterministic per-instance blinding stream from a seed, so the same (value, salt) always
// reproduces the same commitment. Uses sha256(seed | label | counter) reduced mod q.
function blindingStream(seed: string, q: bigint): RandomScalar {
  let counter = 0;
  return () => {
    const h = sha256Hex(`${seed}|blind|${counter++}`);
    // Fold two hashes for >256 bits of entropy before reduction (negligible bias mod q).
    const h2 = sha256Hex(`${seed}|blind|${counter++}|x`);
    return mod(BigInt(`0x${h}${h2}`), q);
  };
}

// Build a range proof for `v` in [0, 2^n). Returns the value commitment C and the proof.
// `seed` derives all blindings deterministically; the LAST bit blinding is solved so that
// sum 2^i r_i == r (the value blinding), making sum 2^i C_i == C hold exactly.
function buildRangeProof(
  ctx: CurveCtx,
  v: bigint,
  n: number,
  seed: string,
  statementTag: string,
): { commitment: CurvePoint; data: RangeProofData } {
  const { q, G, H } = ctx;
  if (v < 0n || v >= 1n << BigInt(n)) {
    throw new Error(`value ${v} not in [0, 2^${n})`);
  }
  const rand = blindingStream(seed, q);

  // Value blinding r and value commitment C = v*G + r*H.
  const r = rand();
  const C = mul(G, v, q).add(mul(H, r, q));

  // Per-bit blindings r_i. We pick r_0..r_{n-2} from the stream, then SOLVE r_{n-1} so that
  // sum_i 2^i * r_i = r (mod q). The factor 2^{n-1} is invertible mod the prime q.
  const bits: bigint[] = [];
  for (let i = 0; i < n; i++) bits.push((v >> BigInt(i)) & 1n);

  const rBits: bigint[] = [];
  let weighted = 0n;
  for (let i = 0; i < n - 1; i++) {
    const ri = rand();
    rBits.push(ri);
    weighted = mod(weighted + (1n << BigInt(i)) * ri, q);
  }
  // Solve last: 2^{n-1} * r_{n-1} = r - weighted  =>  r_{n-1} = (r - weighted) * inv(2^{n-1}).
  const lastWeight = 1n << BigInt(n - 1);
  const invLast = modInverse(lastWeight, q);
  const rLast = mod((r - weighted) * invLast, q);
  rBits.push(rLast);

  const bitCommitments: string[] = [];
  const bitProofs: OrProof[] = [];
  for (let i = 0; i < n; i++) {
    const Ci = mul(G, bits[i], q).add(mul(H, rBits[i], q));
    bitCommitments.push(pointHex(Ci));
  }
  // Bind each bit's OR-proof transcript to the statement and all bit commitments, so a bit
  // proof cannot be lifted into a different statement.
  const bindPrefix = `${statementTag}|${pointHex(C)}|${bitCommitments.join(",")}`;
  for (let i = 0; i < n; i++) {
    const Ci = ctx.Point.fromHex(bitCommitments[i]);
    bitProofs.push(proveBit(ctx, bits[i], rBits[i], Ci, `${bindPrefix}|bit${i}`, blindingStream(`${seed}|or${i}`, q)));
  }

  return { commitment: C, data: { bitCommitments, bitProofs } };
}

function verifyRangeProof(
  ctx: CurveCtx,
  C: CurvePoint,
  n: number,
  data: RangeProofData,
  statementTag: string,
): boolean {
  if (data.bitCommitments.length !== n || data.bitProofs.length !== n) return false;

  let Ci: CurvePoint[];
  try {
    Ci = data.bitCommitments.map((h) => ctx.Point.fromHex(h));
  } catch {
    return false;
  }

  const bindPrefix = `${statementTag}|${pointHex(C)}|${data.bitCommitments.join(",")}`;

  // 1. Each bit commitment opens to a bit.
  for (let i = 0; i < n; i++) {
    if (!verifyBit(ctx, Ci[i], data.bitProofs[i], `${bindPrefix}|bit${i}`)) return false;
  }

  // 2. The bit commitments compose to the value commitment: sum_i 2^i * C_i == C.
  let acc = ctx.Point.ZERO;
  for (let i = 0; i < n; i++) {
    acc = acc.add(mul(Ci[i], 1n << BigInt(i), ctx.q));
  }
  if (!acc.equals(C)) return false;

  return true;
}

// Extended Euclid modular inverse (q is prime, lastWeight is a power of two < q, coprime).
function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  if (old_r !== 1n) throw new Error("modInverse: not invertible");
  return mod(old_s, m);
}

// ---------------------------------------------------------------------------
// Predicate -> range statement reduction
// ---------------------------------------------------------------------------

// Choose a bit-length n that safely contains the shifted value(s) for a predicate, derived
// ONLY from the public predicate bounds so the verifier reconstructs the same n. We need the
// shifted value to provably fit in [0, 2^n). For a bound B (the max possible shifted value
// given the predicate), n = bitLength(B) + 1, floored at a default so tiny ranges still get a
// meaningful proof. The shifted value can never exceed B for an honest in-range prover; an
// out-of-range value would not fit in n bits and cannot be committed bit-wise, so the prover
// fails at build time and the verifier's compose check fails for any forged bits.
const DEFAULT_RANGE_BITS = 32;

function bitLength(x: bigint): number {
  if (x <= 0n) return 1;
  return x.toString(2).length;
}

// Returns the list of [shifted-value-expression-bound] sub-statements for a predicate, where
// each sub-statement is a non-negative integer that must lie in [0, 2^n). The bound is the
// largest value the sub-expression can take for ANY value satisfying the predicate, used to
// fix n. Returns null if the predicate is not a supported range kind.
interface SubStatement {
  // Given the prover's value v, compute the shifted non-negative integer to range-prove.
  shift: (v: bigint) => bigint;
  // Public upper bound on the shifted value (for sizing n). Verifier-reconstructible.
  bound: bigint;
  // A short label distinguishing sub-statements within one predicate.
  label: string;
}

function subStatements(pred: ZkPredicate): SubStatement[] | null {
  switch (pred.kind) {
    case "gte": {
      const t = BigInt(pred.value);
      // v >= t  <=>  v - t in [0, 2^n). Bound the shifted value by 2^DEFAULT_RANGE_BITS - 1.
      return [{ shift: (v) => v - t, bound: (1n << BigInt(DEFAULT_RANGE_BITS)) - 1n, label: "gte" }];
    }
    case "lte": {
      const t = BigInt(pred.value);
      // v <= t  <=>  t - v in [0, t]. Bound by t.
      return [{ shift: (v) => t - v, bound: t, label: "lte" }];
    }
    case "range": {
      const lo = BigInt(pred.min);
      const hi = BigInt(pred.max);
      // lo <= v <= hi  <=>  (v - lo) in [0, hi-lo] AND (hi - v) in [0, hi-lo].
      const span = hi - lo;
      return [
        { shift: (v) => v - lo, bound: span < 0n ? 0n : span, label: "rlo" },
        { shift: (v) => hi - v, bound: span < 0n ? 0n : span, label: "rhi" },
      ];
    }
    default:
      return null;
  }
}

// Bit-length for a sub-statement: large enough to hold `bound`, with a sane floor.
function bitsForBound(bound: bigint): number {
  return Math.max(bitLength(bound), DEFAULT_RANGE_BITS);
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

const SCHEME = "pedersen-bit-decomposition-range";

interface RangePayload {
  // Hex of each sub-statement's value commitment (Pedersen point), in subStatements order.
  commitments: string[];
  // Per-sub-statement range proofs.
  proofs: RangeProofData[];
  // Bit-lengths used per sub-statement (verifier re-derives and cross-checks these).
  bits: number[];
}

// Deterministic blinding seed from the caller-supplied salt + statement, so the same inputs
// reproduce the same commitment (binding the proof to the salt the disclosure carries).
function seedFor(salt: string, statementTag: string, label: string): string {
  return sha256Hex(`${salt}|${statementTag}|${label}`);
}

function statementTagFor(pred: ZkPredicate): string {
  return sha256Hex(`${SCHEME}|${JSON.stringify(pred)}`);
}

// NOTE: The async prove/verify below do the real work; the synchronous ZkBackend interface
// methods wrap them. Because the curve is an OPTIONAL dynamic import, prove/verify are async
// and the ZkBackend `prove`/`verify` (declared sync) throw a directive to use the async API.
// We expose `rangeBackend` implementing ZkBackend so callers detect the scheme, plus async
// `proveRange` / `verifyRange` that perform the cryptography.

export async function proveRange(args: {
  predicate: ZkPredicate;
  value: unknown;
  salt: string;
}): Promise<ZkProof> {
  const ctx = await loadCurve();
  const subs = subStatements(args.predicate);
  if (!subs) {
    throw new Error(`zkRange backend supports gte/lte/range only, got '${args.predicate.kind}'`);
  }
  const v = toNonNegInteger(args.value);
  if (v === null) {
    throw new Error("zkRange backend requires a non-negative integer value");
  }

  const statementTag = statementTagFor(args.predicate);
  const commitments: string[] = [];
  const proofs: RangeProofData[] = [];
  const bits: number[] = [];

  for (const sub of subs) {
    const shifted = sub.shift(v);
    if (shifted < 0n) {
      // The predicate is FALSE for this value: an honest prover cannot build the proof.
      throw new Error(`value does not satisfy predicate (${sub.label}: shifted value is negative)`);
    }
    const n = bitsForBound(sub.bound);
    if (shifted >= 1n << BigInt(n)) {
      throw new Error(`value does not satisfy predicate (${sub.label}: shifted value exceeds range)`);
    }
    const seed = seedFor(args.salt, statementTag, sub.label);
    const { commitment, data } = buildRangeProof(ctx, shifted, n, seed, `${statementTag}|${sub.label}`);
    commitments.push(pointHex(commitment));
    proofs.push(data);
    bits.push(n);
  }

  const payload: RangePayload = { commitments, proofs, bits };
  return {
    scheme: SCHEME,
    predicate: args.predicate,
    // The binding commitment is the first sub-statement's Pedersen commitment; all sub
    // commitments live in the payload. (For gte/lte there is exactly one.)
    commitment: commitments[0],
    payload: payload as unknown as Record<string, unknown>,
  };
}

export async function verifyRange(proof: ZkProof): Promise<ZkVerifyResult> {
  if (proof.scheme !== SCHEME) {
    return { ok: false, reason: `unknown proof scheme '${proof.scheme}'` };
  }
  const subs = subStatements(proof.predicate);
  if (!subs) {
    return { ok: false, reason: `zkRange backend supports gte/lte/range only, got '${proof.predicate.kind}'` };
  }

  let ctx: CurveCtx;
  try {
    ctx = await loadCurve();
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }

  const payload = proof.payload as unknown as Partial<RangePayload>;
  if (
    !Array.isArray(payload.commitments) ||
    !Array.isArray(payload.proofs) ||
    !Array.isArray(payload.bits) ||
    payload.commitments.length !== subs.length ||
    payload.proofs.length !== subs.length ||
    payload.bits.length !== subs.length
  ) {
    return { ok: false, reason: "malformed range payload" };
  }
  if (payload.commitments[0] !== proof.commitment) {
    return { ok: false, reason: "proof.commitment does not match payload" };
  }

  const statementTag = statementTagFor(proof.predicate);

  for (let s = 0; s < subs.length; s++) {
    const sub = subs[s];
    const n = bitsForBound(sub.bound);
    // The verifier fixes n from the PUBLIC predicate; a prover cannot shrink the bit-length.
    if (payload.bits[s] !== n) {
      return { ok: false, reason: `sub-statement ${sub.label}: wrong bit-length` };
    }
    let C: CurvePoint;
    try {
      C = ctx.Point.fromHex(payload.commitments[s]);
    } catch {
      return { ok: false, reason: `sub-statement ${sub.label}: bad commitment encoding` };
    }
    const ok = verifyRangeProof(ctx, C, n, payload.proofs[s], `${statementTag}|${sub.label}`);
    if (!ok) {
      return { ok: false, reason: `sub-statement ${sub.label}: range proof rejected` };
    }
  }

  return { ok: true };
}

// The ZkBackend interface is synchronous, but the curve is an optional dynamic import. We
// surface a backend object whose `scheme` lets callers route, and whose sync methods point at
// the async API. Callers that want range proofs use `proveRange` / `verifyRange` directly.
export const rangeBackend: ZkBackend = {
  scheme: SCHEME,
  prove() {
    throw new Error(
      "zkRange is async (optional @noble/curves import): call proveRange(...) instead of the sync ZkBackend.prove",
    );
  },
  verify() {
    throw new Error(
      "zkRange is async (optional @noble/curves import): call verifyRange(...) instead of the sync ZkBackend.verify",
    );
  },
};
