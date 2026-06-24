// Differential canonicalization fuzzer. Generates a corpus of pseudo-random JSON
// values (objects with shuffled keys, arrays, strings with escapes, integers,
// booleans, null - deliberately NO floats and NO undefined, since the protocol's
// canonical form is defined over parsed-JSON values), canonicalizes each with the
// TS REFERENCE, and writes conformance/fuzz.json. Every native stack re-runs the
// same file and must reproduce `canonical` byte-for-byte: this proves the five
// implementations agree on RANDOM inputs, not just the fixed vectors.
//
// The PRNG is a tiny seeded xorshift32 so the output is deterministic across runs
// and machines - the committed fuzz.json is a stable regression artifact.
//
// Run: node --import tsx conformance/generate-fuzz.ts

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { canonicalize } from "../src/index.ts";

// ── Seeded PRNG (xorshift32) ─────────────────────────────────────────────────
// Fixed seed → identical corpus every run. Non-zero seed required.
const SEED = 0x9e3779b9;

function makeRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x100000000;
  };
}

const rng = makeRng(SEED);

function randInt(maxExclusive: number): number {
  return Math.floor(rng() * maxExclusive);
}

function pick<T>(xs: readonly T[]): T {
  return xs[randInt(xs.length)];
}

// ── Value generators ─────────────────────────────────────────────────────────
// Strings drawn from a pool that exercises the JSON escapes canonicalize relies on
// (JSON.stringify): quotes, backslashes, control chars, unicode, surrogate pairs.
const STRING_POOL = [
  "",
  "hi",
  "a b c",
  'quote " inside',
  "back\\slash",
  "tab\there",
  "newline\nhere",
  "carriage\rreturn",
  "plain text",
  "unicode éü☃",
  "emoji \u{1f600}\u{1f4a1}",
  'mixed "\\/\b\f\n\r\t end',
  "key-like:value",
  "{not json}",
  "[1,2,3]",
];

// Object keys deliberately include strings that sort non-trivially and need escaping,
// so the sorted-key canonicalization is exercised on awkward keys too.
const KEY_POOL = [
  "a",
  "b",
  "c",
  "z",
  "A",
  "Z",
  "0",
  "10",
  "2",
  "key",
  "KEY",
  "with space",
  'with"quote',
  "with\\slash",
  "é",
  "nested",
  "list",
  "value",
];

const INT_POOL = [0, 1, -1, 2, 42, -42, 100, -100, 255, 1024, -1024, 2147483647, -2147483648];

function randString(): unknown {
  return pick(STRING_POOL);
}

function randInteger(): unknown {
  return pick(INT_POOL);
}

function randBool(): unknown {
  return rng() < 0.5;
}

function randNull(): unknown {
  return null;
}

// Shuffle keys so the generated object's insertion order is randomized - the whole
// point is that canonicalize sorts them regardless of how they arrive.
function shuffle<T>(xs: T[]): T[] {
  const out = [...xs];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

// Depth-bounded recursive generator. At depth 0 only scalars are produced, so the
// structure always terminates.
function randValue(depth: number): unknown {
  const scalars = [randString, randInteger, randBool, randNull];
  if (depth <= 0) return pick(scalars)();

  const kind = randInt(6);
  if (kind === 0) return randArray(depth);
  if (kind === 1) return randObject(depth);
  return pick(scalars)();
}

function randArray(depth: number): unknown[] {
  const n = randInt(5); // 0..4 elements
  const out: unknown[] = [];
  for (let i = 0; i < n; i++) out.push(randValue(depth - 1));
  return out;
}

function randObject(depth: number): Record<string, unknown> {
  const n = 1 + randInt(5); // 1..5 keys
  const keys = shuffle([...KEY_POOL]).slice(0, n);
  const obj: Record<string, unknown> = {};
  for (const k of keys) obj[k] = randValue(depth - 1);
  return obj;
}

// ── Corpus ───────────────────────────────────────────────────────────────────
const CASE_COUNT = 200;
const MAX_DEPTH = 4;

export interface FuzzCase {
  input: unknown;
  canonical: string;
}

export function generateFuzzCases(): FuzzCase[] {
  const cases: FuzzCase[] = [];
  for (let i = 0; i < CASE_COUNT; i++) {
    // Bias the top level toward containers so most cases exercise key sorting.
    const top = i % 3 === 0 ? randArray(MAX_DEPTH) : randObject(MAX_DEPTH);
    cases.push({ input: top, canonical: canonicalize(top) });
  }
  return cases;
}

function main(): void {
  const cases = generateFuzzCases();
  const out = fileURLToPath(new URL("./fuzz.json", import.meta.url));
  writeFileSync(out, `${JSON.stringify(cases, null, 2)}\n`, "utf8");
  // eslint-disable-next-line no-console
  console.log(`wrote ${cases.length} fuzz cases to ${out}`);
}

if (
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith("generate-fuzz.ts")
) {
  main();
}
