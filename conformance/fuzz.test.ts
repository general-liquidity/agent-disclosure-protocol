// Differential canonicalization fuzz suite (TS reference leg). Loads the committed
// conformance/fuzz.json corpus and asserts the reference reproduces every recorded
// `canonical`, then adds the two algebraic properties canonicalization must hold for
// ANY input: key-order independence and idempotence. The native suites (Go, Python,
// Rust, C) load the SAME fuzz.json and assert byte-for-byte, which is what proves the
// five stacks agree on random inputs - not just the fixed vectors.

import test from "node:test";
import assert from "node:assert/strict";

import { canonicalize } from "../src/index.ts";
import fuzz from "./fuzz.json" with { type: "json" };

interface FuzzCase {
  input: unknown;
  canonical: string;
}

const cases = fuzz as FuzzCase[];

test("fuzz: corpus is non-empty (guards against an empty/stale fuzz.json)", () => {
  assert.ok(cases.length >= 200, `expected >= 200 fuzz cases, got ${cases.length}`);
});

test("fuzz: reference reproduces every recorded canonical byte-for-byte", () => {
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    assert.equal(canonicalize(c.input), c.canonical, `fuzz[${i}] input=${JSON.stringify(c.input)}`);
  }
});

// ── Property: key-order independence ─────────────────────────────────────────
// Re-serializing then re-parsing through a key-shuffling reviver yields a value with
// the same content but different insertion order; canonicalize MUST collapse both to
// the same string. This is the property that makes cross-stack signatures verify.
function shuffleKeysDeep(value: unknown, rng: () => number): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => shuffleKeysDeep(v, rng));
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);
  for (let i = keys.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [keys[i], keys[j]] = [keys[j], keys[i]];
  }
  const out: Record<string, unknown> = {};
  for (const k of keys) out[k] = shuffleKeysDeep(obj[k], rng);
  return out;
}

// Local deterministic PRNG so the property check itself is reproducible.
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

test("fuzz: canonicalize is key-order independent (shuffled keys yield same string)", () => {
  const rng = makeRng(0x1234abcd);
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    const shuffled = shuffleKeysDeep(c.input, rng);
    assert.equal(canonicalize(shuffled), c.canonical, `fuzz[${i}] shuffled keys diverged`);
  }
});

test("fuzz: canonicalize is idempotent over re-parsed canonical output", () => {
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    // Re-parsing the canonical string yields the same JSON value; canonicalizing it
    // again must produce the identical canonical string.
    const reparsed = JSON.parse(c.canonical);
    assert.equal(canonicalize(reparsed), c.canonical, `fuzz[${i}] not idempotent`);
  }
});
