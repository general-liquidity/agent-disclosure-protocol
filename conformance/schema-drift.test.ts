// Drift guard: the committed schema artifacts (schema/*.json) MUST equal what the zod
// source (src/schema.ts) regenerates. This is the "check:schema" gate — if someone edits
// an enum in zod without regenerating, or hand-edits a committed artifact, CI fails here.
// Regenerate with: node --import tsx scripts/generate-schema.ts

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildArtifacts } from "../scripts/generate-schema.ts";

// Compare content, not line endings: on Windows `core.autocrlf` checks the committed
// schema/*.json out as CRLF while the generator emits LF, so normalize before diffing.
const lf = (s: string) => s.replace(/\r\n/g, "\n");

test("schema artifacts are in sync with the zod source", () => {
  const root = new URL("..", import.meta.url);
  for (const [rel, expected] of Object.entries(buildArtifacts())) {
    const committed = readFileSync(fileURLToPath(new URL(rel, root)), "utf8");
    assert.equal(
      lf(committed),
      lf(expected),
      `${rel} is out of sync with src/schema.ts — regenerate: node --import tsx scripts/generate-schema.ts`,
    );
  }
});

// Sanity: the JSON Schema grammar and the constraints manifest agree on the enums (they
// come from the same consts, but this pins that they stay co-derived).
test("constraints.json enums match the JSON Schema enums", () => {
  const root = new URL("..", import.meta.url);
  const read = (rel: string) => JSON.parse(readFileSync(fileURLToPath(new URL(rel, root)), "utf8"));
  const constraints = read("schema/constraints.json");
  const js = read("schema/disclosure.schema.json");
  assert.deepEqual(js.properties.capital.properties.custody.enum, constraints.custody);
  assert.deepEqual(js.properties.operator.properties.attestation.properties.level.enum, constraints.attestationLevel);
  // scheme is anyOf[known-enum, reverse-domain-pattern]
  const schemeAnyOf = js.properties.operator.properties.attestation.properties.scheme.anyOf;
  assert.deepEqual(schemeAnyOf[0].enum, constraints.attestationSchemeKnown);
  assert.equal(schemeAnyOf[1].pattern, constraints.attestationSchemeReverseDomainPattern);
});
