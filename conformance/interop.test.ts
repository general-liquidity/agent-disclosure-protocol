// The TS reference verifies the cross-stack interop fixtures it generated. This is a
// regression guard (a hand-edit to interop.json that breaks the contract fails here)
// and the template every native implementation ports: load interop.json, reproduce
// each disclosure verdict and each handshake result.

import test from "node:test";
import assert from "node:assert/strict";

import {
  parseSignedDisclosure,
  parseAnySignedDisclosure,
  evaluateDisclosure,
  verifyChallengeResponse,
  verifyRedacted,
  verifyRevocation,
  verifyInclusionProof,
  type VerificationPolicy,
  type Challenge,
  type ChallengeResponse,
  type RedactedView,
  type SignedRevocation,
  type TransparencyLogEntry,
} from "../src/index.ts";
import interop from "./interop.json" with { type: "json" };

test("interop: every disclosure case reproduces its expected verdict", () => {
  for (const c of interop.disclosures) {
    const signed = parseSignedDisclosure(c.signed);
    const verdict = evaluateDisclosure(signed, c.policy as VerificationPolicy);
    assert.equal(verdict.decision, c.expect.decision, c.name);
    const failed = Object.entries(verdict.checks)
      .filter(([, ok]) => !ok)
      .map(([k]) => k)
      .sort();
    assert.deepEqual(failed, c.expect.failed, `${c.name} failed-checks`);
  }
});

test("interop: every v2 JWS disclosure case reproduces its expected verdict", () => {
  for (const c of interop.jwsDisclosures) {
    const signed = parseAnySignedDisclosure(c.signed);
    const verdict = evaluateDisclosure(signed, c.policy as VerificationPolicy);
    assert.equal(verdict.decision, c.expect.decision, c.name);
    const failed = Object.entries(verdict.checks)
      .filter(([, ok]) => !ok)
      .map(([k]) => k)
      .sort();
    assert.deepEqual(failed, c.expect.failed, `${c.name} failed-checks`);
  }
});

test("interop: every handshake case reproduces its expected result", () => {
  for (const c of interop.handshakes) {
    const result = verifyChallengeResponse(c.response as ChallengeResponse, c.challenge as Challenge, {
      expectedAgentId: c.expectedAgentId,
      now: c.now,
    });
    assert.equal(result.ok, c.expect, c.name);
  }
});

test("interop: redaction (selective disclosure) cases verify", () => {
  for (const c of interop.redactions) {
    const r = verifyRedacted(c.view as unknown as RedactedView);
    assert.equal(r.ok, c.expect.ok, c.name);
    if (c.expect.ok) assert.deepEqual([...r.revealedFields].sort(), c.expect.revealedFields, c.name);
  }
});

test("interop: revocation records verify", () => {
  for (const c of interop.revocations) {
    assert.equal(verifyRevocation(c.record as unknown as SignedRevocation), c.expect, c.name);
  }
});

test("interop: transparency inclusion proofs verify", () => {
  for (const c of interop.transparency) {
    assert.equal(verifyInclusionProof(c.entry as unknown as TransparencyLogEntry), c.expect, c.name);
  }
});
