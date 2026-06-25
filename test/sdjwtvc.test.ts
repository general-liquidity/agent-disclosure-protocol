import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { agentIdToDidKey } from "../src/did.ts";
import type { AgentDisclosure } from "../src/schema.ts";
import {
  ADP_VCT,
  presentSdJwtVc,
  toSdJwtVc,
  verifySdJwtVc,
} from "../src/sdjwtvc.ts";

// A minimal but structurally complete disclosure (no OpenSolvency builders — stays
// vendor-neutral). Includes every redactable field so the full _sd set is exercised.
function buildDisclosure(agentId: string): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "d-1",
    agentId,
    issuedAt: "2026-01-01T00:00:00.000Z",
    validUntil: "2026-12-31T00:00:00.000Z",
    nonce: "n-abc",
    auditAnchor: "ab".repeat(32),
    systemPrompt: { algorithm: "sha256", digest: "aa".repeat(32) },
    constitution: {
      hardConstraints: [{ id: "deny-wire", description: "no wires over cap", kind: "deny" }],
      digest: "bb".repeat(32),
      enforced: true,
    },
    tools: { tools: [{ name: "place_order", access: "gated", movesValue: true }] },
    capital: {
      mandates: [
        {
          label: "ops",
          scope: "saas",
          currency: "USD",
          perTxCapMinor: 10000,
          perPeriodCapMinor: 500000,
          period: "month",
          allowedRails: ["card"],
          expiresAt: "2026-12-31T00:00:00.000Z",
        },
      ],
      custody: "non_custodial",
    },
    operator: {
      operatorId: "op-1",
      attestation: { scheme: "none", level: "none" },
      deniabilityBoundary: "operator funds the mandate; agent picks vendors",
    },
    history: {
      chainAnchor: "cc".repeat(32),
      summary: { totalDecisions: 10, settledCount: 8, blockedCount: 2 },
    },
    redTeam: {
      corpus: { name: "va-corpus", version: "1" },
      result: { grade: "A", score: 95, passed: true, hardFails: [] },
      attestedAt: "2026-01-01T00:00:00.000Z",
    },
    model: { name: "fable", fingerprintAlgorithm: "sha256", digest: "dd".repeat(32) },
    provenance: { constitution: { derivedFrom: "opensolvency-gate" } },
  };
}

const VERIFIER = "did:web:verifier.example";
const CHALLENGE = "challenge-nonce-xyz";

test("issue → present → verify round-trip reconstructs revealed claims", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution", "capital"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });
  const result = verifySdJwtVc(presentation, {
    expectedVct: ADP_VCT,
    aud: VERIFIER,
    nonce: CHALLENGE,
  });

  assert.equal(result.ok, true, result.reason);
  assert.equal(result.issuer, agentIdToDidKey(key.publicKeyHex));
  assert.deepEqual(new Set(result.revealedFields), new Set(["constitution", "capital"]));
  // clear claims survive
  assert.equal(result.claims?.vct, ADP_VCT);
  assert.equal(result.claims?.disclosureId, "d-1");
  // revealed values spliced back in
  assert.deepEqual(result.claims?.capital, disclosure.capital);
  assert.deepEqual(result.claims?.constitution, disclosure.constitution);
});

test("a withheld field's NAME is absent from the presentation (name-hiding)", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });

  // The withheld field names must not appear anywhere in the wire string. (constitution
  // IS revealed; operator/capital/model/etc are withheld.)
  for (const withheld of ["operator", "capital", "model", "history", "tools", "systemPrompt"]) {
    assert.equal(
      presentation.includes(withheld),
      false,
      `withheld field name '${withheld}' leaked into the presentation`,
    );
  }

  const result = verifySdJwtVc(presentation, { aud: VERIFIER, nonce: CHALLENGE });
  assert.equal(result.ok, true, result.reason);
  assert.deepEqual(result.revealedFields, ["constitution"]);
  assert.equal("operator" in (result.claims ?? {}), false);
});

test("decoy digests are present and hide the real field count", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const realFieldCount = 9; // every redactable field is present in buildDisclosure
  const issued = toSdJwtVc(disclosure, key, { decoys: 5 });

  // Decode the issuer JWT payload and count _sd digests.
  const issuerJwt = issued.split("~")[0];
  const payload = JSON.parse(Buffer.from(issuerJwt.split(".")[1], "base64url").toString("utf8"));
  assert.equal(Array.isArray(payload._sd), true);
  assert.equal(payload._sd.length, realFieldCount + 5);
  assert.equal(payload._sd_alg, "sha-256");

  // Zero decoys → exactly the real count (so the padding really is the decoys).
  const issuedNoDecoy = toSdJwtVc(disclosure, key, { decoys: 0 });
  const p2 = JSON.parse(
    Buffer.from(issuedNoDecoy.split("~")[0].split(".")[1], "base64url").toString("utf8"),
  );
  assert.equal(p2._sd.length, realFieldCount);
});

test("selective reveal: verifier sees exactly the chosen 2 of N", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["tools", "model"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });
  const result = verifySdJwtVc(presentation, { aud: VERIFIER, nonce: CHALLENGE });

  assert.equal(result.ok, true, result.reason);
  assert.deepEqual(new Set(result.revealedFields), new Set(["tools", "model"]));
  assert.deepEqual(result.claims?.tools, disclosure.tools);
  assert.deepEqual(result.claims?.model, disclosure.model);
  // the other 7 are not reconstructed
  assert.equal("operator" in (result.claims ?? {}), false);
  assert.equal("history" in (result.claims ?? {}), false);
});

test("KB-JWT binds aud: wrong aud rejected", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });

  const result = verifySdJwtVc(presentation, { aud: "did:web:attacker.example", nonce: CHALLENGE });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /aud/);
});

test("KB-JWT binds nonce: wrong nonce rejected", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });

  const result = verifySdJwtVc(presentation, { aud: VERIFIER, nonce: "wrong-challenge" });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /nonce/);
});

test("tampered issuer claim is rejected (issuer signature)", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const segs = issued.split("~");
  const [h, p, s] = segs[0].split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  payload.vct = "https://evil.example/credential";
  const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s}`;
  segs[0] = forged;

  const presentation = presentSdJwtVc(segs.join("~"), ["constitution"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });
  const result = verifySdJwtVc(presentation, { aud: VERIFIER, nonce: CHALLENGE });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /signature/);
});

test("unreferenced disclosure (not in _sd) is rejected", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  // Inject a fabricated, well-formed Disclosure whose digest is not in _sd.
  const fake = Buffer.from(
    JSON.stringify(["AAAAAAAAAAAAAAAAAAAAAA", "injected", { x: 1 }]),
  ).toString("base64url");
  const segs = issued.split("~");
  // place before the trailing "" terminator
  segs.splice(segs.length - 1, 0, fake);

  const presentation = presentSdJwtVc(segs.join("~"), [], key, { aud: VERIFIER, nonce: CHALLENGE });
  // presentSdJwtVc drops disclosures not in revealFieldNames, so re-inject after present
  // to exercise the verifier path directly.
  const presSegs = presentation.split("~");
  presSegs.splice(presSegs.length - 1, 0, fake); // before KB-JWT
  const result = verifySdJwtVc(presSegs.join("~"), { aud: VERIFIER, nonce: CHALLENGE });

  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /not referenced/);
});

test("duplicate disclosure digest is rejected", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });
  // duplicate the (single) revealed disclosure segment
  const segs = presentation.split("~");
  const disc = segs[1];
  segs.splice(2, 0, disc); // a second copy, still before the KB-JWT
  const result = verifySdJwtVc(segs.join("~"), { aud: VERIFIER, nonce: CHALLENGE });

  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /duplicate/);
});

test("sd_hash mismatch: dropping a disclosure after KB-JWT signing is rejected", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution", "capital"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });
  // Remove one disclosure segment AFTER the KB-JWT was computed → sd_hash no longer matches.
  const segs = presentation.split("~");
  segs.splice(1, 1); // drop the first disclosure
  const result = verifySdJwtVc(segs.join("~"), { aud: VERIFIER, nonce: CHALLENGE });

  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /sd_hash/);
});

test("expired credential is rejected when now is provided", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });
  // now = 2027, exp = end of 2026
  const result = verifySdJwtVc(presentation, {
    aud: VERIFIER,
    nonce: CHALLENGE,
    now: Math.floor(Date.parse("2027-01-01T00:00:00.000Z") / 1000),
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /expired/);
});
