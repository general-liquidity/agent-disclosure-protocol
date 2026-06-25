import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { agentIdToDidKey } from "../src/did.ts";
import type { AgentDisclosure } from "../src/schema.ts";
import {
  ADP_VCT,
  __setSdJwtVcLoader,
  presentSdJwtVc,
  toSdJwtVc,
  verifySdJwtVc,
  verifySdJwtVcWithLib,
} from "../src/sdjwtvc.ts";

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
    constitution: { hardConstraints: [], digest: "bb".repeat(32), enforced: true },
    tools: { tools: [{ name: "place_order", access: "gated", movesValue: true }] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: {
      operatorId: "op-1",
      attestation: { scheme: "none", level: "none" },
      deniabilityBoundary: "operator funds the mandate; agent picks vendors",
    },
    history: { chainAnchor: "cc".repeat(32), summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
    model: { name: "fable", fingerprintAlgorithm: "sha256", digest: "dd".repeat(32) },
  } as AgentDisclosure;
}

const VERIFIER = "did:web:verifier.example";
const CHALLENGE = "challenge-nonce-xyz";

// A mock `@sd-jwt/sd-jwt-vc` whose SDJwtVcInstance.verify delegates to ADP's own bespoke
// verifySdJwtVc — this confirms the OPTIONAL library path returns the same disclosure as
// the bespoke path (the requirement), and exercises the wiring (callbacks, hasher, claim
// mapping) without installing the real package.
function sdJwtMockLoader() {
  return async () => ({
    SDJwtVcInstance: class {
      private verifier: (data: string, sig: string) => boolean | Promise<boolean>;
      private kbVerifier?: (data: string, sig: string) => boolean | Promise<boolean>;
      constructor(config: {
        verifier: (data: string, sig: string) => boolean | Promise<boolean>;
        kbVerifier?: (data: string, sig: string) => boolean | Promise<boolean>;
      }) {
        this.verifier = config.verifier;
        this.kbVerifier = config.kbVerifier;
      }
      async verify(encoded: string, _required?: string[], requireKb?: boolean) {
        // Drive the injected callbacks so the test really exercises ADP's EdDSA wiring.
        const issuerJwt = encoded.split("~")[0];
        const [h, p, s] = issuerJwt.split(".");
        const issuerOk = await this.verifier(`${h}.${p}`, s);
        if (!issuerOk) throw new Error("issuer signature invalid");
        const bespoke = verifySdJwtVc(
          encoded,
          requireKb ? { aud: VERIFIER, nonce: CHALLENGE } : {},
        );
        if (!bespoke.ok) throw new Error(bespoke.reason ?? "verification failed");
        if (requireKb && this.kbVerifier) {
          const kb = encoded.split("~").pop() as string;
          const [kh, kp, ks] = kb.split(".");
          const kbOk = await this.kbVerifier(`${kh}.${kp}`, ks);
          if (!kbOk) throw new Error("KB-JWT signature invalid");
        }
        return { payload: bespoke.claims as Record<string, unknown> };
      }
    },
  });
}

test("optional sd-jwt lib path verifies the same disclosure as bespoke (round-trip)", async () => {
  __setSdJwtVcLoader(sdJwtMockLoader());
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);

  const issued = toSdJwtVc(disclosure, key);
  const presentation = presentSdJwtVc(issued, ["constitution", "capital"], key, {
    aud: VERIFIER,
    nonce: CHALLENGE,
  });

  const bespoke = verifySdJwtVc(presentation, { aud: VERIFIER, nonce: CHALLENGE });
  const lib = await verifySdJwtVcWithLib(presentation, {
    expectedVct: ADP_VCT,
    aud: VERIFIER,
    nonce: CHALLENGE,
  });

  assert.equal(lib.ok, true, lib.reason);
  assert.equal(lib.issuer, agentIdToDidKey(key.publicKeyHex));
  // same revealed fields + same spliced values as the bespoke path
  assert.deepEqual(new Set(lib.revealedFields), new Set(bespoke.revealedFields));
  assert.deepEqual(lib.claims?.constitution, disclosure.constitution);
  assert.deepEqual(lib.claims?.capital, disclosure.capital);
  assert.deepEqual(lib.claims?.constitution, bespoke.claims?.constitution);
});

test("optional sd-jwt lib path enforces expectedVct", async () => {
  __setSdJwtVcLoader(sdJwtMockLoader());
  const key = generateAgentKeyPair();
  const issued = toSdJwtVc(buildDisclosure(key.publicKeyHex), key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, { aud: VERIFIER, nonce: CHALLENGE });

  const res = await verifySdJwtVcWithLib(presentation, {
    expectedVct: "https://evil.example/cred",
    aud: VERIFIER,
    nonce: CHALLENGE,
  });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /vct/);
});

test("optional sd-jwt lib path enforces the aud/nonce expectation", async () => {
  __setSdJwtVcLoader(sdJwtMockLoader());
  const key = generateAgentKeyPair();
  const issued = toSdJwtVc(buildDisclosure(key.publicKeyHex), key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, { aud: VERIFIER, nonce: CHALLENGE });

  const res = await verifySdJwtVcWithLib(presentation, { aud: VERIFIER, nonce: "wrong" });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /nonce/);
});

test("optional sd-jwt lib path surfaces a library rejection", async () => {
  // A loader whose verify always throws — simulates the real library rejecting the proof.
  __setSdJwtVcLoader(async () => ({
    SDJwtVcInstance: class {
      async verify(): Promise<{ payload: Record<string, unknown> }> {
        throw new Error("digest not found in _sd");
      }
    },
  }));
  const key = generateAgentKeyPair();
  const issued = toSdJwtVc(buildDisclosure(key.publicKeyHex), key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, { aud: VERIFIER, nonce: CHALLENGE });

  const res = await verifySdJwtVcWithLib(presentation, { aud: VERIFIER, nonce: CHALLENGE });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /rejected/);
});

test("optional sd-jwt lib path throws an install hint when the dep is absent", async () => {
  __setSdJwtVcLoader(async () => {
    throw new Error("Cannot find module '@sd-jwt/sd-jwt-vc'");
  });
  const key = generateAgentKeyPair();
  const issued = toSdJwtVc(buildDisclosure(key.publicKeyHex), key);
  const presentation = presentSdJwtVc(issued, ["constitution"], key, { aud: VERIFIER, nonce: CHALLENGE });
  await assert.rejects(() => verifySdJwtVcWithLib(presentation), /@sd-jwt\/sd-jwt-vc/);
});
