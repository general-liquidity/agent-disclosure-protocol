// Generates conformance/interop.json: a deterministic set of signed disclosures +
// policies + expected verdicts, and challenge-response handshake fixtures, that
// EVERY native implementation verifies against. The fixed key makes the output
// stable (ed25519 is deterministic), so interop.json is committed and only diffs
// when the contract itself changes.
//
//   node --import tsx conformance/generate-interop.ts
//
// A verifier in any language MUST, for each disclosure case, reproduce `expect.decision`
// (the primary contract) and SHOULD reproduce `expect.failed` (the set of failed check
// names). For each handshake case it MUST reproduce `expect`.

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  agentKeyFromPrivateHex,
  signDisclosure,
  evaluateDisclosure,
  createChallenge,
  respondToChallenge,
  sha256Hex,
  type AgentDisclosure,
  type SignedDisclosure,
  type VerificationPolicy,
  type Challenge,
  type ChallengeResponse,
} from "../src/index.ts";

// A fixed ed25519 identity (PKCS8 DER hex). ed25519 is deterministic, so every run
// produces byte-identical signatures and a stable interop.json.
const PRIV = "302e020100300506032b657004220420aace66c414504180b9dc76c2fe47f41cdcda8909882c0f6e4774e5a5535bf8ee";
const key = agentKeyFromPrivateHex(PRIV);
const AGENT = key.publicKeyHex;
const OTHER = `${"0".repeat(63)}1`; // a different, non-matching agentId

const ISSUED = "2026-06-24T12:00:00.000Z";
const VALID_UNTIL = "2026-06-24T13:00:00.000Z";
const FRESH = "2026-06-24T12:30:00.000Z";
const STALE = "2026-06-24T14:00:00.000Z";
const H = sha256Hex("anchor");

function base(over: Partial<AgentDisclosure> = {}): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "disc_interop",
    agentId: AGENT,
    issuedAt: ISSUED,
    validUntil: VALID_UNTIL,
    nonce: "nonce_interop",
    auditAnchor: H,
    systemPrompt: { algorithm: "sha256", digest: H },
    constitution: {
      hardConstraints: [{ id: "no_self_payment", description: "no paying your own operator", kind: "deny" }],
      digest: H,
      enforced: true,
    },
    tools: { tools: [{ name: "pay", access: "gated", movesValue: true }] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: { operatorId: "op", attestation: { scheme: "none", level: "none" }, deniabilityBoundary: "spend within mandates" },
    history: { chainAnchor: H, summary: { totalDecisions: 5, settledCount: 4, blockedCount: 1 } },
    redTeam: { corpus: { name: "spendtrust", version: "1.0.0" }, result: { grade: "A", score: 95, passed: true, hardFails: [] }, attestedAt: ISSUED },
    ...over,
  };
}

interface DisclosureCase {
  name: string;
  signed: SignedDisclosure;
  policy: VerificationPolicy;
  expect: { decision: "transact" | "refuse"; failed: string[] };
}

// Expectations are computed by the REAL verifier, so the fixtures are correct by
// construction; another language reproduces them.
function caseOf(name: string, signed: SignedDisclosure, policy: VerificationPolicy): DisclosureCase {
  const v = evaluateDisclosure(signed, policy);
  const failed = Object.entries(v.checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k)
    .sort();
  return { name, signed, policy, expect: { decision: v.decision, failed } };
}

const strict: Omit<VerificationPolicy, "now"> = {
  requireEnforcedConstitution: true,
  requireNonCustodial: true,
  requireDeploymentHistory: true,
  requireAuditAnchor: true,
  minRedTeamGrade: "B",
};

const disclosures: DisclosureCase[] = [
  caseOf("valid-transact", signDisclosure(base(), key), { now: FRESH, ...strict }),
  caseOf("unenforced-refuse", signDisclosure(base({ constitution: { hardConstraints: [], digest: H, enforced: false } }), key), { now: FRESH, ...strict }),
  caseOf("stale-refuse", signDisclosure(base(), key), { now: STALE, ...strict }),
  caseOf("custodial-refuse", signDisclosure(base({ capital: { mandates: [], custody: "custodial" } }), key), { now: FRESH, ...strict }),
  caseOf("low-grade-refuse", signDisclosure(base({ redTeam: { corpus: { name: "spendtrust", version: "1.0.0" }, result: { grade: "D", score: 40, passed: false, hardFails: [] }, attestedAt: ISSUED } }), key), { now: FRESH, ...strict }),
  caseOf("no-history-refuse", signDisclosure(base({ history: { chainAnchor: H, summary: { totalDecisions: 0, settledCount: 0, blockedCount: 0 } } }), key), { now: FRESH, ...strict }),
];

// Tampered signature: mutate a field after signing -> canonical bytes no longer match.
{
  const signed = signDisclosure(base(), key);
  const tampered: SignedDisclosure = {
    ...signed,
    disclosure: { ...signed.disclosure, constitution: { ...signed.disclosure.constitution, digest: sha256Hex("different") } },
  };
  disclosures.push(caseOf("tampered-signature-refuse", tampered, { now: FRESH, ...strict }));
}

// Forged agentId: agentId no longer equals the signing public key -> binding fails.
{
  const signed = signDisclosure(base(), key);
  const forged: SignedDisclosure = { ...signed, disclosure: { ...signed.disclosure, agentId: OTHER } };
  disclosures.push(caseOf("forged-agentid-refuse", forged, { now: FRESH, ...strict }));
}

interface HandshakeCase {
  name: string;
  challenge: Challenge;
  response: ChallengeResponse;
  expectedAgentId: string;
  now: string;
  expect: boolean;
}

const challenge = createChallenge(FRESH, { nonce: "chal_interop", verifierId: "verifier-X" });
const good = respondToChallenge(challenge, key, H, FRESH);
const flip = `${good.signature.slice(0, -2)}${good.signature.endsWith("00") ? "11" : "00"}`;

const handshakes: HandshakeCase[] = [
  { name: "valid", challenge, response: good, expectedAgentId: AGENT, now: FRESH, expect: true },
  { name: "nonce-mismatch", challenge: { ...challenge, nonce: "different" }, response: good, expectedAgentId: AGENT, now: FRESH, expect: false },
  { name: "wrong-agent", challenge, response: { ...good, agentId: OTHER }, expectedAgentId: AGENT, now: FRESH, expect: false },
  { name: "bad-signature", challenge, response: { ...good, signature: flip }, expectedAgentId: AGENT, now: FRESH, expect: false },
  { name: "stale", challenge, response: good, expectedAgentId: AGENT, now: STALE, expect: false },
];

const out = {
  _comment:
    "Cross-stack interop fixtures, generated from the TS reference with a fixed ed25519 key. A verifier in any language MUST reproduce disclosures[].expect.decision and handshakes[].expect; SHOULD reproduce disclosures[].expect.failed (sorted check names). Regenerate with: node --import tsx conformance/generate-interop.ts",
  key: { privateKeyHex: PRIV, publicKeyHex: AGENT },
  disclosures,
  handshakes,
};

writeFileSync(fileURLToPath(new URL("./interop.json", import.meta.url)), `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote interop.json: ${disclosures.length} disclosure cases, ${handshakes.length} handshake cases`);
