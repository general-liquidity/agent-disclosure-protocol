// Generates conformance/negative.json: a MUST-REJECT corpus. A verifier given any of
// these inputs MUST NOT return transact/accept and MUST NOT crash. Some are malformed
// JSON shapes; some parse but fail the schema, the agentId<->key binding, or the
// signature. `raw` is the value to feed the verifier; when `isRawString` is true, `raw`
// is a literal byte string (not valid JSON) the parser must reject gracefully.
//
//   node --import tsx conformance/generate-negative.ts

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { agentKeyFromPrivateHex, signDisclosure, sha256Hex, type AgentDisclosure } from "../src/index.ts";

const PRIV = "302e020100300506032b657004220420aace66c414504180b9dc76c2fe47f41cdcda8909882c0f6e4774e5a5535bf8ee";
const key = agentKeyFromPrivateHex(PRIV);
const AGENT = key.publicKeyHex;
const OTHER = `${"0".repeat(63)}1`;
const H = sha256Hex("anchor");
const NOW = "2026-06-24T12:00:00.000Z";

function disclosure(): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "d",
    agentId: AGENT,
    issuedAt: NOW,
    validUntil: "2026-06-24T13:00:00.000Z",
    nonce: "n",
    auditAnchor: H,
    systemPrompt: { algorithm: "sha256", digest: H },
    constitution: { hardConstraints: [], digest: H, enforced: true },
    tools: { tools: [] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: { operatorId: "op", attestation: { scheme: "none", level: "none" }, deniabilityBoundary: "x" },
    history: { chainAnchor: H, summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
  };
}

const valid = signDisclosure(disclosure(), key);
const clone = () => JSON.parse(JSON.stringify(valid));

interface NegativeCase {
  name: string;
  raw: unknown;
  isRawString?: boolean;
}

const cases: NegativeCase[] = [
  { name: "empty-object", raw: {} },
  { name: "null", raw: null },
  { name: "number", raw: 42 },
  { name: "array", raw: [1, 2, 3] },
  { name: "not-json", raw: "this is not json {", isRawString: true },
  { name: "missing-signature", raw: { disclosure: valid.disclosure } },
  { name: "missing-disclosure", raw: { signature: valid.signature } },
];

{
  const c = clone();
  c.disclosure.version = "1";
  cases.push({ name: "wrong-version-type", raw: c });
}
{
  const c = clone();
  c.signature.algorithm = "hmac-sha256";
  cases.push({ name: "wrong-algorithm", raw: c });
}
{
  const c = clone();
  c.disclosure.agentId = OTHER; // agentId no longer matches the signing key
  cases.push({ name: "agentid-mismatch", raw: c });
}
{
  const c = clone();
  c.signature.value = "zzzz"; // non-hex signature
  cases.push({ name: "bad-signature-hex", raw: c });
}
{
  const c = clone();
  c.disclosure.constitution.enforced = false; // tampered field, signature no longer matches
  cases.push({ name: "tampered-field", raw: c });
}

// ── Signed-but-schema-invalid: the signature is VALID over these bytes, only the
// schema is violated (a bad enum / literal). A verifier that leans on the signature
// and skips structural validation would wrongly ACCEPT them — these cases force every
// port to validate the field grammar, not just the ed25519 signature. SPEC §3.11.
function signedWith(mutate: (d: AgentDisclosure) => void, name: string) {
  const d = disclosure();
  // deliberately violate the schema after constructing a valid base, then sign so the
  // signature matches the (invalid) bytes.
  mutate(d as AgentDisclosure);
  cases.push({ name, raw: signDisclosure(d, key) });
}
signedWith((d) => ((d as unknown as { version: number }).version = 9999), "unsupported-version-value");
signedWith((d) => ((d.capital as unknown as { custody: string }).custody = "escrow"), "bad-custody-enum");
signedWith((d) => ((d.operator.attestation as unknown as { scheme: string }).scheme = "Unknown"), "bad-attestation-scheme");
signedWith((d) => ((d.operator.attestation as unknown as { level: string }).level = "verified"), "bad-attestation-level");
signedWith((d) => ((d.systemPrompt as unknown as { algorithm: string }).algorithm = "sha512"), "bad-systemprompt-algorithm");

const out = {
  _comment:
    "MUST-REJECT corpus. A verifier given any of these MUST NOT return transact/accept and MUST NOT crash. `raw` is the value to feed the verifier; when isRawString is true, `raw` is a literal byte string (not valid JSON) the parser must reject. Regenerate: node --import tsx conformance/generate-negative.ts",
  cases,
};

writeFileSync(fileURLToPath(new URL("./negative.json", import.meta.url)), `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote negative.json: ${cases.length} must-reject cases`);
