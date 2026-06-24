// Conformance report generator. Runs the TS-reference conformance assertions
// (canonicalization vectors + differential fuzz corpus, sha256 digests, and the
// interop disclosure / handshake / signature checks) and prints a Markdown report:
// one row per suite with (cases, pass, fail) plus a single PASS/FAIL summary line.
// Exits 0 only when every case passes, so it doubles as a CI gate.
//
// Run: node --import tsx scripts/conformanceReport.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  canonicalize,
  sha256Hex,
  evaluateDisclosure,
  verifyDisclosureSignature,
  verifyChallengeResponse,
  type SignedDisclosure,
} from "../src/index.ts";
import type { VerificationPolicy } from "../src/verify.ts";

function load(rel: string): unknown {
  return JSON.parse(readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8"));
}

const vectors = load("../conformance/vectors.json") as {
  canonicalization: { input: unknown; canonical: string }[];
  sha256: { input: string; sha256: string }[];
};
const fuzz = load("../conformance/fuzz.json") as { input: unknown; canonical: string }[];
const interop = load("../conformance/interop.json") as {
  disclosures: {
    name: string;
    signed: SignedDisclosure;
    policy: VerificationPolicy;
    expect: { decision: string; failed: string[] };
  }[];
  handshakes: {
    name: string;
    challenge: { nonce: string; verifierId?: string };
    response: {
      nonce: string;
      agentId: string;
      auditHead: string;
      signedAt: string;
      signature: string;
    };
    expectedAgentId: string;
    now?: string;
    expect: boolean;
  }[];
};

interface SuiteResult {
  suite: string;
  cases: number;
  pass: number;
  fail: number;
}

// Each runner returns one SuiteResult. A case "passes" iff its assertion held; the
// runner counts rather than throws so the report shows the full picture in one pass.
function runCanonicalizationVectors(): SuiteResult {
  let pass = 0;
  for (const v of vectors.canonicalization) {
    if (canonicalize(v.input) === v.canonical) pass++;
  }
  const cases = vectors.canonicalization.length;
  return { suite: "canonicalization vectors", cases, pass, fail: cases - pass };
}

function runFuzzCanonicalization(): SuiteResult {
  let pass = 0;
  for (const c of fuzz) {
    if (canonicalize(c.input) === c.canonical) pass++;
  }
  return { suite: "fuzz canonicalization", cases: fuzz.length, pass, fail: fuzz.length - pass };
}

function runSha256(): SuiteResult {
  let pass = 0;
  for (const v of vectors.sha256) {
    if (sha256Hex(v.input) === v.sha256) pass++;
  }
  const cases = vectors.sha256.length;
  return { suite: "sha256 vectors", cases, pass, fail: cases - pass };
}

function failedChecks(checks: Record<string, boolean>): string[] {
  return Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([name]) => name)
    .sort();
}

function arraysEqual(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function runInteropDisclosures(): SuiteResult {
  let pass = 0;
  for (const c of interop.disclosures) {
    const verdict = evaluateDisclosure(c.signed, c.policy);
    const decisionOk = verdict.decision === c.expect.decision;
    const failedOk = arraysEqual(failedChecks(verdict.checks), [...c.expect.failed].sort());
    if (decisionOk && failedOk) pass++;
  }
  const cases = interop.disclosures.length;
  return { suite: "interop disclosures", cases, pass, fail: cases - pass };
}

function runInteropSignatures(): SuiteResult {
  // Every non-tampered/non-forged interop disclosure must carry a verifying
  // signature - the byte-for-byte proof the canonical form matches what signed it.
  const eligible = interop.disclosures.filter((c) => !c.expect.failed.includes("signature"));
  let pass = 0;
  for (const c of eligible) {
    if (verifyDisclosureSignature(c.signed).ok) pass++;
  }
  return { suite: "interop signatures verify", cases: eligible.length, pass, fail: eligible.length - pass };
}

function runInteropHandshakes(): SuiteResult {
  let pass = 0;
  for (const c of interop.handshakes) {
    const result = verifyChallengeResponse(c.response, c.challenge, {
      expectedAgentId: c.expectedAgentId,
      now: c.now,
    });
    if (result.ok === c.expect) pass++;
  }
  const cases = interop.handshakes.length;
  return { suite: "interop handshakes", cases, pass, fail: cases - pass };
}

export function runConformanceReport(): { results: SuiteResult[]; allPass: boolean } {
  const results = [
    runCanonicalizationVectors(),
    runFuzzCanonicalization(),
    runSha256(),
    runInteropDisclosures(),
    runInteropSignatures(),
    runInteropHandshakes(),
  ];
  const allPass = results.every((r) => r.fail === 0);
  return { results, allPass };
}

export function renderReport(results: SuiteResult[], allPass: boolean): string {
  const totalCases = results.reduce((n, r) => n + r.cases, 0);
  const totalFail = results.reduce((n, r) => n + r.fail, 0);
  const lines = [
    "# ADP Conformance Report (TS reference)",
    "",
    "| Suite | Cases | Pass | Fail |",
    "| --- | ---: | ---: | ---: |",
  ];
  for (const r of results) {
    lines.push(`| ${r.suite} | ${r.cases} | ${r.pass} | ${r.fail} |`);
  }
  lines.push(`| **total** | **${totalCases}** | **${totalCases - totalFail}** | **${totalFail}** |`);
  lines.push("");
  lines.push(`**${allPass ? "PASS" : "FAIL"}** - ${totalCases - totalFail}/${totalCases} cases pass across ${results.length} suites.`);
  return lines.join("\n");
}

function main(): void {
  const { results, allPass } = runConformanceReport();
  // eslint-disable-next-line no-console
  console.log(renderReport(results, allPass));
  process.exit(allPass ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("conformanceReport.ts")) {
  main();
}
