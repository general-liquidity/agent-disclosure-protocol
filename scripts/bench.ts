// Verification throughput benchmark. Puts real numbers behind the protocol's central
// economic claim: "verification is cheap". We build one valid signed disclosure, then
// time the hot operations a counterparty (or a signer) actually runs on the path -
// canonicalize, signDisclosure, verifyDisclosureSignature, and the full policy
// evaluateDisclosure - and report ops/sec + median microseconds for each.
//
// We then translate the verify number into the economics framing in economics.ts: at the
// measured per-verification CPU time, and a stated $/CPU-hour, what does one verification
// cost, and which sample markets clear once you charge yourself that cost before every tx?
//
// Self-contained, no deps beyond the package itself. Uses performance.now() for timing.
//
// Run: node --import tsx scripts/bench.ts

import {
  canonicalize,
  generateAgentKeyPair,
  signDisclosure,
  verifyDisclosureSignature,
  type AgentKeyPair,
} from "../src/attestation.ts";
import { DisclosureBuilder } from "../src/builder.ts";
import {
  type MarketParams,
  perTxVerificationCostMinor,
  type VerificationParams,
  viabilityOf,
} from "../src/economics.ts";
import type { SignedDisclosure } from "../src/schema.ts";
import { evaluateDisclosure, type VerificationPolicy } from "../src/verify.ts";
import { argv } from "node:process";
import { pathToFileURL } from "node:url";

// ── Benchmark calibration ────────────────────────────────────────────────────
const ITERATIONS = 50_000;
const WARMUP = 5_000;

// Cost assumption, stated plainly: a commodity cloud vCPU-hour. At 2026 spot/on-demand
// rates a general-purpose vCPU-hour lands around $0.02-$0.05; we take the round middle.
// One verification holds a single core for its measured wall time, so:
//   costPerVerification = (cpuHourUsd / 3600 seconds) * secondsPerVerification.
const CPU_HOUR_USD = 0.04;
const USD_PER_GBP = 1.27; // to express the verify cost in pence, the economics minor unit

// ── Build one valid signed disclosure (a minimal, real disclosure) ───────────
export function buildSampleSigned(key: AgentKeyPair, now: string): SignedDisclosure {
  return new DisclosureBuilder()
    .systemPrompt("You are a payment agent operating under an enforced governance gate.", "v1")
    .constitution({
      hardConstraints: [
        { id: "no-self-transfer", description: "never pay an operator-controlled address", kind: "deny" },
        { id: "per-tx-cap", description: "no single tx over the per-tx cap", kind: "cap" },
      ],
      parameters: { minRationaleChars: 10, velocityCeilingPerHour: 20 },
      enforced: true,
      enforcementEvidence: "agentworth-gate@audit-chain",
    })
    .tools(
      [
        { name: "get_quote", access: "read_only", movesValue: false },
        { name: "pay", access: "gated", movesValue: true },
      ],
      "pay",
    )
    .capital({
      mandates: [
        {
          label: "vendor-payments",
          scope: "allowlisted SaaS vendors",
          currency: "GBP",
          perTxCapMinor: 50_000,
          perPeriodCapMinor: 500_000,
          period: "day",
          allowedRails: ["x402"],
          expiresAt: "2027-01-01T00:00:00.000Z",
        },
      ],
      aggregatePerPeriodCapMinor: 500_000,
      custody: "non_custodial",
    })
    .operator({
      operatorId: "op_general_liquidity",
      attestation: { scheme: "ERC8004", level: "registry_attested" },
      deniabilityBoundary: "operator accountable for mandate config, not per-decision intent",
    })
    .history({
      chainAnchor: "ab".repeat(32),
      summary: { totalDecisions: 1_280, settledCount: 1_240, blockedCount: 40 },
    })
    .redTeam({
      corpus: { name: "adp-public-corpus", version: "1.0" },
      result: { grade: "A", score: 96, passed: true, hardFails: [] },
      attestedAt: now,
    })
    .buildAndSign({ agentKey: key, now, nonce: "bench-nonce-0001" });
}

// A non-trivial policy so evaluateDisclosure exercises real checks, not just the baseline.
export function buildPolicy(now: string): VerificationPolicy {
  return {
    now,
    requireValidSignature: true,
    requireFresh: true,
    requireEnforcedConstitution: true,
    requiredHardConstraints: ["no-self-transfer", "per-tx-cap"],
    requireRedTeam: true,
    minRedTeamGrade: "B",
    requireNonCustodial: true,
    minAttestationLevel: "signed",
    requireDeploymentHistory: true,
  };
}

// ── Timing harness ───────────────────────────────────────────────────────────
export interface BenchResult {
  name: string;
  opsPerSec: number;
  medianMicros: number;
  meanMicros: number;
}

// Times `fn` over ITERATIONS, after a WARMUP burst. Returns ops/sec from the total
// wall time and the median per-op latency from per-iteration samples (median resists
// the GC-pause outliers that would skew a mean). A sink consumes the result so the
// optimizer cannot dead-code-eliminate the call.
export function bench(name: string, fn: () => unknown, iterations = ITERATIONS, warmup = WARMUP): BenchResult {
  for (let i = 0; i < warmup; i++) sink(fn());

  const samples = new Float64Array(iterations);
  const startAll = performance.now();
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    sink(fn());
    samples[i] = performance.now() - t0;
  }
  const totalMs = performance.now() - startAll;

  const sorted = Array.from(samples).sort((a, b) => a - b);
  const medianMicros = sorted[Math.floor(sorted.length / 2)] * 1000;
  const meanMicros = (totalMs / iterations) * 1000;
  return { name, opsPerSec: iterations / (totalMs / 1000), medianMicros, meanMicros };
}

let SINK = 0;
function sink(v: unknown): void {
  // Cheap, side-effecting consume that the JIT cannot prove is a no-op.
  if (typeof v === "string") SINK += v.length;
  else if (typeof v === "object" && v !== null) SINK += Object.keys(v).length;
  else SINK += 1;
}

// ── Markets (same shapes as econSim.ts; money in pence / minor units) ────────
const markets: MarketParams[] = [
  { name: "micro-payment", txValueMinor: 50, marginBps: 30, fraudRateWithout: 0.001, lossGivenFraudMinor: 50 },
  { name: "mid-value", txValueMinor: 5_000, marginBps: 80, fraudRateWithout: 0.004, lossGivenFraudMinor: 5_000 },
  { name: "high-value", txValueMinor: 200_000, marginBps: 150, fraudRateWithout: 0.01, lossGivenFraudMinor: 200_000 },
];

function fmtNum(n: number): string {
  return n.toLocaleString("en-US", { maximumFractionDigits: 0 });
}

function main(): void {
  const now = new Date().toISOString();
  const key = generateAgentKeyPair();
  const signed = buildSampleSigned(key, now);
  const policy = buildPolicy(now);

  // Sanity: the sample disclosure must actually pass, or the numbers are meaningless.
  const verdict = evaluateDisclosure(signed, policy);
  if (verdict.decision !== "transact") {
    throw new Error(`sample disclosure does not pass policy: ${verdict.reasons.join("; ")}`);
  }
  const sigCheck = verifyDisclosureSignature(signed);
  if (!sigCheck.ok) throw new Error(`sample signature does not verify: ${sigCheck.reason}`);

  const canonicalBytes = Buffer.byteLength(canonicalize(signed.disclosure), "utf8");

  const results: BenchResult[] = [
    bench("canonicalize", () => canonicalize(signed.disclosure)),
    bench("signDisclosure", () => signDisclosure(signed.disclosure, key)),
    bench("verifyDisclosureSignature", () => verifyDisclosureSignature(signed)),
    bench("evaluateDisclosure (full policy)", () => evaluateDisclosure(signed, policy)),
  ];

  // ── Output ──────────────────────────────────────────────────────────────
  console.log("# Verification throughput benchmark\n");
  console.log("Putting real numbers behind the protocol's claim that verification is cheap.\n");
  console.log(
    [
      `- iterations: ${fmtNum(ITERATIONS)} per op (warmup ${fmtNum(WARMUP)})`,
      `- runtime: Node ${process.version} on ${process.platform}/${process.arch}`,
      `- disclosure size (canonical): ${canonicalBytes} bytes`,
      `- policy checks evaluated: ${verdict.cost.checksRun}`,
    ].join("\n"),
  );
  console.log();

  console.log("| operation | ops/sec | median latency (us) | mean latency (us) |");
  console.log("|---|--:|--:|--:|");
  for (const r of results) {
    console.log(
      `| ${r.name} | ${fmtNum(r.opsPerSec)} | ${r.medianMicros.toFixed(2)} | ${r.meanMicros.toFixed(2)} |`,
    );
  }
  console.log();

  // ── Economics translation ────────────────────────────────────────────────
  const verify = results.find((r) => r.name === "evaluateDisclosure (full policy)");
  if (!verify) throw new Error("missing verify result");

  // Per-verification CPU cost. One verification = one core held for its wall time.
  const secondsPerVerify = verify.meanMicros / 1e6;
  const usdPerVerify = (CPU_HOUR_USD / 3600) * secondsPerVerify;
  const pencePerVerify = usdPerVerify * (1 / USD_PER_GBP) * 100;

  console.log("## Economics translation\n");
  console.log("Assumptions (stated plainly, change them and the conclusion moves):");
  console.log(`- CPU cost: $${CPU_HOUR_USD.toFixed(2)} per vCPU-hour (commodity cloud, 2026).`);
  console.log("- one full-policy verification holds a single core for its measured mean wall time.");
  console.log(`- FX: $${USD_PER_GBP.toFixed(2)} per GBP (economics minor unit is pence).`);
  console.log("- caching/tiering are MODELLED here, not measured: the bench gives the raw");
  console.log("  per-verification cost; the regimes below apply it via economics.ts.\n");

  console.log(
    [
      `Measured: ${verify.meanMicros.toFixed(2)} us/verify`,
      `-> ${fmtNum(verify.opsPerSec)} verifications/sec/core`,
      `-> ~$${usdPerVerify.toExponential(2)}/verify`,
      `(~${pencePerVerify.toExponential(2)} pence/verify).`,
    ].join("\n"),
  );
  console.log();

  // Feed the measured per-verify pence cost into economics.ts as the deep-path cost.
  // Two regimes, same shape as econSim.ts: deep-verify every tx vs tiered + cached.
  const regimes: { label: string; v: VerificationParams }[] = [
    {
      label: "deep-verify-every-tx (measured cost on every tx)",
      v: {
        fastCostMinor: pencePerVerify,
        deepCostMinor: pencePerVerify,
        deepFraction: 1,
        cacheHitRate: 0,
        residualFraudRate: 0.0005,
      },
    },
    {
      label: "tiered+cached (2% deep, 95% cache hit)",
      v: {
        fastCostMinor: pencePerVerify,
        deepCostMinor: pencePerVerify,
        deepFraction: 0.02,
        cacheHitRate: 0.95,
        residualFraudRate: 0.0005,
      },
    },
  ];

  console.log("Markets clearing at the MEASURED verification cost (money in pence):\n");
  for (const { label, v } of regimes) {
    const cost = perTxVerificationCostMinor(v);
    const cleared = markets.filter((m) => viabilityOf(m, v).viable);
    console.log(`### regime: ${label}`);
    console.log(`per-tx verify cost: ${cost.toExponential(2)} pence\n`);
    console.log("| market | net/tx (pence) | clears? |");
    console.log("|---|--:|:--|");
    for (const m of markets) {
      const r = viabilityOf(m, v);
      console.log(`| ${m.name} | ${r.netPerTxMinor.toFixed(4)} | ${r.viable ? "yes" : "no"} |`);
    }
    console.log(`\n-> ${cleared.length}/${markets.length} markets clear\n`);
  }

  console.log(
    "Takeaway: at the measured per-verification cost, verification is so cheap that even the",
  );
  console.log(
    "thin micro-payment market clears - the cost story is dominated by margin and fraud-saving,",
  );
  console.log("not by the price of running the checks.");

  // Touch the sink so it cannot be eliminated.
  if (SINK < 0) console.log(SINK);
}

// Run only when invoked directly, so a test can import the bench helpers without
// triggering the full 50k-iteration run on import.
const invokedDirectly = argv[1] !== undefined && import.meta.url === pathToFileURL(argv[1]).href;
if (invokedDirectly) main();

export { main };
