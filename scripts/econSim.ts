// Economic-viability simulation. Runs economics.ts across representative markets
// (micro-payment, mid, high-value) under two verification regimes (deep-verify every
// tx vs tiered + validity-window cache) and prints which markets clear and the
// break-even verification cost each can bear.
//
// Run: node --import tsx scripts/econSim.ts

import {
  breakEvenVerificationCostMinor,
  type MarketParams,
  perTxVerificationCostMinor,
  type VerificationParams,
  viabilityOf,
} from "../src/economics.ts";

// All money in pence (minor units).
const markets: MarketParams[] = [
  {
    name: "micro-payment",
    txValueMinor: 50, // 50p tx
    marginBps: 30,
    fraudRateWithout: 0.001,
    lossGivenFraudMinor: 50,
  },
  {
    name: "mid-value",
    txValueMinor: 5_000, // 50 GBP tx
    marginBps: 80,
    fraudRateWithout: 0.004,
    lossGivenFraudMinor: 5_000,
  },
  {
    name: "high-value",
    txValueMinor: 200_000, // 2000 GBP tx
    marginBps: 150,
    fraudRateWithout: 0.01,
    lossGivenFraudMinor: 200_000,
  },
];

const regimes: { label: string; v: VerificationParams }[] = [
  {
    label: "deep-every-tx",
    v: { fastCostMinor: 0.5, deepCostMinor: 5, deepFraction: 1, cacheHitRate: 0, residualFraudRate: 0.0005 },
  },
  {
    label: "tiered+cached",
    v: { fastCostMinor: 0.5, deepCostMinor: 5, deepFraction: 0.02, cacheHitRate: 0.95, residualFraudRate: 0.0005 },
  },
];

function p(minor: number): string {
  return `${minor.toFixed(4)}p`;
}

console.log("Agent-to-agent market viability under verification cost\n");

for (const { label, v } of regimes) {
  const cost = perTxVerificationCostMinor(v);
  console.log(`== regime: ${label} (per-tx verify cost ${p(cost)}) ==`);
  let cleared = 0;
  for (const m of markets) {
    const r = viabilityOf(m, v);
    const breakEven = breakEvenVerificationCostMinor(m, v.residualFraudRate);
    if (r.viable) cleared++;
    console.log(
      [
        `  ${m.name.padEnd(14)}`,
        r.viable ? "CLEARS " : "FAILS  ",
        `margin=${p(r.perTxMarginMinor)}`,
        `fraudSaving=${p(r.expectedFraudSavingMinor)}`,
        `net=${p(r.netPerTxMinor)}`,
        `breakEvenCost=${p(breakEven)}`,
      ].join("  "),
    );
  }
  console.log(`  -> ${cleared}/${markets.length} markets clear\n`);
}

console.log("Takeaway: deep-verifying every tx strands thin micro-payment markets;");
console.log("tiering + a validity-window cache lifts them back above break-even.");
