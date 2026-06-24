import { test } from "node:test";
import assert from "node:assert/strict";

import {
  breakEvenVerificationCostMinor,
  type MarketParams,
  perTxVerificationCostMinor,
  surviving,
  type VerificationParams,
  viabilityOf,
} from "../src/economics.ts";

// Calibration: money in pence (minor units). fastCost=0.5p, deepCost=5p model a cheap
// deterministic fast path vs an expensive live handshake + corpus re-run. residualFraudRate
// (0.0005) sits below each market's fraudRateWithout so verification earns a small, honest
// fraud-saving - not a windfall that masks the margin-vs-cost story.
const deepEvery: VerificationParams = {
  fastCostMinor: 0.5,
  deepCostMinor: 5,
  deepFraction: 1, // deep-verify EVERY tx
  cacheHitRate: 0,
  residualFraudRate: 0.0005,
};

const tieredCached: VerificationParams = {
  fastCostMinor: 0.5,
  deepCostMinor: 5,
  deepFraction: 0.02, // only 2% need the deep path
  cacheHitRate: 0.95, // 95% of the fast path served from the validity-window cache
  residualFraudRate: 0.0005,
};

// £100 tx at 200bps -> 200p margin. Fat enough to absorb deep-verify-every-tx.
const fatMarket: MarketParams = {
  name: "high-margin-settlement",
  txValueMinor: 10_000,
  marginBps: 200,
  fraudRateWithout: 0.01,
  lossGivenFraudMinor: 10_000,
};

// £0.50 tx at 30bps -> 0.15p margin. Sub-margin micropayment.
const microMarket: MarketParams = {
  name: "micropayment",
  txValueMinor: 50,
  marginBps: 30,
  fraudRateWithout: 0.001,
  lossGivenFraudMinor: 50,
};

test("perTxVerificationCostMinor matches the blended formula", () => {
  // deep-every: pure deep cost
  assert.equal(perTxVerificationCostMinor(deepEvery), 5);
  // tiered+cached: 0.98 * 0.5 * 0.05 + 0.02 * 5 = 0.0245 + 0.1 = 0.1245
  assert.ok(Math.abs(perTxVerificationCostMinor(tieredCached) - 0.1245) < 1e-9);
});

test("high-margin market is viable even deep-verifying every tx", () => {
  const r = viabilityOf(fatMarket, deepEvery);
  assert.equal(r.perTxMarginMinor, 200);
  assert.equal(r.perTxVerificationCostMinor, 5);
  assert.ok(r.viable);
  assert.ok(r.netPerTxMinor > 0);
});

test("thin micropayment fails deep-verify-every-tx but caching+tiering rescues it", () => {
  const naive = viabilityOf(microMarket, deepEvery);
  assert.equal(naive.perTxMarginMinor, 0.15);
  assert.equal(naive.perTxVerificationCostMinor, 5);
  assert.equal(naive.viable, false); // margin 0.15 cannot cover 5p of deep verify
  assert.ok(naive.netPerTxMinor < 0);

  // Same market, same costs, but tiered + cached: cost drops to 0.1245p, below margin
  // (0.15) plus the small fraud-saving -> net tips positive.
  const rescued = viabilityOf(microMarket, tieredCached);
  assert.equal(rescued.viable, true);
  assert.ok(rescued.netPerTxMinor > 0);
});

test("perTxVerificationCostMinor decreases as cacheHitRate rises", () => {
  const base = { fastCostMinor: 5, deepCostMinor: 30, deepFraction: 0.1, residualFraudRate: 0 };
  const hits = [0, 0.25, 0.5, 0.75, 1];
  const costs = hits.map((cacheHitRate) =>
    perTxVerificationCostMinor({ ...base, cacheHitRate }),
  );
  for (let i = 1; i < costs.length; i++) {
    assert.ok(costs[i] < costs[i - 1], `cost not decreasing at hit ${hits[i]}`);
  }
});

test("perTxVerificationCostMinor decreases as deepFraction falls", () => {
  const base = { fastCostMinor: 5, deepCostMinor: 30, cacheHitRate: 0.5, residualFraudRate: 0 };
  const fractions = [1, 0.75, 0.5, 0.25, 0]; // falling
  const costs = fractions.map((deepFraction) =>
    perTxVerificationCostMinor({ ...base, deepFraction }),
  );
  for (let i = 1; i < costs.length; i++) {
    assert.ok(costs[i] < costs[i - 1], `cost not decreasing at deepFraction ${fractions[i]}`);
  }
});

test("fraud saving lifts a borderline market into viable", () => {
  // £1 tx at 10bps -> 0.1p margin. deepEvery costs 5p. Margin alone is hopeless.
  const borderline: MarketParams = {
    name: "borderline",
    txValueMinor: 100,
    marginBps: 10,
    fraudRateWithout: 0, // no fraud to save -> cannot cover the cost
    lossGivenFraudMinor: 100_000,
  };
  assert.equal(viabilityOf(borderline, deepEvery).viable, false);

  // Same market but a real, removable fraud rate: saving = (0.01 - 0.0005) * 100000 = 950p,
  // dwarfing the 5p cost -> now viable purely on fraud avoided.
  const withFraud: MarketParams = { ...borderline, fraudRateWithout: 0.01 };
  const r = viabilityOf(withFraud, deepEvery);
  assert.equal(r.expectedFraudSavingMinor, 950);
  assert.equal(r.viable, true);

  // break-even cost it can now bear = margin (0.1) + saving (950) = 950.1p
  assert.ok(
    Math.abs(breakEvenVerificationCostMinor(withFraud, deepEvery.residualFraudRate) - 950.1) < 1e-9,
  );
});

test("breakEvenVerificationCostMinor is the net=0 verification cost", () => {
  const be = breakEvenVerificationCostMinor(fatMarket, deepEvery.residualFraudRate);
  // a regime costing exactly break-even nets zero (not viable: net must be > 0)
  const atBreakEven: VerificationParams = {
    fastCostMinor: be,
    deepCostMinor: be,
    deepFraction: 1,
    cacheHitRate: 0,
    residualFraudRate: deepEvery.residualFraudRate,
  };
  const r = viabilityOf(fatMarket, atBreakEven);
  assert.ok(Math.abs(r.netPerTxMinor) < 1e-9);
  assert.equal(r.viable, false);
});

test("surviving returns exactly the viable subset", () => {
  const markets = [fatMarket, microMarket, microMarket];
  // deep-every: only the fat market survives
  assert.deepEqual(
    surviving(markets, deepEvery).map((m) => m.name),
    ["high-margin-settlement"],
  );
  // tiered+cached: micropayment is rescued, so all three survive
  assert.equal(surviving(markets, tieredCached).length, 3);

  // exact subset agreement with viabilityOf
  const expected = markets.filter((m) => viabilityOf(m, tieredCached).viable);
  assert.deepEqual(surviving(markets, tieredCached), expected);
});
