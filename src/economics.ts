// The economic-viability model (proposal part 3): which agent-to-agent markets survive
// once you charge yourself a per-tx cost to verify a counterparty before transacting.
//
// Thesis: cheap deterministic verification + caching/tiering keeps most markets viable.
// Only sub-margin micropayments fail - and only if you deep-verify every single tx.
// Tiering (a small deepFraction) + a validity-window cache (high cacheHitRate) is the
// enabler that lifts thin markets back above break-even.
//
// Vendor-neutral and PURE: no I/O, deterministic. All money in integer minor units.
//
// Assumptions worth stating plainly:
//  - independence: fraud events are treated as independent across txs, so expected
//    fraud loss is just probability * loss-given-fraud. Correlated/adversarial bursts
//    are out of scope here.
//  - per-tx amortization: the verification cost is amortized per transaction. A cache
//    hit on the fast path costs ~0 (the validity window already paid for it); the model
//    does not separately amortize the one-time cost of populating the cache.
//  - linearity: margin and fraud-saving are modelled per-tx and additive.

/** A market we might transact in, described in per-tx economic terms. */
export interface MarketParams {
  name: string;
  /** notional value moved per transaction, minor units */
  txValueMinor: number;
  /** gross margin earned on a tx, in basis points of txValue (1bp = 0.01%) */
  marginBps: number;
  /** fraud probability with NO verification at all, 0..1 */
  fraudRateWithout: number;
  /** expected loss when a fraud lands, minor units */
  lossGivenFraudMinor: number;
}

/** The verification regime applied before each tx: a fast (cacheable) path and a
 *  deep (live handshake + corpus re-run) path, with a fraction routed to each. */
export interface VerificationParams {
  /** cost of one fast-path verification, minor units */
  fastCostMinor: number;
  /** cost of one deep-path verification, minor units */
  deepCostMinor: number;
  /** fraction of txs that need the deep path, 0..1 */
  deepFraction: number;
  /** fraction of fast-path txs served from the validity-window cache at ~0 cost, 0..1 */
  cacheHitRate: number;
  /** fraud probability that survives verification, 0..1 */
  residualFraudRate: number;
}

/**
 * Blended per-tx verification cost. The fast path is the (1 - deepFraction) share and
 * only pays fastCost on a cache MISS (the (1 - cacheHitRate) share); the deep path is
 * the deepFraction share and always pays deepCost.
 *
 *   (1 - deepFraction) * fastCost * (1 - cacheHitRate)  +  deepFraction * deepCost
 */
export function perTxVerificationCostMinor(v: VerificationParams): number {
  return (
    (1 - v.deepFraction) * v.fastCostMinor * (1 - v.cacheHitRate) +
    v.deepFraction * v.deepCostMinor
  );
}

export interface Viability {
  /** gross margin on the tx, minor units */
  perTxMarginMinor: number;
  /** blended cost to verify the counterparty, minor units */
  perTxVerificationCostMinor: number;
  /** expected fraud loss avoided BY verifying, minor units */
  expectedFraudSavingMinor: number;
  /** margin + fraudSaving - verificationCost, minor units */
  netPerTxMinor: number;
  /** net strictly positive */
  viable: boolean;
}

/**
 * Per-tx economics of transacting in a market under a verification regime.
 *
 *   margin      = txValue * marginBps / 10000
 *   fraudSaving = (fraudRateWithout - residualFraudRate) * lossGivenFraud
 *   net         = margin + fraudSaving - verificationCost
 *
 * fraudSaving credits verification with the fraud it removes (the delta between the
 * no-verification and residual fraud rates). A market is viable when net > 0.
 */
export function viabilityOf(market: MarketParams, v: VerificationParams): Viability {
  const perTxMarginMinor = (market.txValueMinor * market.marginBps) / 10000;
  const verificationCost = perTxVerificationCostMinor(v);
  const expectedFraudSavingMinor =
    (market.fraudRateWithout - v.residualFraudRate) * market.lossGivenFraudMinor;
  const netPerTxMinor = perTxMarginMinor + expectedFraudSavingMinor - verificationCost;
  return {
    perTxMarginMinor,
    perTxVerificationCostMinor: verificationCost,
    expectedFraudSavingMinor,
    netPerTxMinor,
    viable: netPerTxMinor > 0,
  };
}

/**
 * The maximum per-tx verification cost a market can bear while net stays >= 0. At
 * break-even the regime is free to spend exactly margin + fraudSaving:
 *
 *   breakEven = txValue * marginBps / 10000 + (fraudRateWithout - residualFraudRate) * lossGivenFraud
 *
 * fraudSaving is derived from the market here; the residual/without rates and
 * loss-given-fraud are passed explicitly so the caller can probe a hypothetical regime
 * without constructing a full VerificationParams.
 */
export function breakEvenVerificationCostMinor(
  market: MarketParams,
  residualFraudRate: number,
  fraudRateWithout: number = market.fraudRateWithout,
  lossGivenFraudMinor: number = market.lossGivenFraudMinor,
): number {
  const margin = (market.txValueMinor * market.marginBps) / 10000;
  const fraudSaving = (fraudRateWithout - residualFraudRate) * lossGivenFraudMinor;
  return margin + fraudSaving;
}

/** Filter a set of markets to those that remain viable under a verification regime. */
export function surviving(markets: MarketParams[], v: VerificationParams): MarketParams[] {
  return markets.filter((m) => viabilityOf(m, v).viable);
}
