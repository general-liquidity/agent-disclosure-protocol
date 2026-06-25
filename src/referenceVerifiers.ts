// Reference verifier implementations for the four injected attestation seams.
//
// `self.ts`, `worldid.ts`, `humanpassport.ts`, and `worldagent.ts` each leave the HEAVY
// half of verification as an INJECTED seam (a `SelfVerifier`, `WorldIdVerifier`,
// `PassportScorer`, `AgentBookResolver`) so ADP itself bundles no SDK / RPC / network dep.
// That is the right default — but it leaves every adopter hand-wiring the same four
// boilerplate integrations against the same four services. This module ships concrete,
// OPTIONAL reference implementations of each seam so an adopter can drop one in instead.
//
// Dependency posture: NONE of these is a required dep.
//   • Self uses the OPTIONAL `@selfxyz/core` SelfBackendVerifier (dynamically imported).
//   • World ID uses the Developer-Portal `/verify` endpoint via `fetch` (built-in).
//   • Human Passport uses the Passport API scorer via `fetch` (built-in), and is the
//     boundary that parses the API's numeric-STRING `score`/`threshold` into numbers.
//   • World Agent uses an INJECTED `eth_call` transport (the AgentBook `lookupHuman` read)
//     — the RPC itself stays the adopter's choice; this wires the ABI call shape.
// Each factory returns exactly the seam's contract type, so it plugs straight into the
// matching `verify*` function's `opts`.

import type { AgentBookResolver } from "./worldagent.ts";
import type { PassportScorer } from "./humanpassport.ts";
import type { SelfAttestation, SelfVerifier } from "./self.ts";
import { isSelfOnchainRef } from "./self.ts";
import type { WorldIdAttestation, WorldIdVerifier } from "./worldid.ts";

// ── Self: @selfxyz/core SelfBackendVerifier wiring ────────────────────────────

const SELF_HINT =
  "the Self reference verifier needs @selfxyz/core. " +
  "Install it: `npm install @selfxyz/core` (optional extra) and pass it via `loader`, or " +
  "hand-wire your own `SelfVerifier`.";

// The slice of @selfxyz/core's SelfBackendVerifier we drive. Kept minimal so a mock can
// satisfy it without the package installed. `verify` returns the off-chain result shape
// self.ts already models (isValidDetails + discloseOutput).
interface SelfBackendResult {
  isValidDetails: { isValid: boolean; isOlderThanValid?: boolean; isOfacValid?: boolean };
  discloseOutput?: { nullifier?: string };
}
interface SelfBackendVerifierLike {
  verify: (
    attestationId: number | string,
    proof: unknown,
    pubSignals: unknown,
    userContextData: unknown,
  ) => Promise<SelfBackendResult>;
}
interface SelfCoreModule {
  SelfBackendVerifier: new (...args: unknown[]) => SelfBackendVerifierLike;
}

export interface SelfReferenceVerifierConfig {
  /** a constructed `@selfxyz/core` SelfBackendVerifier (or compatible). */
  backend?: SelfBackendVerifierLike;
  /** loader for `@selfxyz/core` when no `backend` is supplied (overridable for tests). */
  loader?: () => Promise<SelfCoreModule>;
  /** args forwarded to the SelfBackendVerifier constructor when built from the loader. */
  constructorArgs?: unknown[];
}

/** A reference `SelfVerifier` backed by `@selfxyz/core`'s SelfBackendVerifier. For an
 *  off-chain proof it calls `backend.verify(...)` and maps the result to the seam's
 *  `{ valid, nullifier? }` contract (valid ⇔ proof valid AND not OFAC-sanctioned — the
 *  same inverted-OFAC rule self.ts applies). An on-chain ref has no self-contained proof
 *  to check here, so it returns `{ valid: false }` (use an `isVerifiedAgent` resolver for
 *  that arm). Pass a constructed `backend`, or a `loader` for the optional package. */
export function makeSelfReferenceVerifier(cfg: SelfReferenceVerifierConfig = {}): SelfVerifier {
  return async (att: SelfAttestation) => {
    if (isSelfOnchainRef(att)) return { valid: false };

    let backend = cfg.backend;
    if (!backend) {
      const load = cfg.loader ?? (() => import("@selfxyz/core") as unknown as Promise<SelfCoreModule>);
      let mod: SelfCoreModule;
      try {
        mod = await load();
      } catch {
        throw new Error(SELF_HINT);
      }
      backend = new mod.SelfBackendVerifier(...(cfg.constructorArgs ?? []));
    }

    const result = await backend.verify(att.attestationId, att, att, att.scope);
    const valid = result.isValidDetails.isValid === true && result.isValidDetails.isOfacValid !== true;
    const nullifier = result.discloseOutput?.nullifier ?? att.nullifier;
    return nullifier !== undefined ? { valid, nullifier } : { valid };
  };
}

// ── World ID: Developer-Portal /verify fetch ──────────────────────────────────

/** The Developer-Portal verify endpoint template; `{app_id}` is substituted per call. */
export const WORLDID_VERIFY_URL = "https://developer.worldcoin.org/api/v2/verify/{app_id}";

export interface WorldIdReferenceVerifierConfig {
  /** override the verify URL template (`{app_id}` placeholder). Defaults to `WORLDID_VERIFY_URL`. */
  urlTemplate?: string;
  /** override the network fetch (tests). Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
}

/** A reference `WorldIdVerifier` that POSTs the proof to the Developer-Portal `/verify/{app_id}`
 *  endpoint and maps the response to the seam's `{ valid, nullifier? }` contract. The portal
 *  returns `{ success: true, ... }` on a valid proof; this surfaces the attestation's
 *  `nullifier_hash` (the portal does not echo it). Uses only `fetch` — no SDK dep. */
export function makeWorldIdReferenceVerifier(
  cfg: WorldIdReferenceVerifierConfig = {},
): WorldIdVerifier {
  const template = cfg.urlTemplate ?? WORLDID_VERIFY_URL;
  return async (att: WorldIdAttestation) => {
    const doFetch = cfg.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined);
    if (!doFetch) return { valid: false };
    const url = template.replace("{app_id}", encodeURIComponent(att.app_id));
    const res = await doFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nullifier_hash: att.nullifier_hash,
        merkle_root: att.merkle_root,
        proof: att.proof,
        verification_level: att.verification_level,
        action: att.action,
        signal_hash: att.signal,
      }),
    });
    if (!res.ok) return { valid: false, nullifier: att.nullifier_hash };
    const body = (await res.json()) as { success?: boolean };
    return { valid: body.success === true, nullifier: att.nullifier_hash };
  };
}

// ── Human Passport: Passport API scorer ───────────────────────────────────────

/** The Passport API stamp-score endpoint template; `{scorer_id}`/`{address}` substituted. */
export const PASSPORT_SCORE_URL =
  "https://api.passport.xyz/v2/stamps/{scorer_id}/score/{address}";

export interface PassportReferenceScorerConfig {
  /** the Passport scorer id (the community/scorer the address is evaluated against). */
  scorerId: string;
  /** the Passport API key (sent as `X-API-KEY`). */
  apiKey: string;
  /** override the score URL template. Defaults to `PASSPORT_SCORE_URL`. */
  urlTemplate?: string;
  /** override the network fetch (tests). Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
}

/** A reference `PassportScorer` that fetches the live Unique Humanity Score from the
 *  Passport API (`X-API-KEY`). This is the boundary that PARSES the API's numeric-STRING
 *  `score`/`threshold` into numbers (humanpassport.ts stores them as numbers). Returns the
 *  seam's `{ score, passing?, threshold? }` contract. Uses only `fetch` — no SDK dep. */
export function makePassportReferenceScorer(cfg: PassportReferenceScorerConfig): PassportScorer {
  const template = cfg.urlTemplate ?? PASSPORT_SCORE_URL;
  return async (address: string) => {
    const doFetch = cfg.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined);
    if (!doFetch) return { score: 0, passing: false };
    const url = template
      .replace("{scorer_id}", encodeURIComponent(cfg.scorerId))
      .replace("{address}", encodeURIComponent(address));
    const res = await doFetch(url, { headers: { "X-API-KEY": cfg.apiKey } });
    if (!res.ok) return { score: 0, passing: false };
    const body = (await res.json()) as { score?: string | number; passing_score?: boolean; threshold?: string | number };
    // Parse the API's numeric STRINGS into numbers (the documented gotcha).
    const score = typeof body.score === "string" ? Number.parseFloat(body.score) : (body.score ?? 0);
    const out: { score: number; passing?: boolean; threshold?: number } = { score };
    if (body.passing_score !== undefined) out.passing = body.passing_score;
    if (body.threshold !== undefined) {
      out.threshold = typeof body.threshold === "string" ? Number.parseFloat(body.threshold) : body.threshold;
    }
    return out;
  };
}

// ── World Agent: AgentBook lookupHuman via an injected RPC ─────────────────────

/** The AgentBook `lookupHuman(address) -> uint256` selector (keccak256 of the signature,
 *  first 4 bytes). Precomputed so the reference resolver needs no keccak dependency. */
export const LOOKUP_HUMAN_SELECTOR = "0x9f181b5e";

/** A minimal `eth_call` transport: send a JSON-RPC `eth_call` and get back the hex result.
 *  The adopter supplies this (viem/ethers/raw fetch) — the RPC endpoint stays their choice. */
export type EthCallTransport = (call: { to: string; data: string }) => Promise<string>;

export interface WorldAgentReferenceResolverConfig {
  /** the `eth_call` transport against a World Chain RPC. */
  transport: EthCallTransport;
  /** the AgentBook contract address. Defaults to the canonical `AGENT_BOOK_ADDRESS`. */
  agentBook?: string;
  /** the lookupHuman selector. Defaults to `LOOKUP_HUMAN_SELECTOR`. */
  selector?: string;
}

/** A reference `AgentBookResolver` that ABI-encodes a `lookupHuman(address)` `eth_call`
 *  against AgentBook and decodes the `uint256` humanId. A zero return means the wallet is
 *  unregistered (`{ registered: false }`); a non-zero return is the registering human's
 *  nullifier (`{ registered: true, humanNullifier }`). The RPC transport is injected — the
 *  endpoint and library stay the adopter's choice; this only wires the ABI call shape. */
export function makeWorldAgentReferenceResolver(
  cfg: WorldAgentReferenceResolverConfig,
): AgentBookResolver {
  // Lazy default so importing worldagent's AGENT_BOOK_ADDRESS doesn't widen this module's
  // hot surface; resolved on first call.
  return async (address: string, _chainId?: string) => {
    const { AGENT_BOOK_ADDRESS } = await import("./worldagent.ts");
    const to = cfg.agentBook ?? AGENT_BOOK_ADDRESS;
    const selector = cfg.selector ?? LOOKUP_HUMAN_SELECTOR;
    // ABI-encode the single address arg: 32-byte left-padded, lowercase, no 0x on the body.
    const arg = address.toLowerCase().replace(/^0x/, "").padStart(64, "0");
    const data = `${selector}${arg}`;
    const raw = await cfg.transport({ to, data });
    const hex = raw.replace(/^0x/, "");
    if (hex.length === 0 || /^0+$/.test(hex)) return { registered: false };
    return { registered: true, humanNullifier: `0x${hex.replace(/^0+/, "")}` };
  };
}
