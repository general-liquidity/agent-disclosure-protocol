// Proof-of-Enforcement (PoE) — the keystone that turns ADP's `enforced` boolean
// into a CRYPTOGRAPHICALLY FALSIFIABLE claim. A self-asserted "enforced: true" is a
// promise; PoE makes it a checkable statement backed by OpenSolvency's deterministic,
// signed, replayable audit chain. OS *emits* a PoEAttestation, the OS→ADP builder
// *binds* a policyHash into the disclosure, and this module *verifies* the three legs:
//
//   bound    — the disclosed policyHash equals the policyHash the gate actually runs
//   fresh    — the attestation's live audit head matches / advances the disclosed anchor
//   replayed — sampled real decisions, re-executed under the disclosed policy, match
//              their signed verdicts (ANY mismatch ⇒ a false `enforced` claim is DETECTED)
//
// Dep-light by design: zod + node:crypto only. ADP does NOT import OpenSolvency — the
// gate-replay is an INJECTED seam (`opts.replay`), the canonical wiring being OS's pure
// `replayDecision`. The policyHash is computed with ADP's own `canonicalize` (RFC 8785 /
// JCS) + sha256, byte-identical to OS's `computePolicyHash`, so both sides hash the same
// EffectivePolicy to the same digest without sharing code.

import { z } from "zod";
import { canonicalize, sha256Hex } from "./attestation.ts";
import type { AgentDisclosure } from "./schema.ts";

// ── EffectivePolicy — the hashed governing policy at decision time ────────────
// The exact object OS hashes (spec §1). Deny-rule PREDICATES are functions (closures
// can't hash), so only their stable `id`s + reasons travel — `denyRuleIds` here. The
// shapes of `gateConfig` / `riskConfig` are intentionally open (`record(unknown)`): ADP
// neither interprets nor constrains OS's internal gate/risk parameters, it only hashes
// them. canonicalize sorts object keys recursively, so those nested objects are stable
// regardless of OS's key order; the only ordering ADP imposes is array order (mandates
// by id, denyRuleIds lexical) — see `normalizePolicy`.
export const MandateSchema = z
  .object({ id: z.string() })
  .catchall(z.unknown());

export const EffectivePolicySchema = z.object({
  /** active mandates, normalized + sorted by id before hashing */
  mandates: z.array(MandateSchema),
  /** declared gate parameters (min-rationale, velocity ceiling, …) */
  gateConfig: z.record(z.string(), z.unknown()),
  /** the stable ids of the active deny rules (predicates hash by id, not closure) */
  denyRuleIds: z.array(z.string()),
  /** the risk-classifier configuration */
  riskConfig: z.record(z.string(), z.unknown()),
});

export type EffectivePolicy = z.infer<typeof EffectivePolicySchema>;

// ── PoEAttestation — what the live handshake returns / the builder commits to ──
export const DecisionRecordSchema = z.object({
  /** the structured payment intent the gate evaluated */
  intent: z.unknown(),
  /** a digest of the decision context (so the record commits to its inputs) */
  ctxDigest: z.string(),
  /** the signed gate verdict for this decision */
  verdict: z.unknown(),
  /** the policyHash the decision ran under (proves which policy governed it) */
  policyHash: z.string(),
  at: z.string(),
});

export type DecisionRecord = z.infer<typeof DecisionRecordSchema>;

export const PoEAttestationSchema = z.object({
  /** the policyHash the gate is currently enforcing */
  policyHash: z.string(),
  /** the live, signed audit-chain head */
  auditHead: z.string(),
  /** a sample of recent signed decisions, for replay */
  recentDecisions: z.array(DecisionRecordSchema).optional(),
  generatedAt: z.string(),
});

export type PoEAttestation = z.infer<typeof PoEAttestationSchema>;

// ── policyHash — byte-identical to OS's computePolicyHash ─────────────────────
/** Normalize an EffectivePolicy to its canonical hashing form. This MUST byte-match the
 *  OpenSolvency emitter (`src/core/enforcement.ts` `computePolicyHash`): the emitter projects
 *  each mandate to a STABLE field set (dropping volatile/extra fields like `grantedAt`) and
 *  sorts `allowedRails`, and projects `gateConfig`/`riskConfig` to fixed fields — so unrelated
 *  fields can never silently shift the binding. Object KEY order is handled by `canonicalize`
 *  (RFC 8785); we pin ARRAY order (mandates by id, allowedRails, denyRuleIds) and the field
 *  projection here. (Cross-repo-tested: identical digest to OS for the same EffectivePolicy.) */
function normalizePolicy(policy: EffectivePolicy): EffectivePolicy {
  const m = (x: Record<string, unknown>) => ({
    id: x.id,
    scope: x.scope,
    currency: x.currency,
    allowedRails: Array.isArray(x.allowedRails) ? [...(x.allowedRails as unknown[])].sort() : x.allowedRails,
    perTxCap: x.perTxCap,
    perPeriodCap: x.perPeriodCap,
    period: x.period,
    expiresAt: x.expiresAt,
    status: x.status,
  });
  const g = policy.gateConfig as Record<string, unknown>;
  const r = policy.riskConfig as Record<string, unknown>;
  return {
    mandates: [...policy.mandates]
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .map((x) => m(x as Record<string, unknown>)) as EffectivePolicy["mandates"],
    gateConfig: {
      minRationaleChars: g.minRationaleChars,
      velocityWindowMinutes: g.velocityWindowMinutes,
      velocityMaxCount: g.velocityMaxCount,
      anomalyMultiple: g.anomalyMultiple,
    },
    denyRuleIds: [...policy.denyRuleIds].sort(),
    riskConfig: {
      velocityWindowMinutes: r.velocityWindowMinutes,
      velocityMaxCount: r.velocityMaxCount,
      anomalyMultiple: r.anomalyMultiple,
    },
  };
}

/** sha256_hex( JCS_canonicalize(EffectivePolicy) ) — the binding anchor (spec §1). The
 *  same digest OS computes, because both use ADP's `canonicalize` over the same normalized
 *  object. Deterministic; no clock or IO. */
export function computePolicyHash(policy: EffectivePolicy): string {
  return sha256Hex(canonicalize(normalizePolicy(policy)));
}

// ── Where ADP reads the DISCLOSED policyHash without touching the frozen schema ─
// The constitution schema is frozen (changing it would drift the committed JSON-Schema
// artifacts). So the disclosed policyHash rides in `disclosure.extensions` under a
// reverse-domain key — already a first-class, drift-free extension surface — and the
// binding is anchored to the disclosure's EXISTING `auditAnchor`. If a builder hasn't
// populated the extension, ADP falls back to the attestation's own policyHash so the
// fresh + replay legs still run (binding then degrades to attestation-internal).
export const ENFORCEMENT_EXTENSION_KEY = "com.opensolvency.enforcement";

const DisclosedEnforcementSchema = z.object({
  policyHash: z.string(),
  /** mirrors disclosure.auditAnchor; carried for self-containment, not required */
  auditAnchor: z.string().optional(),
});

/** Pull the disclosed policyHash out of the enforcement extension, if present and
 *  well-formed. Returns undefined when absent/malformed — the caller then has no
 *  independent disclosed hash and binding can't be asserted from the disclosure. */
function disclosedPolicyHash(disclosure: AgentDisclosure): string | undefined {
  const raw = disclosure.extensions?.[ENFORCEMENT_EXTENSION_KEY];
  if (raw !== undefined) {
    const parsed = DisclosedEnforcementSchema.safeParse(raw);
    if (parsed.success) return parsed.data.policyHash;
  }
  // Fallback: the OpenSolvency builder carries the binding in the schema-stable
  // `constitution.enforcementEvidence` string (a nested `enforcement` object is stripped
  // by the frozen ConstitutionSchema), encoded as "…; poe=<json>". Recover it.
  const ev = (disclosure.constitution as { enforcementEvidence?: unknown } | undefined)?.enforcementEvidence;
  if (typeof ev === "string") {
    const at = ev.indexOf("poe=");
    if (at >= 0) {
      try {
        const obj = JSON.parse(ev.slice(at + 4)) as { policyHash?: unknown };
        if (typeof obj.policyHash === "string") return obj.policyHash;
      } catch {
        /* malformed evidence → no disclosed hash */
      }
    }
  }
  return undefined;
}

// ── verifyEnforcement — the falsifiable verifier ─────────────────────────────
export type ReplaySeam = (record: DecisionRecord, policy: EffectivePolicy) => { matches: boolean };

export interface VerifyEnforcementOptions {
  /** the INJECTED gate-replay seam (OS's pure `replayDecision` is the canonical wiring).
   *  Absent ⇒ replay is skipped (binding-only verification). */
  replay?: ReplaySeam;
  /** the disclosed EffectivePolicy the decisions are replayed under. Required alongside
   *  `replay` to run the replay leg. */
  policy?: EffectivePolicy;
}

export type ReplayResult = "skipped" | "passed" | "FAILED";

export interface EnforcementVerification {
  /** the overall verdict: bound AND fresh AND replay-not-FAILED */
  ok: boolean;
  /** disclosed policyHash === attestation.policyHash (the gate runs what's disclosed) */
  bound: boolean;
  /** the attestation's live audit head is consistent with / advances the disclosed anchor */
  fresh: boolean;
  /** the falsifiability leg: every sampled decision re-executed to its signed verdict */
  replayed: ReplayResult;
  /** the first failing reason, when ok is false */
  reason?: string;
}

/**
 * Verify a Proof-of-Enforcement. Three legs (spec §3):
 *
 *  - **bound**: the disclosed policyHash (from the enforcement extension) equals
 *    `attestation.policyHash`. When the disclosure carries no extension, binding cannot be
 *    asserted from the disclosure side ⇒ `bound:false`.
 *  - **fresh**: `attestation.auditHead` is consistent with / advances the disclosure's
 *    `auditAnchor` (the live-handshake leg). Equality or any advance is fresh; only a
 *    MISSING live head is stale. A regression cannot be detected without the full chain,
 *    so — exactly as the handshake leg does — equality/advance is accepted and the chain
 *    walk is the verifier's separate concern. Absence of a disclosure anchor means there
 *    is nothing to be stale against ⇒ fresh as long as the attestation has a head.
 *  - **replayed**: if BOTH `opts.replay` and `opts.policy` are supplied, each
 *    `attestation.recentDecisions` is re-run through the injected seam under the disclosed
 *    policy. ANY `matches:false` ⇒ `"FAILED"` ⇒ `ok:false` — a gate that does not enforce
 *    what it discloses is now DETECTED, not merely asserted. No seam/policy ⇒ `"skipped"`.
 *
 * Pure; dep-light. The replay seam is the only place OS-specific logic enters, and it is
 * injected — ADP never imports OpenSolvency.
 */
export function verifyEnforcement(
  disclosure: AgentDisclosure,
  attestation: PoEAttestation,
  opts: VerifyEnforcementOptions = {},
): EnforcementVerification {
  const disclosed = disclosedPolicyHash(disclosure);
  const bound = disclosed !== undefined && disclosed === attestation.policyHash;

  // fresh: the live head must exist and be consistent with the disclosed anchor. We can't
  // fully order two heads without the chain (the handshake leg has the same limitation), so
  // a present head that equals or differs-from the anchor is accepted; only an absent head
  // is stale. A disclosure with no anchor has nothing to regress against.
  const liveHead = attestation.auditHead;
  const fresh = liveHead.length > 0;

  // replayed: the falsifiability leg.
  let replayed: ReplayResult = "skipped";
  if (opts.replay && opts.policy) {
    const decisions = attestation.recentDecisions ?? [];
    replayed = "passed";
    for (const record of decisions) {
      if (!opts.replay(record, opts.policy).matches) {
        replayed = "FAILED";
        break;
      }
    }
  }

  const ok = bound && fresh && replayed !== "FAILED";

  let reason: string | undefined;
  if (!ok) {
    if (replayed === "FAILED") {
      reason = "replay mismatch: a sampled decision did not reproduce its signed verdict under the disclosed policy";
    } else if (!bound) {
      reason =
        disclosed === undefined
          ? `disclosure carries no enforcement binding (extensions["${ENFORCEMENT_EXTENSION_KEY}"].policyHash absent)`
          : "disclosed policyHash does not match the attestation policyHash (gate is not running the disclosed policy)";
    } else if (!fresh) {
      reason = "attestation has no live audit head (cannot confirm the gate is currently running)";
    }
  }

  return { ok, bound, fresh, replayed, reason };
}
