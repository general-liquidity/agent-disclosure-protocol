// The Agent Disclosure schema (Agent Disclosure Protocol, ADP).
//
// This is the vendor-neutral core of the disclosure protocol: what an agent must
// expose, BEFORE transacting, to be a credible counterparty. It deliberately has
// ZERO dependencies on any product internals (only zod), so it is the portable core
// of the standalone `agent-disclosure` package; a reference implementation
// (OpenSolvency) maps its live primitives onto these structures.
//
// Each field group maps to a surface serious agent products already maintain, and
// each carries the threat it is meant to make legible (the proposal's part-2 threat
// model). The document is the CONTENT; `SignedDisclosure` wraps it with an
// asymmetric signature so a counterparty can verify it without holding any secret.

import { z } from "zod";

/** Bump on any breaking change to the disclosure structure. */
export const DISCLOSURE_SCHEMA_VERSION = 1;

const Iso = z.string().describe("ISO-8601 timestamp");
const Hex = z.string().regex(/^[0-9a-fA-F]+$/, "hex string");

// ── 1. System-prompt fingerprint ─────────────────────────────────────────────
// A hash of the agent's composed system prompt. Lets a counterparty pin the
// behavioural surface; combined with the constitution binding, it raises the cost
// of a prompt-injection-mediated substitution (the disclosed prompt no longer
// matches the running one).
export const SystemPromptFingerprintSchema = z.object({
  algorithm: z.literal("sha256"),
  digest: Hex.describe("hash of the canonical system prompt"),
  promptVersion: z.string().optional(),
});

// ── 2. Operating constitution + hard constraints ─────────────────────────────
// The structured, declared rules the agent operates under. `enforced` is the
// load-bearing field: when true (with an attestation), the constitution IS the
// gate actually running — not a claim — which is the strongest available defense
// against constitution substitution.
export const HardConstraintSchema = z.object({
  id: z.string(),
  description: z.string(),
  /** what category of action it forbids/limits */
  kind: z.enum(["deny", "cap", "velocity", "rationale", "scope", "other"]),
});

export const ConstitutionSchema = z.object({
  /** the hard deny-list — predicates over structured intent, not model text */
  hardConstraints: z.array(HardConstraintSchema),
  /** declared gate parameters (e.g. min-rationale, velocity ceiling) */
  parameters: z.record(z.string(), z.union([z.number(), z.string(), z.boolean()])).optional(),
  /** a digest of the canonical constitution, for binding/diffing */
  digest: Hex,
  /** TRUE iff these constraints are enforced at runtime by a gate the agent cannot
   *  override — the difference between a disclosure and a promise. */
  enforced: z.boolean(),
  /** how `enforced` can be checked (e.g. a reference to the gate/audit) */
  enforcementEvidence: z.string().optional(),
});

// ── 3. Tool inventory + permission boundaries ────────────────────────────────
export const ToolSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  /** gated = passes the governance gate; read_only = no value movement;
   *  operator_only = exists but is NOT reachable by the agent (operator controls) */
  access: z.enum(["gated", "read_only", "operator_only"]),
  movesValue: z.boolean(),
});

export const ToolInventorySchema = z.object({
  tools: z.array(ToolSchema),
  /** the single value-moving path, if the product funnels all spend through one */
  valuePath: z.string().optional(),
});

// ── 4. Capital + risk envelope ───────────────────────────────────────────────
// The mandate set: scoped, capped, expiring spend authority. This is the field no
// model's weights can tell you — what capital envelope the agent operates inside.
export const MandateDisclosureSchema = z.object({
  label: z.string(),
  scope: z.string().describe("what it can pay (class or allowlist, summarized)"),
  currency: z.string(),
  perTxCapMinor: z.number().int().nonnegative(),
  perPeriodCapMinor: z.number().int().nonnegative(),
  period: z.enum(["day", "week", "month"]),
  allowedRails: z.array(z.string()),
  expiresAt: Iso,
});

export const CapitalEnvelopeSchema = z.object({
  mandates: z.array(MandateDisclosureSchema),
  /** aggregate ceiling across all mandates over the stated period, minor-units */
  aggregatePerPeriodCapMinor: z.number().int().nonnegative().optional(),
  custody: z.enum(["non_custodial", "custodial"]),
  /** declared risk-classifier identity/version, if any */
  riskModel: z.object({ name: z.string(), version: z.string() }).optional(),
});

// ── 5. Operator identity + deniability boundary ──────────────────────────────
export const OperatorIdentitySchema = z.object({
  /** may be pseudonymous; a stable identifier for the deploying party */
  operatorId: z.string(),
  attestation: z.object({
    scheme: z.enum(["AIP", "VisaTAP", "ERC8004", "none"]),
    level: z.enum(["none", "signed", "registry_attested"]),
    evidence: z.string().optional(),
  }),
  /** explicit statement of what the operator is / is NOT accountable for —
   *  the deniability boundary the proposal calls for. */
  deniabilityBoundary: z.string(),
});

// ── 6. Cumulative deployment history ─────────────────────────────────────────
// Derived from a tamper-evident, hash-linked audit chain; the `chainAnchor` lets a
// counterparty verify the summary against the real history rather than trust it.
export const DeploymentHistorySchema = z.object({
  /** head hash of the signed audit chain this summary is computed from */
  chainAnchor: Hex,
  summary: z.object({
    totalDecisions: z.number().int().nonnegative(),
    settledCount: z.number().int().nonnegative(),
    blockedCount: z.number().int().nonnegative(),
    firstSeen: Iso.optional(),
    lastActive: Iso.optional(),
  }),
  /** how the chain can be independently verified (e.g. an export-verify endpoint) */
  verificationHint: z.string().optional(),
});

// ── 7. Red-team pass/fail attestations ───────────────────────────────────────
// Against a public adversarial corpus, so the result is comparable and the agent
// cannot grade itself on a private rubric.
export const RedTeamAttestationSchema = z.object({
  corpus: z.object({ name: z.string(), version: z.string() }),
  result: z.object({
    grade: z.enum(["A", "B", "C", "D", "F"]),
    score: z.number().min(0).max(100),
    passed: z.boolean(),
    hardFails: z.array(z.string()).default([]),
  }),
  attestedAt: Iso,
  /** signed reference / where the run can be re-verified */
  attestationRef: z.string().optional(),
});

// ── Declared model identity (the model-swap defense, declared half) ──────────
// A fingerprint of the model the agent declares it runs on. This is the cheap,
// declarable half; cryptographically proving the RUNNING model matches at
// transact-time needs hardware (TEE) attestation - the honest open P2 item.
export const ModelIdentitySchema = z.object({
  name: z.string(),
  fingerprintAlgorithm: z.literal("sha256"),
  /** digest of a declared model identifier / weights manifest */
  digest: Hex,
});

// ── Field-level provenance ───────────────────────────────────────────────────
// How each field was derived/attested, so a verifier can WEIGHT claims (a field
// bound to an enforced gate is worth more than a self-asserted one).
export const FieldProvenanceSchema = z.object({
  /** where the field came from, e.g. "opensolvency-gate", "audit-chain", "spendtrust" */
  derivedFrom: z.string(),
  /** an attestation reference, if the source is itself attested */
  attestedBy: z.string().optional(),
});

// ── The disclosure document ──────────────────────────────────────────────────
export const AgentDisclosureSchema = z.object({
  version: z.literal(DISCLOSURE_SCHEMA_VERSION),
  /** unique id for this disclosure instance */
  disclosureId: z.string(),
  /** the agent's stable id — by convention the key id used to sign (see envelope) */
  agentId: z.string(),
  issuedAt: Iso,
  /** freshness window — a verifier rejects an expired disclosure (anti-staleness) */
  validUntil: Iso,
  /** anti-replay: a fresh nonce per disclosure; pair with a challenge for liveness */
  nonce: z.string(),
  /** binds the disclosure to a tamper-evident anchor (e.g. the audit-chain head),
   *  so it cannot be retro-edited without breaking the link */
  auditAnchor: Hex.optional(),

  systemPrompt: SystemPromptFingerprintSchema,
  constitution: ConstitutionSchema,
  tools: ToolInventorySchema,
  capital: CapitalEnvelopeSchema,
  operator: OperatorIdentitySchema,
  history: DeploymentHistorySchema,
  redTeam: RedTeamAttestationSchema.optional(),
  /** declared model identity (the declarable half of the model-swap defense) */
  model: ModelIdentitySchema.optional(),
  /** per-field derivation/attestation, so a verifier can weight claims.
   *  keyed by top-level field name (e.g. "constitution", "history"). */
  provenance: z.record(z.string(), FieldProvenanceSchema).optional(),
});

// ── The signed envelope ──────────────────────────────────────────────────────
// Asymmetric signature so a COUNTERPARTY can verify without any shared secret —
// the one capability HMAC (OpenSolvency's audit signing) can't provide here.
export const SignedDisclosureSchema = z.object({
  disclosure: AgentDisclosureSchema,
  signature: z.object({
    algorithm: z.literal("ed25519"),
    /** the signer's public key (hex), = the agentId's key material */
    publicKey: Hex,
    /** signature over the canonicalized disclosure (hex) */
    value: Hex,
  }),
});

// ── Inferred types ───────────────────────────────────────────────────────────
export type SystemPromptFingerprint = z.infer<typeof SystemPromptFingerprintSchema>;
export type HardConstraint = z.infer<typeof HardConstraintSchema>;
export type Constitution = z.infer<typeof ConstitutionSchema>;
export type Tool = z.infer<typeof ToolSchema>;
export type ToolInventory = z.infer<typeof ToolInventorySchema>;
export type MandateDisclosure = z.infer<typeof MandateDisclosureSchema>;
export type CapitalEnvelope = z.infer<typeof CapitalEnvelopeSchema>;
export type OperatorIdentity = z.infer<typeof OperatorIdentitySchema>;
export type DeploymentHistory = z.infer<typeof DeploymentHistorySchema>;
export type RedTeamAttestation = z.infer<typeof RedTeamAttestationSchema>;
export type ModelIdentity = z.infer<typeof ModelIdentitySchema>;
export type FieldProvenance = z.infer<typeof FieldProvenanceSchema>;
export type AgentDisclosure = z.infer<typeof AgentDisclosureSchema>;
export type SignedDisclosure = z.infer<typeof SignedDisclosureSchema>;

/** Parse + validate an untrusted disclosure document (structural check only — does
 *  not verify the signature; see ../disclosure verify for that). */
export function parseDisclosure(raw: unknown): AgentDisclosure {
  return AgentDisclosureSchema.parse(raw);
}

/** Parse + validate a signed disclosure envelope. */
export function parseSignedDisclosure(raw: unknown): SignedDisclosure {
  return SignedDisclosureSchema.parse(raw);
}
