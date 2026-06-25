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

import { Buffer } from "node:buffer";
import { z } from "zod";
import { RotationStatementSchema } from "./keys.ts";

/** Bump on any breaking change to the disclosure structure. */
export const DISCLOSURE_SCHEMA_VERSION = 1;

const Iso = z.string().describe("ISO-8601 timestamp");
const Hex = z.string().regex(/^[0-9a-fA-F]+$/, "hex string");

// Reverse-domain namespace id (e.g. "com.visa.tap"), the UCP/MCP-style extension key.
// Requires at least one dot, so a bare unknown word ("Unknown") is NOT a valid namespace.
// The pattern string is the single source (generators emit it verbatim); the regex derives.
export const REVERSE_DOMAIN_PATTERN = "^[a-z0-9]+(\\.[a-z0-9-]+)+$";
const ReverseDomain = new RegExp(REVERSE_DOMAIN_PATTERN);

// ── Enum value sets — the SINGLE SOURCE of the schema grammar ─────────────────
// Every enum/literal lives here once. The zod schemas below consume these consts, and
// scripts/generate-schema.ts emits BOTH `schema/*.json` (JSON Schema 2020-12) AND the
// per-language constant files (go/schema_gen.go, python/.../_schema_gen.py,
// rust/src/schema_gen.rs, c/schema_gen.h) from the same values — so the field grammar is
// defined once and never hand-copied into five languages. A drift test regenerates and
// diffs, failing CI if the committed artifacts fall out of sync.
export const DIGEST_ALGORITHM = "sha256" as const;
export const CUSTODY_MODES = ["non_custodial", "custodial"] as const;
export const ATTESTATION_LEVELS = ["none", "signed", "registry_attested"] as const;
export const KNOWN_ATTESTATION_SCHEMES = ["AIP", "VisaTAP", "ERC8004", "DID", "none"] as const;
export const CONSTRAINT_KINDS = ["deny", "cap", "velocity", "rationale", "scope", "other"] as const;
export const TOOL_ACCESS_LEVELS = ["gated", "read_only", "operator_only"] as const;
export const MANDATE_PERIODS = ["day", "week", "month"] as const;
export const REDTEAM_GRADES = ["A", "B", "C", "D", "F"] as const;

// Operator attestation scheme: a known value OR a third-party reverse-domain id, so a new
// attestation scheme is a vendor-namespace publication, not a core enum edit + 5-way re-port.
const AttestationScheme = z.union([
  z.enum(KNOWN_ATTESTATION_SCHEMES),
  z.string().regex(ReverseDomain, "attestation scheme must be a known value or a reverse-domain id"),
]);

// ── 1. System-prompt fingerprint ─────────────────────────────────────────────
// A hash of the agent's composed system prompt. Lets a counterparty pin the
// behavioural surface; combined with the constitution binding, it raises the cost
// of a prompt-injection-mediated substitution (the disclosed prompt no longer
// matches the running one).
export const SystemPromptFingerprintSchema = z.object({
  algorithm: z.literal(DIGEST_ALGORITHM),
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
  kind: z.enum(CONSTRAINT_KINDS),
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
  access: z.enum(TOOL_ACCESS_LEVELS),
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
  period: z.enum(MANDATE_PERIODS),
  allowedRails: z.array(z.string()),
  expiresAt: Iso,
});

export const CapitalEnvelopeSchema = z.object({
  mandates: z.array(MandateDisclosureSchema),
  /** aggregate ceiling across all mandates over the stated period, minor-units */
  aggregatePerPeriodCapMinor: z.number().int().nonnegative().optional(),
  custody: z.enum(CUSTODY_MODES),
  /** declared risk-classifier identity/version, if any */
  riskModel: z.object({ name: z.string(), version: z.string() }).optional(),
});

// ── 5. Operator identity + deniability boundary ──────────────────────────────
export const OperatorIdentitySchema = z.object({
  /** may be pseudonymous; a stable identifier for the deploying party */
  operatorId: z.string(),
  attestation: z.object({
    scheme: AttestationScheme,
    level: z.enum(ATTESTATION_LEVELS),
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
    grade: z.enum(REDTEAM_GRADES),
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
  fingerprintAlgorithm: z.literal(DIGEST_ALGORITHM),
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
  /** Namespaced third-party extensions, keyed by reverse-domain id (e.g.
   *  "com.vendor.feature"). A verifier acts only on keys it recognizes; unknown extensions
   *  are carried and ignored, and canonicalize deterministically — so a vendor can add a
   *  field without a core spec change or a 5-way validator re-port. */
  extensions: z.record(z.string().regex(ReverseDomain), z.unknown()).optional(),
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
  /** Optional key-rotation chain linking the disclosure's stable `agentId` to the
   *  `signature.publicKey` that actually signed, when they differ post-rotation. NOT
   *  part of the signed bytes (it's verification metadata); the agentId it roots at is
   *  signed, so the binding can't be forged. Absent for the common no-rotation case. */
  rotationChain: z.array(RotationStatementSchema).optional(),
});

// ── v2: JWS (EdDSA) flattened envelope ───────────────────────────────────────
// A second, JOSE-interoperable wrapping of the SAME disclosure document. The disclosure
// schema is unchanged; only the envelope differs, so v1 and v2 coexist and a verifier
// accepts either (dual-encode). Distinguished by SHAPE: v2 carries `payload` + a
// base64url `protected` header; v1 carries `disclosure` + a `signature` object. The
// protected header (with `alg`) is part of the signed input here, closing the v1 gap
// where the algorithm field sat outside the signed bytes.
export const JwsSignedDisclosureSchema = z.object({
  /** base64url(UTF8(canonicalize(disclosure))) — the RFC 8785 (JCS) document bytes */
  payload: z.string(),
  /** base64url(UTF8(JSON protected header)); { alg: "EdDSA", typ }. Integrity-protected. */
  protected: z.string(),
  /** unprotected header carrying the signing key as an OKP / Ed25519 JWK */
  header: z.object({
    jwk: z.object({ kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: z.string() }),
  }),
  /** base64url( ed25519 over ASCII(protected + "." + payload) ) */
  signature: z.string(),
  /** optional rotation chain (see SignedDisclosureSchema) */
  rotationChain: z.array(RotationStatementSchema).optional(),
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
export type JwsSignedDisclosure = z.infer<typeof JwsSignedDisclosureSchema>;
/** Either envelope wrapping of a disclosure (v1 object envelope or v2 flattened JWS). */
export type AnySignedDisclosure = SignedDisclosure | JwsSignedDisclosure;

/** True if the envelope is the v2 flattened-JWS form (discriminated by shape). */
export function isJwsSignedDisclosure(signed: AnySignedDisclosure): signed is JwsSignedDisclosure {
  const s = signed as Partial<JwsSignedDisclosure>;
  return typeof s.payload === "string" && typeof s.protected === "string";
}

/** Extract the disclosure document from either envelope shape. For v2 it decodes and
 *  schema-validates the base64url JCS payload. */
export function getDisclosure(signed: AnySignedDisclosure): AgentDisclosure {
  if (isJwsSignedDisclosure(signed)) {
    return AgentDisclosureSchema.parse(JSON.parse(Buffer.from(signed.payload, "base64url").toString("utf8")));
  }
  return signed.disclosure;
}

/** Parse + validate an untrusted disclosure document (structural check only — does
 *  not verify the signature; see ../disclosure verify for that). */
export function parseDisclosure(raw: unknown): AgentDisclosure {
  return AgentDisclosureSchema.parse(raw);
}

/** Parse + validate a signed disclosure envelope (v1 object form). */
export function parseSignedDisclosure(raw: unknown): SignedDisclosure {
  return SignedDisclosureSchema.parse(raw);
}

/** Parse + validate a signed disclosure envelope of EITHER shape (v1 object or v2 JWS),
 *  discriminated by the presence of `payload`/`protected`. */
export function parseAnySignedDisclosure(raw: unknown): AnySignedDisclosure {
  if (raw && typeof raw === "object" && "payload" in raw && "protected" in raw) {
    return JwsSignedDisclosureSchema.parse(raw);
  }
  return SignedDisclosureSchema.parse(raw);
}
