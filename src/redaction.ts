// Selective / redactable disclosure via salted hash commitments.
//
// The signature is over per-field COMMITMENTS, not the cleartext, so an agent can
// reveal only the fields a counterparty's policy requires (privacy + the operator's
// deniability boundary) WITHOUT breaking the signature. A revealed field carries its
// value plus its per-field salt; the verifier recomputes the commitment and checks it
// against the signed set. Withheld fields stay as opaque commitments. The salt is
// per-field so revealing one field leaks nothing about another, and the salt is what
// stops a verifier from brute-forcing a low-entropy value out of its commitment.
//
// Vendor-neutral: node:crypto + the disclosure schema/attestation only.

import { randomBytes } from "node:crypto";
import { canonicalize, sha256Hex, signMessage, verifyMessage, type AgentKeyPair } from "./attestation.ts";
import type { AgentDisclosure } from "./schema.ts";

// Fields a holder may withhold. Everything else is always-clear meta, because a
// verifier needs identity + freshness to even decide whether to look at the rest.
export const REDACTABLE_FIELDS = [
  "systemPrompt",
  "constitution",
  "tools",
  "capital",
  "operator",
  "history",
  "redTeam",
  "model",
  "provenance",
] as const;

export type RedactableField = (typeof REDACTABLE_FIELDS)[number];

// Always-clear identity/freshness fields lifted verbatim into the signed envelope.
export interface DisclosureMeta {
  version: AgentDisclosure["version"];
  disclosureId: string;
  agentId: string;
  issuedAt: string;
  validUntil: string;
  nonce: string;
  auditAnchor?: string;
}

export interface RedactableSignature {
  algorithm: "ed25519";
  publicKey: string;
  value: string;
}

export interface RedactableDisclosure {
  meta: DisclosureMeta;
  /** field name -> salted commitment over its canonical value */
  commitments: Record<string, string>;
  signature: RedactableSignature;
}

// What the agent retains so it can later reveal any subset of fields. Never shipped.
export interface RedactableHolder {
  redactable: RedactableDisclosure;
  /** the cleartext value of each committed field */
  fields: Record<string, unknown>;
  /** the per-field salt used in each commitment */
  salts: Record<string, string>;
}

export interface RevealedField {
  value: unknown;
  salt: string;
}

export interface RedactedView {
  meta: DisclosureMeta;
  commitments: Record<string, string>;
  /** only the disclosed fields, each with the salt needed to recompute its commitment */
  revealed: Record<string, RevealedField>;
  signature: RedactableSignature;
}

export interface VerifyRedactedResult {
  ok: boolean;
  reason?: string;
  revealedFields: string[];
}

/** Commitment for a field: bind its canonical value to a per-field salt so the
 *  commitment is hiding (salt) and binding (sha256). */
function commit(value: unknown, salt: string): string {
  return sha256Hex(`${canonicalize(value)}:${salt}`);
}

function extractMeta(disclosure: AgentDisclosure): DisclosureMeta {
  return {
    version: disclosure.version,
    disclosureId: disclosure.disclosureId,
    agentId: disclosure.agentId,
    issuedAt: disclosure.issuedAt,
    validUntil: disclosure.validUntil,
    nonce: disclosure.nonce,
    auditAnchor: disclosure.auditAnchor,
  };
}

/** Build the redactable form: commit every present redactable field under a fresh
 *  salt, then sign {meta, commitments}. The holder keeps values + salts for reveal. */
export function prepareRedactable(
  disclosure: AgentDisclosure,
  key: AgentKeyPair,
): { redactable: RedactableDisclosure; holder: RedactableHolder } {
  const meta = extractMeta(disclosure);
  const commitments: Record<string, string> = {};
  const fields: Record<string, unknown> = {};
  const salts: Record<string, string> = {};

  for (const field of REDACTABLE_FIELDS) {
    const value = (disclosure as Record<string, unknown>)[field];
    if (value === undefined) continue;
    const salt = randomBytes(16).toString("hex");
    commitments[field] = commit(value, salt);
    fields[field] = value;
    salts[field] = salt;
  }

  const signature: RedactableSignature = {
    algorithm: "ed25519",
    publicKey: key.publicKeyHex,
    value: signMessage(canonicalize({ meta, commitments }), key),
  };

  const redactable: RedactableDisclosure = { meta, commitments, signature };
  return { redactable, holder: { redactable, fields, salts } };
}

/** Produce a view revealing only `fields` (value + salt). All commitments and the
 *  signature are carried through unchanged, so withheld fields stay verifiable-but-opaque. */
export function reveal(holder: RedactableHolder, fields: string[]): RedactedView {
  const { meta, commitments, signature } = holder.redactable;
  const revealed: Record<string, RevealedField> = {};

  for (const field of fields) {
    // Only fields that were actually committed can be revealed.
    if (!(field in commitments)) continue;
    revealed[field] = { value: holder.fields[field], salt: holder.salts[field] };
  }

  return { meta, commitments, revealed, signature };
}

/** Verify a redacted view:
 *   1. the claimed agentId is the signing key (identity binding),
 *   2. the signature covers {meta, commitments} (no field can be added/removed/edited
 *      without breaking it),
 *   3. each revealed field recomputes to its committed value.
 *  Returns the field names whose disclosure is cryptographically proven. */
export function verifyRedacted(view: RedactedView): VerifyRedactedResult {
  if (view.meta.agentId !== view.signature.publicKey) {
    return { ok: false, reason: "agentId does not match the signing public key", revealedFields: [] };
  }

  const signed = canonicalize({ meta: view.meta, commitments: view.commitments });
  if (!verifyMessage(signed, view.signature.publicKey, view.signature.value)) {
    return { ok: false, reason: "signature mismatch", revealedFields: [] };
  }

  const revealedFields: string[] = [];
  for (const [field, { value, salt }] of Object.entries(view.revealed)) {
    const expected = view.commitments[field];
    if (expected === undefined) {
      return { ok: false, reason: `revealed field '${field}' has no commitment`, revealedFields: [] };
    }
    if (commit(value, salt) !== expected) {
      return { ok: false, reason: `revealed field '${field}' does not match its commitment`, revealedFields: [] };
    }
    revealedFields.push(field);
  }

  return { ok: true, revealedFields };
}
