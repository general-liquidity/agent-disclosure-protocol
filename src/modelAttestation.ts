// The model-attestation envelope - the verifiable CLAIM that an agent runs a given
// model. The declared model fingerprint already lives in the disclosure schema
// (ModelIdentitySchema); this wraps it in a standalone, separately-signable
// attestation so a counterparty can verify the model claim on its own and bind it
// to the agentId.
//
// IMPORTANT: this proves the agent DECLARED the model, not that the model actually
// running at transact-time is the declared one. Cryptographically binding the
// RUNNING model needs hardware (TEE) attestation - the honest open P2 item.

import { z } from "zod";
import { canonicalize, signMessage, verifyMessage, type AgentKeyPair } from "./attestation.ts";

const Hex = z.string().regex(/^[0-9a-fA-F]+$/, "hex string");

export const ModelAttestationSchema = z.object({
  /** the agent's stable id = the ed25519 public key (hex) that signs this */
  agentId: z.string(),
  model: z.object({
    name: z.string(),
    fingerprintAlgorithm: z.literal("sha256"),
    /** digest of a declared model identifier / weights manifest */
    digest: Hex,
  }),
  attestedAt: z.string().describe("ISO-8601 timestamp"),
  /** ed25519 signature (hex) over canonical {agentId, model, attestedAt} */
  signature: Hex,
});

export type ModelAttestation = z.infer<typeof ModelAttestationSchema>;

/** Sign a model claim with the agent key. The agentId is bound to the signing key,
 *  so a verifier can later check it matches (the same binding the disclosure uses). */
export function attestModel(
  key: AgentKeyPair,
  model: ModelAttestation["model"],
  now: string,
): ModelAttestation {
  const agentId = key.publicKeyHex;
  return {
    agentId,
    model,
    attestedAt: now,
    signature: signMessage(canonicalize({ agentId, model, attestedAt: now }), key),
  };
}

export interface ModelAttestationCheck {
  ok: boolean;
  reason?: string;
}

/** Verify a model attestation: the signature must check against the agentId's key.
 *  A true result proves the agent DECLARED this model - NOT that a TEE confirms the
 *  model actually running. The runtime-binding half stays the open P2 item. */
export function verifyModelAttestation(att: ModelAttestation): ModelAttestationCheck {
  const message = canonicalize({
    agentId: att.agentId,
    model: att.model,
    attestedAt: att.attestedAt,
  });
  return verifyMessage(message, att.agentId, att.signature)
    ? { ok: true }
    : { ok: false, reason: "signature mismatch" };
}
