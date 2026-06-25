// Key management for agent signing identities: a KeyRing to hold many identities,
// and signed key ROTATION so identity survives a key change. Rotation matters
// because an agentId IS its public key here; without a chained statement, a new key
// is just an unrelated identity. The old key signs over the new one, so a verifier
// who trusted the old identity can follow the chain to the new one.

import { z } from "zod";
import {
  type AgentKeyPair,
  agentKeyFromPrivateHex,
  exportAgentKey,
  rotationStatementBody,
  signMessage,
  verifyMessage,
} from "./attestation.ts";

/** Serialize a key pair's signing identity to a hex string (PKCS8 DER). */
export function keyToFile(key: AgentKeyPair): string {
  return exportAgentKey(key);
}

/** Reconstruct a key pair from a persisted hex string (PKCS8 DER). */
export function keyFromFile(hex: string): AgentKeyPair {
  return agentKeyFromPrivateHex(hex);
}

// ── KeyRing ──────────────────────────────────────────────────────────────────
// Holds multiple agent identities keyed by agentId (= public key hex), so a
// process running several agents can look up the right signer.
export class KeyRing {
  private readonly keys = new Map<string, AgentKeyPair>();

  /** Register a key under its agentId (publicKeyHex). Last write wins. */
  add(key: AgentKeyPair): void {
    this.keys.set(key.publicKeyHex, key);
  }

  /** Look up a key by agentId, or undefined if absent. */
  get(agentId: string): AgentKeyPair | undefined {
    return this.keys.get(agentId);
  }

  /** The agentIds currently held. */
  agentIds(): string[] {
    return [...this.keys.keys()];
  }
}

// ── Key rotation ─────────────────────────────────────────────────────────────
// A statement signed by the OLD key attesting that identity moves to the NEW key.
// Verifying it against the `from` key proves the holder of the old identity
// authorized the change, chaining trust across the rotation.
export const RotationStatementSchema = z.object({
  type: z.literal("rotation"),
  /** agentId (public key hex) being rotated away from */
  from: z.string(),
  /** agentId (public key hex) being rotated to */
  to: z.string(),
  rotatedAt: z.string().describe("ISO-8601 timestamp"),
  /** old key's signature over the canonical {type, from, to, rotatedAt} body (hex) */
  signature: z.string().regex(/^[0-9a-fA-F]+$/, "hex string"),
});

export type RotationStatement = z.infer<typeof RotationStatementSchema>;

/** Issue a rotation statement: the OLD key signs that identity moves to the new
 *  key. The new key never signs here; trust flows forward from the established
 *  identity. */
export function rotateKey(
  oldKey: AgentKeyPair,
  newKey: AgentKeyPair,
  now: string,
): RotationStatement {
  const from = oldKey.publicKeyHex;
  const to = newKey.publicKeyHex;
  return {
    type: "rotation",
    from,
    to,
    rotatedAt: now,
    signature: signMessage(rotationStatementBody(from, to, now), oldKey),
  };
}

export interface RotationCheck {
  ok: boolean;
  reason?: string;
}

/** Verify a rotation statement's signature against the `from` key. A valid result
 *  means the holder of the old identity authorized the move to `to`. */
export function verifyRotation(statement: RotationStatement): RotationCheck {
  const body = rotationStatementBody(statement.from, statement.to, statement.rotatedAt);
  return verifyMessage(body, statement.from, statement.signature)
    ? { ok: true }
    : { ok: false, reason: "rotation signature does not verify against the from key" };
}
