// Disclosure revocation - a disclosure (or the agent behind it) can be revoked:
// compromised key, decommissioned agent, rotated identity. A verifier fetches a
// portable status list and refuses any revoked id, the same way a CRL/OCSP list
// gates a certificate. signRevocation makes a revocation attributable to the
// issuing key, so a third party cannot forge a denial-of-service revocation.

import { canonicalize, signMessage, verifyMessage, type AgentKeyPair } from "./attestation.ts";

export interface RevocationStatus {
  revoked: boolean;
  reason?: string;
  revokedAt?: string;
}

interface RevocationEntry {
  id: string;
  reason: string;
  revokedAt: string;
}

/** A portable, fetch/cacheable status list keyed by string id - the id may be a
 *  disclosureId (revoke one document) OR an agentId (revoke the whole agent). */
export class RevocationList {
  readonly #entries = new Map<string, RevocationEntry>();

  revoke(id: string, reason: string, at: string): void {
    this.#entries.set(id, { id, reason, revokedAt: at });
  }

  isRevoked(id: string): boolean {
    return this.#entries.has(id);
  }

  status(id: string): RevocationStatus {
    const e = this.#entries.get(id);
    if (!e) return { revoked: false };
    return { revoked: true, reason: e.reason, revokedAt: e.revokedAt };
  }

  entries(): RevocationEntry[] {
    return [...this.#entries.values()];
  }

  toJSON(): RevocationEntry[] {
    return this.entries();
  }

  static fromJSON(raw: RevocationEntry[]): RevocationList {
    const list = new RevocationList();
    for (const e of raw) list.revoke(e.id, e.reason, e.revokedAt);
    return list;
  }
}

export interface SignedRevocation {
  id: string;
  reason: string;
  revokedAt: string;
  publicKey: string;
  signature: string;
}

/** Sign a revocation so it is attributable to the issuing key - the signed bytes
 *  are the canonical {id, reason, revokedAt}, matching the disclosure's scheme. */
export function signRevocation(id: string, reason: string, at: string, key: AgentKeyPair): SignedRevocation {
  return {
    id,
    reason,
    revokedAt: at,
    publicKey: key.publicKeyHex,
    signature: signMessage(canonicalize({ id, reason, revokedAt: at }), key),
  };
}

/** Verify a signed revocation against its embedded public key. */
export function verifyRevocation(rec: SignedRevocation): boolean {
  return verifyMessage(
    canonicalize({ id: rec.id, reason: rec.reason, revokedAt: rec.revokedAt }),
    rec.publicKey,
    rec.signature,
  );
}
