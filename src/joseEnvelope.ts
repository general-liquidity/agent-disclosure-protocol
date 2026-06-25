// JOSE-backed verification of ADP's v2 flattened-JWS (EdDSA) envelope.
//
// `attestation.ts` signs a disclosure as a flattened JWS (`signDisclosureJws`): the
// EdDSA signature covers ASCII(b64u(protected) + "." + b64u(payload)), the protected
// header carries `alg: "EdDSA"`, and the payload is the RFC 8785 (JCS) canonical
// document. That is a standards-compliant JOSE structure ON PURPOSE — so the headline
// "a stock JOSE library verifies our envelope" is checkable, not just claimed.
//
// This module is the OPTIONAL `jose`-backed verifier that demonstrates exactly that: it
// hands the bespoke-signed envelope to `jose.flattenedVerify` and confirms the same
// signature + key-binding the node:crypto path (`verifyDisclosureJws`) does. ADP does
// NOT depend on jose at the default path — `verifyDisclosureJws` (node:crypto only) stays
// the default. `jose` is an OPTIONAL dependency, dynamically imported here.
//
// Scope: this file does NOT edit attestation.ts. It only ADDS a second verifier over the
// same wire bytes.

import { type SignatureCheck, verifyKeyBinding } from "./attestation.ts";
import type { JwsSignedDisclosure } from "./schema.ts";

const JOSE_HINT =
  "verifying the envelope with a stock JOSE library needs `jose`. " +
  "Install it: `npm install jose` (optional extra), or use `verifyDisclosureJws` for the " +
  "dep-free node:crypto path.";

// The slice of `jose` we drive: a JWK importer and the flattened-JWS verifier. Kept
// minimal so a mock can satisfy it without the package installed.
type JoseKeyLike = unknown;
interface JoseModule {
  importJWK: (jwk: Record<string, unknown>, alg?: string) => Promise<JoseKeyLike>;
  flattenedVerify: (
    jws: { protected?: string; payload: string; signature: string; header?: unknown },
    key: JoseKeyLike,
    options?: { algorithms?: string[] },
  ) => Promise<{ payload: Uint8Array; protectedHeader: Record<string, unknown> }>;
}

let joseLoader: () => Promise<JoseModule> = () => import("jose") as unknown as Promise<JoseModule>;

/** Test seam: inject a mock `jose` module so the optional path is exercised without
 *  installing it. */
export function __setJoseLoader(loader: () => Promise<JoseModule>): void {
  joseLoader = loader;
}

/** Verify an ADP v2 flattened-JWS envelope with the OPTIONAL `jose` library — proving a
 *  stock JOSE verifier accepts our envelope. Recovers the signing key from the embedded
 *  OKP/Ed25519 JWK (`jose.importJWK`), runs `jose.flattenedVerify` restricted to EdDSA,
 *  then binds the payload's `agentId` to that key via the shared `verifyKeyBinding`
 *  (direct hex, did:key, or rotation chain) — identical semantics to the node:crypto
 *  `verifyDisclosureJws`. Throws an install hint if `jose` is absent. */
export async function verifyDisclosureJwsWithJose(
  signed: JwsSignedDisclosure,
): Promise<SignatureCheck> {
  let jose: JoseModule;
  try {
    jose = await joseLoader();
  } catch {
    throw new Error(JOSE_HINT);
  }

  // The protected header must declare EdDSA (mirrors verifyDisclosureJws's guard).
  let header: { alg?: unknown };
  try {
    header = JSON.parse(Buffer.from(signed.protected, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "unreadable protected header" };
  }
  if (header.alg !== "EdDSA") return { ok: false, reason: `unsupported JWS alg: ${String(header.alg)}` };

  const jwk = { ...signed.header.jwk };
  let key: JoseKeyLike;
  try {
    key = await jose.importJWK(jwk, "EdDSA");
  } catch (e) {
    return { ok: false, reason: `jwk import failed: ${(e as Error).message}` };
  }

  let payloadBytes: Uint8Array;
  try {
    const res = await jose.flattenedVerify(
      { protected: signed.protected, payload: signed.payload, signature: signed.signature },
      key,
      { algorithms: ["EdDSA"] },
    );
    payloadBytes = res.payload;
  } catch (e) {
    return { ok: false, reason: `jose verify failed: ${(e as Error).message}` };
  }

  // The signature held over the bespoke bytes; now bind the agentId to the JWK key, exactly
  // as the node:crypto verifier does (so the two paths agree on accept/reject).
  const pubHex = Buffer.from(signed.header.jwk.x, "base64url").toString("hex");
  if (pubHex.length !== 64) return { ok: false, reason: "jwk.x is not a 32-byte ed25519 key" };

  let agentId: unknown;
  try {
    agentId = (JSON.parse(Buffer.from(payloadBytes).toString("utf8")) as { agentId?: unknown }).agentId;
  } catch {
    return { ok: false, reason: "unreadable payload" };
  }
  if (typeof agentId !== "string") return { ok: false, reason: "payload has no agentId" };
  return verifyKeyBinding(agentId, pubHex, signed.rotationChain);
}
