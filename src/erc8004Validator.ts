// ADP-as-ERC-8004-validator — the disclosure verdict expressed as an ERC-8004
// *validation* attestation.
//
// ERC-8004 names a Validation Registry (https://eips.ethereum.org/EIPS/eip-8004,
// reference contracts at github.com/erc-8004/erc-8004-contracts) as the pluggable
// verification socket the spec itself defers to: a validator posts a `validationResponse`
// carrying a `uint8` 0-100 `response` score for an agent's `validationRequest`, plus an
// off-chain `responseURI`/`responseHash` that backs the score. The EIP leaves the
// validator's *judgement* unspecified — it standardises the socket, not what plugs into
// it. ADP fills exactly that hole: an ADP verifier's verdict (`evaluateDisclosure` →
// `DisclosureVerdict`) IS the off-chain evidence behind a `validationResponse`, and its
// transact/refuse decision maps onto the 0-100 score.
//
// This module is the BRIDGE — pure + structural — that turns a `DisclosureVerdict` into:
//   1. an ERC-8004 `validationResponse`-shaped attestation (`Erc8004ValidationAttestation`),
//      the exact tuple a validator would submit on-chain (response, responseHash, tag, …),
//      bound to the disclosure via `responseHash` (sha256 over the verdict evidence), and
//   2. a typed `ValidationRequestInput` (reused from erc8004Validation.ts) so a caller can
//      OPEN the validation the attestation answers.
//
// On-chain seam (INJECTED, no live RPC in core). erc8004Validation.ts already supplies the
// read client (`getValidationStatus` → `ValidationStatus`). This module composes against
// the SAME read shape: `confirmAttestationOnchain` checks that a registered
// `ValidationStatus` matches an attestation we produced (same response score + responseHash),
// via an injected `ValidationStatusReader` — so the loop closes without this module pulling
// in viem. The write (submitting the `validationResponse`) is a state-changing tx that needs
// a wallet; it is out of scope here, exactly as in erc8004Validation.ts — we model the SHAPE.
//
// Dependency posture: zod + node:crypto only. viem stays optional and untouched here.

import { createHash } from "node:crypto";
import { z } from "zod";
import type { DisclosureVerdict } from "./verify.ts";
import type { ValidationRequestInput, ValidationStatus } from "./erc8004Validation.ts";

/** The on-chain `response` is a `uint8` 0-100 score (0 = failed .. 100 = passed). */
export const ERC8004_RESPONSE_PASS = 100;
export const ERC8004_RESPONSE_FAIL = 0;

/** The default `tag` an ADP validator stamps its responses with, so a consumer can filter
 *  `getSummary(agentId, validators, tag)` to ADP disclosure validations specifically.
 *  ERC-8004 leaves the tag application-defined; ADP reserves this one. */
export const ADP_VALIDATION_TAG = "adp.disclosure";

const Bytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/, "must be a 0x-prefixed 32-byte hash");

/** The ERC-8004 `validationResponse` tuple, as an ADP verifier would submit it. Mirrors
 *  the on-chain ABI `validationResponse(requestHash, response, responseURI, responseHash,
 *  tag)` 1:1, so a caller can encode it directly. `response` is the uint8 0-100 score
 *  derived from the ADP verdict; `responseHash` binds the off-chain evidence on-chain. */
export const Erc8004ValidationAttestationSchema = z.object({
  /** the `requestHash` of the `validationRequest` this answers (the agreed off-chain handle). */
  requestHash: Bytes32,
  /** the uint8 0-100 score. Derived from the verdict: 100 on transact, 0 on refuse. */
  response: z.number().int().min(0).max(100),
  /** URI at which the off-chain evidence (the full ADP verdict) can be fetched. */
  responseURI: z.string(),
  /** sha256 over the canonical verdict evidence — what `responseURI` must resolve to. */
  responseHash: Bytes32,
  /** the application-defined tag; ADP stamps `ADP_VALIDATION_TAG` by default. */
  tag: z.string(),
});

export type Erc8004ValidationAttestation = z.infer<typeof Erc8004ValidationAttestationSchema>;

/** The off-chain evidence document a `responseHash`/`responseURI` resolves to: the ADP
 *  verdict, plus the agent + verifier identities and the disclosure it scored. This is the
 *  payload whose sha256 is the attestation's `responseHash` (the on-chain binding). */
export interface Erc8004ValidationEvidence {
  /** marks the evidence as an ADP-sourced ERC-8004 validation. */
  kind: "adp.erc8004.validation";
  /** the ADP agentId (ed25519 hex) whose disclosure was scored. */
  agentId: string;
  /** the disclosureId of the scored disclosure (the instance handle). */
  disclosureId: string;
  /** the ERC-8004 uint256 agentId (tokenId) the validation is registered against. */
  erc8004AgentId: string;
  /** the full ADP verdict — decision, per-check pass/fail, reasons, cost. */
  verdict: DisclosureVerdict;
}

/** Deterministic sha256 (hex, 0x-prefixed bytes32 form) over a stable JSON serialization —
 *  keys sorted so producers agree on the bytes (the same discipline as the audit chain). */
function sha256Bytes32(value: unknown): string {
  const json = JSON.stringify(value, (_k, v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        )
      : v,
  );
  return `0x${createHash("sha256").update(json).digest("hex")}`;
}

/** Map an ADP verdict's transact/refuse decision to the ERC-8004 uint8 0-100 `response`.
 *  Binary by default (transact → 100, refuse → 0): an ADP verdict is itself a hard
 *  decision, so a graded score would over-claim precision the verdict does not carry. A
 *  caller wanting a graded score (e.g. fraction of checks passed) can supply `opts.score`. */
function verdictToResponse(verdict: DisclosureVerdict, override?: number): number {
  if (override !== undefined) {
    if (!Number.isInteger(override) || override < 0 || override > 100) {
      throw new Error("erc8004 validation response score must be an integer in [0, 100]");
    }
    return override;
  }
  return verdict.decision === "transact" ? ERC8004_RESPONSE_PASS : ERC8004_RESPONSE_FAIL;
}

export interface ToValidationAttestationOptions {
  /** the off-chain URI the evidence is published at (resolves to `responseHash`'s preimage). */
  responseURI?: string;
  /** override the uint8 score (default: 100 on transact, 0 on refuse). Must be in [0, 100]. */
  score?: number;
  /** override the tag (default `ADP_VALIDATION_TAG`). */
  tag?: string;
}

export interface ValidationAttestationContext {
  /** the `requestHash` of the `validationRequest` being answered (the agreed off-chain handle). */
  requestHash: string;
  /** the ADP agentId (ed25519 hex) whose disclosure was scored. */
  agentId: string;
  /** the disclosureId of the scored disclosure. */
  disclosureId: string;
  /** the ERC-8004 uint256 agentId (tokenId) the validation is registered against, as a
   *  decimal/hex string (bigint-serializable). */
  erc8004AgentId: bigint | string;
}

export interface ValidationAttestationResult {
  /** the ERC-8004 `validationResponse`-shaped attestation (the on-chain tuple). */
  attestation: Erc8004ValidationAttestation;
  /** the off-chain evidence whose sha256 is `attestation.responseHash`. Publish at
   *  `attestation.responseURI`; a verifier rehashes it to confirm the binding. */
  evidence: Erc8004ValidationEvidence;
}

/** Express an ADP `DisclosureVerdict` as an ERC-8004 validation attestation. Produces the
 *  on-chain `validationResponse` tuple (score, responseHash, tag, …) plus the off-chain
 *  evidence document the `responseHash` commits to. Pure + deterministic: the same verdict
 *  + context yields the same `responseHash`, so the attestation is reproducible/auditable. */
export function verdictToValidationAttestation(
  verdict: DisclosureVerdict,
  ctx: ValidationAttestationContext,
  opts: ToValidationAttestationOptions = {},
): ValidationAttestationResult {
  if (!/^0x[0-9a-fA-F]{64}$/.test(ctx.requestHash)) {
    throw new Error("requestHash must be a 0x-prefixed 32-byte hash");
  }
  const evidence: Erc8004ValidationEvidence = {
    kind: "adp.erc8004.validation",
    agentId: ctx.agentId,
    disclosureId: ctx.disclosureId,
    erc8004AgentId: ctx.erc8004AgentId.toString(),
    verdict,
  };
  const attestation: Erc8004ValidationAttestation = Erc8004ValidationAttestationSchema.parse({
    requestHash: ctx.requestHash,
    response: verdictToResponse(verdict, opts.score),
    responseURI: opts.responseURI ?? "",
    responseHash: sha256Bytes32(evidence),
    tag: opts.tag ?? ADP_VALIDATION_TAG,
  });
  return { attestation, evidence };
}

/** The typed `validationRequest` an ADP validator constructs to OPEN the validation an
 *  attestation answers. Reuses erc8004Validation.ts's `ValidationRequestInput` shape (the
 *  on-chain `validationRequest(validatorAddress, agentId, requestURI, requestHash)`),
 *  binding it to the SAME `requestHash` the attestation answers. The write needs a wallet
 *  and is out of scope (as in erc8004Validation.ts); this is the encode-ready shape. */
export function validationRequestForAttestation(
  attestation: Erc8004ValidationAttestation,
  fields: { validatorAddress: string; agentId: bigint; requestURI: string },
): ValidationRequestInput {
  return {
    validatorAddress: fields.validatorAddress,
    agentId: fields.agentId,
    requestURI: fields.requestURI,
    requestHash: attestation.requestHash,
  };
}

/** Rehash an evidence document and confirm it is the preimage of an attestation's
 *  `responseHash` (and that the score agrees). The check a consumer runs after fetching
 *  the `responseURI`: it proves the on-chain score is backed by the ADP verdict claimed. */
export function verifyValidationEvidence(
  attestation: Erc8004ValidationAttestation,
  evidence: Erc8004ValidationEvidence,
): { ok: boolean; reason?: string } {
  if (sha256Bytes32(evidence) !== attestation.responseHash) {
    return { ok: false, reason: "evidence does not hash to the attestation responseHash" };
  }
  const expected =
    evidence.verdict.decision === "transact" ? ERC8004_RESPONSE_PASS : ERC8004_RESPONSE_FAIL;
  // A graded score (opts.score) is allowed to diverge from the binary expectation, but a
  // default-scored attestation whose verdict disagrees with its score is inconsistent.
  if (
    attestation.response !== expected &&
    (attestation.response === 0 || attestation.response === 100)
  ) {
    return { ok: false, reason: "attestation score contradicts the evidence verdict decision" };
  }
  return { ok: true };
}

/** The injected on-chain seam: read a registered `ValidationStatus` for a requestHash.
 *  Same shape erc8004Validation.ts's `ValidationRegistryClient.getValidationStatus`
 *  returns — so `createValidationRegistryClient(...).getValidationStatus` drops in as the
 *  reader, while tests inject a stub and core pulls in no chain client. */
export type ValidationStatusReader = (requestHash: string) => Promise<ValidationStatus>;

export interface OnchainAttestationCheck {
  ok: boolean;
  reason?: string;
  /** the on-chain status that was read back, when one was found. */
  status?: ValidationStatus;
}

/** Close the loop on-chain: an attestation we produced must match what the Validation
 *  Registry actually recorded for its `requestHash`. Reads the registered `ValidationStatus`
 *  (via the injected reader), then confirms (1) a response was recorded (lastUpdate != 0),
 *  (2) the recorded `response` score equals the attestation's, and (3) the recorded
 *  `responseHash` equals the attestation's evidence binding. A mismatch on any leg means
 *  the on-chain record is not the attestation we made (stale, spoofed, or different
 *  validator). */
export async function confirmAttestationOnchain(
  attestation: Erc8004ValidationAttestation,
  read: ValidationStatusReader,
): Promise<OnchainAttestationCheck> {
  const status = await read(attestation.requestHash);
  if (status.lastUpdate === 0n) {
    return {
      ok: false,
      reason: "no validationResponse recorded on-chain for this requestHash",
      status,
    };
  }
  if (status.response !== attestation.response) {
    return {
      ok: false,
      reason: `on-chain response ${status.response} does not match attestation ${attestation.response}`,
      status,
    };
  }
  if (status.responseHash.toLowerCase() !== attestation.responseHash.toLowerCase()) {
    return { ok: false, reason: "on-chain responseHash does not match the attestation", status };
  }
  return { ok: true, status };
}
