// The Agent Disclosure Protocol (ADP) - a vendor-neutral disclosure protocol for
// agent-to-agent commerce, and the wire format for Verifiable Agency. An agent
// exposes, BEFORE transacting, what it is committed to (its constitution, capital
// envelope, tool boundary, history, red-team posture); a counterparty verifies that
// disclosure and decides transact / refuse before a single unit of value moves.
//
// This package is the protocol + a reference verifier. It has ONE runtime
// dependency (zod) and uses only node:crypto for signing, so any agent stack can
// emit or verify a disclosure. OpenSolvency is the reference implementation that
// populates these structures from a live, enforced governance gate.
//
// See SPEC.md for the normative protocol and conformance/ for the test vectors.

// The disclosure document + signed envelope (zod schemas + inferred types).
export * from "./schema.ts";

// Attestation primitives: ed25519 signing, canonicalization, freshness. A
// counterparty verifies with the public key in the envelope - no shared secret.
export * from "./attestation.ts";

// The live challenge-response handshake (defeats identity replay).
export * from "./handshake.ts";

// Counterparty verification: evaluate a disclosure against a policy -> verdict.
export * from "./verify.ts";

// The verifier-side over-the-wire loop (fetch -> evaluate -> handshake -> decide).
export * from "./client.ts";

// Outbound disclose-before-settle + mutual disclosure.
export * from "./guard.ts";

// Tiered verification + a validity-window cache (the economic enabler).
export * from "./cache.ts";

// Selective / redactable disclosure (reveal only what a policy requires).
export * from "./redaction.ts";

// Revocation status list (revoke a compromised or decommissioned identity).
export * from "./revocation.ts";

// Transparency log - an append-only, third-party-auditable anchor.
export * from "./transparency.ts";

// The economic-viability model (which markets survive at verification cost C).
export * from "./economics.ts";
