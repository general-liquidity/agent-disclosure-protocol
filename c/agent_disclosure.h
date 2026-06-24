/*
 * Agent Disclosure Protocol (ADP) - native C verifier.
 *
 * Ports the canonicalization + verification core from the TypeScript reference
 * (src/attestation.ts, src/verify.ts, src/handshake.ts) so the protocol verifies
 * even in C. The crux is canonicalize() byte-matching the TS reference; the
 * signatures the TS emitter produced (conformance/interop.json) must verify here.
 *
 * Crypto is libsodium (crypto_sign_verify_detached over a raw 32-byte ed25519
 * public key, crypto_hash_sha256). JSON is vendored cJSON; cJSON keeps insertion
 * order and stores numbers as double, so adp_canonicalize() sorts object members
 * by key and prints integral numbers without a decimal point.
 */
#ifndef ADP_AGENT_DISCLOSURE_H
#define ADP_AGENT_DISCLOSURE_H

#include <stdbool.h>
#include <stddef.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Canonicalization (SPEC.md §4) ─────────────────────────────────────────────
 * Returns a freshly malloc'd, NUL-terminated canonical string. Caller frees.
 * Mirrors canonicalize() in src/attestation.ts:
 *   - object: "{" + keys sorted lexicographically (byte order), undefined values
 *     dropped, <json-key>:<canonicalize(value)> joined by "," + "}"
 *   - array : "[" + elements joined by "," + "]" (order preserved)
 *   - scalar: JSON form; integers print as integers (5, not 5.0)
 * Returns NULL only on allocation failure. */
char *adp_canonicalize(const cJSON *value);

/* sha256 of input bytes, lowercase hex (65-byte buffer incl. NUL). out must be
 * >= 65 bytes. Mirrors sha256Hex() in src/attestation.ts. */
void adp_sha256_hex(const unsigned char *input, size_t len, char out[65]);

/* ── Signature + identity binding (SPEC.md §5) ─────────────────────────────────
 * Verify the ed25519 signature over canonicalize(disclosure) AND enforce the
 * agentId == signature.publicKey binding (checked first, per the reference).
 * `signed_env` is a parsed { disclosure, signature } cJSON object.
 * On failure, *reason (if non-NULL) points to a static string. */
bool adp_verify_disclosure_signature(const cJSON *signed_env, const char **reason);

/* Freshness (SPEC.md §6): now >= issuedAt && now <= validUntil, ISO-8601 lexical.
 * `disclosure` is the inner disclosure object. */
bool adp_is_fresh(const cJSON *disclosure, const char *now);

/* ── Robust raw-input gate ─────────────────────────────────────────────────────
 * Parse `raw` (untrusted bytes) and run the verification pipeline, treating ANY
 * malformed / tampered / missing input as rejected. Returns 1 if the input is
 * REJECTED (the safe default), 0 only if it would be accepted (parses to a
 * well-formed envelope whose ed25519 signature verifies and whose agentId binds to
 * the signing public key). Guards every field access — a NULL/non-object/wrong-typed
 * member never gets dereferenced — and MUST NOT crash on any input, including
 * non-JSON, NULL, JSON null/arrays/numbers, or a missing signature/disclosure. */
int adp_verify_raw(const char *raw);

/* ── Emitter: ed25519 signing (SPEC.md §5) ─────────────────────────────────────
 * The seed is the trailing 32 bytes of the PKCS8 DER private key (after the
 * `302e020100300506032b657004220420` prefix). adp_seed_from_pkcs8_hex() extracts
 * it; adp_keypair_from_seed() expands it into a libsodium 64-byte secret key + the
 * 32-byte public key, mirroring agentKeyFromPrivateHex() in src/attestation.ts. */

/* Extract the 32-byte ed25519 seed from a PKCS8 DER private key (hex). Returns 0 on
 * success (seed[32] filled), -1 if the hex is malformed or lacks the ed25519 prefix. */
int adp_seed_from_pkcs8_hex(const char *pkcs8_hex, unsigned char seed[32]);

/* Expand a 32-byte seed into a keypair (sk = 64-byte libsodium secret key, pk =
 * 32-byte public key). Mirrors crypto_sign_seed_keypair. */
void adp_keypair_from_seed(const unsigned char seed[32],
                           unsigned char pk[32], unsigned char sk[64]);

/* Sign `msglen` bytes of `msg` with a libsodium secret key, writing the detached
 * 64-byte signature as lowercase hex into out_hex (129 bytes incl. NUL).
 * Mirrors signMessage() (sign over the raw UTF-8 bytes). */
void adp_sign_message(const unsigned char *msg, size_t msglen,
                      const unsigned char sk[64], char out_hex[129]);

/* Sign a disclosure object: canonicalize it, sign the canonical UTF-8 bytes, and
 * emit the signature hex into out_sig_hex[129]. Mirrors signDisclosure() — the
 * caller assembles the { disclosure, signature: { algorithm, publicKey, value } }
 * envelope (publicKey = the agent's raw pubkey hex). Returns 0 on success, -1 if
 * canonicalization fails. */
int adp_sign_disclosure(const cJSON *disclosure, const unsigned char sk[64],
                        char out_sig_hex[129]);

/* ── Redactable disclosure (src/redaction.ts) ──────────────────────────────────
 * Verify a redacted view: identity binding (meta.agentId == signature.publicKey),
 * the signature over canonicalize({meta, commitments}), and each revealed field
 * recomputing to its commitment (sha256Hex(canonicalize(value) + ":" + salt)).
 * On success *out_revealed (if non-NULL) receives a sorted, NUL-terminated array of
 * the proven field names; caller frees each entry + the array via adp_free_str_list.
 * On failure returns false, sets *reason (static string) and *out_revealed = NULL. */
bool adp_verify_redacted(const cJSON *view, char ***out_revealed,
                         size_t *out_count, const char **reason);

/* Free a NUL-terminated-count string list produced by adp_verify_redacted. */
void adp_free_str_list(char **list, size_t count);

/* ── Revocation (src/revocation.ts) ────────────────────────────────────────────
 * Verify a signed revocation record { id, reason, revokedAt, publicKey, signature }
 * — the signature covers canonicalize({id, reason, revokedAt}). */
bool adp_verify_revocation(const cJSON *record);

/* ── Transparency inclusion proof (src/transparencyTransport.ts) ───────────────
 * Recompute sha256Hex(canonicalize({index, disclosureDigest, agentId, issuedAt,
 * prevHash})) and confirm it equals entry.hash. */
bool adp_verify_inclusion_proof(const cJSON *entry);

/* ── Counterparty policy evaluation (SPEC.md §8) ───────────────────────────────
 * Evaluate a signed disclosure against a policy object (same shape as the TS
 * VerificationPolicy; only the fields the conformance fixtures exercise are
 * honored, plus the full check set). Produces a decision and the sorted set of
 * failed check names. */
typedef struct {
    /* "transact" or "refuse" */
    char decision[16];
    /* sorted, NUL-terminated failed check names; caller frees each + the array */
    char **failed;
    size_t failed_count;
    int checks_run;
} adp_verdict;

void adp_evaluate_disclosure(const cJSON *signed_env, const cJSON *policy, adp_verdict *out);
void adp_verdict_free(adp_verdict *v);

/* ── Handshake (SPEC.md §7) ────────────────────────────────────────────────────
 * Verify a challenge response against the challenge + expected agentId/clock.
 * Mirrors verifyChallengeResponse() in src/handshake.ts. maxAgeMs default 60000
 * when max_age_ms < 0. `now` may be NULL to skip the freshness check. */
bool adp_verify_challenge_response(const cJSON *response,
                                   const cJSON *challenge,
                                   const char *expected_agent_id,
                                   const char *now,
                                   long max_age_ms,
                                   const char **reason);

#ifdef __cplusplus
}
#endif

#endif /* ADP_AGENT_DISCLOSURE_H */
