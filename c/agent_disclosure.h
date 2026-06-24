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
