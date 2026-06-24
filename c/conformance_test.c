/* ADP C conformance harness.
 *
 * Reads ../conformance/vectors.json and ../conformance/interop.json and exercises:
 *   - canonicalization vectors (byte-exact)
 *   - sha256 vectors
 *   - interop disclosure cases (decision + sorted failed-check set)
 *   - handshake cases (boolean accept/refuse)
 * Prints PASS/FAIL counts per section and exits nonzero on any failure. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "agent_disclosure.h"
#include "cJSON.h"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

static int total_pass = 0;
static int total_fail = 0;

/* ── canonicalization vectors ──────────────────────────────────────────────── */
static void run_canonicalization(const cJSON *root) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "canonicalization");
    int pass = 0, fail = 0;
    const cJSON *vec;
    cJSON_ArrayForEach(vec, arr) {
        const cJSON *input = cJSON_GetObjectItemCaseSensitive(vec, "input");
        const cJSON *expected = cJSON_GetObjectItemCaseSensitive(vec, "canonical");
        char *got = adp_canonicalize(input);
        if (got && cJSON_IsString(expected) && strcmp(got, expected->valuestring) == 0) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] canonicalize: expected %s got %s\n",
                   cJSON_IsString(expected) ? expected->valuestring : "(null)",
                   got ? got : "(null)");
        }
        free(got);
    }
    printf("canonicalization: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

/* ── differential fuzz corpus ───────────────────────────────────────────────────
 * Replays conformance/fuzz.json (top-level array) produced by the TS reference. Each
 * case carries the reference's canonical output; C MUST reproduce it byte-for-byte. */
static void run_fuzz(const cJSON *arr) {
    int pass = 0, fail = 0;
    const cJSON *vec;
    cJSON_ArrayForEach(vec, arr) {
        const cJSON *input = cJSON_GetObjectItemCaseSensitive(vec, "input");
        const cJSON *expected = cJSON_GetObjectItemCaseSensitive(vec, "canonical");
        char *got = adp_canonicalize(input);
        if (got && cJSON_IsString(expected) && strcmp(got, expected->valuestring) == 0) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] fuzz canonicalize: expected %s got %s\n",
                   cJSON_IsString(expected) ? expected->valuestring : "(null)",
                   got ? got : "(null)");
        }
        free(got);
    }
    printf("fuzz canonicalization: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

/* ── sha256 vectors ────────────────────────────────────────────────────────── */
static void run_sha256(const cJSON *root) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "sha256");
    int pass = 0, fail = 0;
    const cJSON *vec;
    cJSON_ArrayForEach(vec, arr) {
        const cJSON *input = cJSON_GetObjectItemCaseSensitive(vec, "input");
        const cJSON *expected = cJSON_GetObjectItemCaseSensitive(vec, "sha256");
        char out[65];
        const char *in = cJSON_IsString(input) ? input->valuestring : "";
        adp_sha256_hex((const unsigned char *)in, strlen(in), out);
        if (cJSON_IsString(expected) && strcmp(out, expected->valuestring) == 0) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] sha256(\"%s\"): expected %s got %s\n", in,
                   cJSON_IsString(expected) ? expected->valuestring : "(null)", out);
        }
    }
    printf("sha256: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

/* compare actual failed-set against expected array (both sorted) */
static int failset_matches(const adp_verdict *v, const cJSON *expected) {
    size_t en = (size_t)cJSON_GetArraySize(expected);
    if (en != v->failed_count) return 0;
    /* expected is the fixture's sorted set; our verdict is sorted too. Compare as
     * a set to be robust to fixture ordering. */
    for (size_t i = 0; i < v->failed_count; i++) {
        int found = 0;
        const cJSON *e;
        cJSON_ArrayForEach(e, expected) {
            if (cJSON_IsString(e) && strcmp(e->valuestring, v->failed[i]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    }
    return 1;
}

static void run_interop_disclosures(const cJSON *root) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "disclosures");
    int pass = 0, fail = 0;
    const cJSON *tc;
    cJSON_ArrayForEach(tc, arr) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(tc, "name");
        const cJSON *signed_env = cJSON_GetObjectItemCaseSensitive(tc, "signed");
        const cJSON *policy = cJSON_GetObjectItemCaseSensitive(tc, "policy");
        const cJSON *expect = cJSON_GetObjectItemCaseSensitive(tc, "expect");
        const cJSON *exp_decision = cJSON_GetObjectItemCaseSensitive(expect, "decision");
        const cJSON *exp_failed = cJSON_GetObjectItemCaseSensitive(expect, "failed");

        adp_verdict v;
        adp_evaluate_disclosure(signed_env, policy, &v);

        int dec_ok = cJSON_IsString(exp_decision) &&
                     strcmp(v.decision, exp_decision->valuestring) == 0;
        int failed_ok = cJSON_IsArray(exp_failed) ? failset_matches(&v, exp_failed) : 1;

        if (dec_ok && failed_ok) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] disclosure '%s': decision=%s (want %s) failed={",
                   cJSON_IsString(name) ? name->valuestring : "?", v.decision,
                   cJSON_IsString(exp_decision) ? exp_decision->valuestring : "?");
            for (size_t i = 0; i < v.failed_count; i++)
                printf("%s%s", i ? "," : "", v.failed[i]);
            printf("}\n");
        }
        adp_verdict_free(&v);
    }
    printf("interop disclosures: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

/* ── emitter byte-match ─────────────────────────────────────────────────────────
 * Re-sign each interop disclosure with the fixed seed (PKCS8 DER → 32-byte seed →
 * libsodium keypair) and compare the produced signature hex against the fixture's
 * signature.value. For a correctly-bound, non-tampered disclosure (the fixture's own
 * signature already verifies against its disclosure) the re-signed value MUST equal
 * the fixture; for tampered/forged cases it MUST differ. */
static void run_emitter(const cJSON *root) {
    int pass = 0, fail = 0;
    const cJSON *key = cJSON_GetObjectItemCaseSensitive(root, "key");
    const cJSON *priv = cJSON_GetObjectItemCaseSensitive(key, "privateKeyHex");
    const cJSON *pubHex = cJSON_GetObjectItemCaseSensitive(key, "publicKeyHex");
    if (!cJSON_IsString(priv) || !cJSON_IsString(pubHex)) {
        printf("  [FAIL] emitter: missing key.privateKeyHex/publicKeyHex\n");
        total_fail++;
        return;
    }

    unsigned char seed[32], pk[32], sk[64];
    if (adp_seed_from_pkcs8_hex(priv->valuestring, seed) != 0) {
        printf("  [FAIL] emitter: cannot extract seed from PKCS8 DER\n");
        total_fail++;
        return;
    }
    adp_keypair_from_seed(seed, pk, sk);

    /* the derived public key must equal the fixture's published agent pubkey */
    char pk_hex[65];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
    if (strcmp(pk_hex, pubHex->valuestring) != 0) {
        printf("  [FAIL] emitter: derived pubkey %s != fixture %s\n", pk_hex, pubHex->valuestring);
        fail++;
    } else {
        pass++;
    }

    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "disclosures");
    const cJSON *tc;
    cJSON_ArrayForEach(tc, arr) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(tc, "name");
        const cJSON *signed_env = cJSON_GetObjectItemCaseSensitive(tc, "signed");
        const cJSON *disclosure = cJSON_GetObjectItemCaseSensitive(signed_env, "disclosure");
        const cJSON *signature = cJSON_GetObjectItemCaseSensitive(signed_env, "signature");
        const cJSON *fix_value = cJSON_GetObjectItemCaseSensitive(signature, "value");
        if (!cJSON_IsObject(disclosure) || !cJSON_IsString(fix_value)) continue;

        /* A disclosure is a correctly-bound, faithfully-emitted fixture when the
         * fixture's own signature verifies against canonicalize(disclosure). Those
         * must byte-match the re-signed value; tampered/forged ones must not. */
        const char *vreason = NULL;
        bool fixture_verifies = adp_verify_disclosure_signature(signed_env, &vreason);

        char resigned[129];
        if (adp_sign_disclosure(disclosure, sk, resigned) != 0) {
            printf("  [FAIL] emitter '%s': re-sign failed\n",
                   cJSON_IsString(name) ? name->valuestring : "?");
            fail++;
            continue;
        }
        bool match = strcmp(resigned, fix_value->valuestring) == 0;
        bool expect_match = fixture_verifies;

        if (match == expect_match) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] emitter '%s': byte-match=%s expected=%s\n",
                   cJSON_IsString(name) ? name->valuestring : "?",
                   match ? "true" : "false", expect_match ? "true" : "false");
        }
    }
    printf("emitter byte-match: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

/* ── redactions ──────────────────────────────────────────────────────────────── */
static int strlist_matches(char **got, size_t got_n, const cJSON *expected) {
    size_t en = (size_t)cJSON_GetArraySize(expected);
    if (en != got_n) return 0;
    for (size_t i = 0; i < got_n; i++) {
        int found = 0;
        const cJSON *e;
        cJSON_ArrayForEach(e, expected) {
            if (cJSON_IsString(e) && strcmp(e->valuestring, got[i]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    }
    return 1;
}

static void run_redactions(const cJSON *root) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "redactions");
    int pass = 0, fail = 0;
    const cJSON *tc;
    cJSON_ArrayForEach(tc, arr) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(tc, "name");
        const cJSON *vieww = cJSON_GetObjectItemCaseSensitive(tc, "view");
        const cJSON *expect = cJSON_GetObjectItemCaseSensitive(tc, "expect");
        const cJSON *exp_ok = cJSON_GetObjectItemCaseSensitive(expect, "ok");
        const cJSON *exp_fields = cJSON_GetObjectItemCaseSensitive(expect, "revealedFields");

        char **revealed = NULL;
        size_t count = 0;
        const cJSON *reason = NULL;
        bool ok = adp_verify_redacted(vieww, &revealed, &count, (const char **)&reason);
        bool want = cJSON_IsTrue(exp_ok);
        int ok_match = (ok == want);
        int fields_match = cJSON_IsArray(exp_fields) ? strlist_matches(revealed, count, exp_fields) : 1;

        if (ok_match && fields_match) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] redaction '%s': ok=%s (want %s) revealed={",
                   cJSON_IsString(name) ? name->valuestring : "?",
                   ok ? "true" : "false", want ? "true" : "false");
            for (size_t i = 0; i < count; i++) printf("%s%s", i ? "," : "", revealed[i]);
            printf("}\n");
        }
        adp_free_str_list(revealed, count);
    }
    printf("redactions: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

/* ── revocations ─────────────────────────────────────────────────────────────── */
static void run_revocations(const cJSON *root) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "revocations");
    int pass = 0, fail = 0;
    const cJSON *tc;
    cJSON_ArrayForEach(tc, arr) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(tc, "name");
        const cJSON *record = cJSON_GetObjectItemCaseSensitive(tc, "record");
        const cJSON *expect = cJSON_GetObjectItemCaseSensitive(tc, "expect");
        bool ok = adp_verify_revocation(record);
        bool want = cJSON_IsTrue(expect);
        if (ok == want) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] revocation '%s': got %s want %s\n",
                   cJSON_IsString(name) ? name->valuestring : "?",
                   ok ? "true" : "false", want ? "true" : "false");
        }
    }
    printf("revocations: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

/* ── transparency inclusion proofs ───────────────────────────────────────────── */
static void run_transparency(const cJSON *root) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "transparency");
    int pass = 0, fail = 0;
    const cJSON *tc;
    cJSON_ArrayForEach(tc, arr) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(tc, "name");
        const cJSON *entry = cJSON_GetObjectItemCaseSensitive(tc, "entry");
        const cJSON *expect = cJSON_GetObjectItemCaseSensitive(tc, "expect");
        bool ok = adp_verify_inclusion_proof(entry);
        bool want = cJSON_IsTrue(expect);
        if (ok == want) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] transparency '%s': got %s want %s\n",
                   cJSON_IsString(name) ? name->valuestring : "?",
                   ok ? "true" : "false", want ? "true" : "false");
        }
    }
    printf("transparency: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

static void run_interop_handshakes(const cJSON *root) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "handshakes");
    int pass = 0, fail = 0;
    const cJSON *tc;
    cJSON_ArrayForEach(tc, arr) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(tc, "name");
        const cJSON *challenge = cJSON_GetObjectItemCaseSensitive(tc, "challenge");
        const cJSON *response = cJSON_GetObjectItemCaseSensitive(tc, "response");
        const cJSON *expAgent = cJSON_GetObjectItemCaseSensitive(tc, "expectedAgentId");
        const cJSON *now = cJSON_GetObjectItemCaseSensitive(tc, "now");
        const cJSON *expect = cJSON_GetObjectItemCaseSensitive(tc, "expect");

        const char *reason = NULL;
        bool ok = adp_verify_challenge_response(
            response, challenge,
            cJSON_IsString(expAgent) ? expAgent->valuestring : NULL,
            cJSON_IsString(now) ? now->valuestring : NULL,
            -1, &reason);
        bool want = cJSON_IsTrue(expect);
        if (ok == want) {
            pass++;
        } else {
            fail++;
            printf("  [FAIL] handshake '%s': got %s want %s (%s)\n",
                   cJSON_IsString(name) ? name->valuestring : "?",
                   ok ? "true" : "false", want ? "true" : "false",
                   reason ? reason : "ok");
        }
    }
    printf("interop handshakes: %d passed, %d failed\n", pass, fail);
    total_pass += pass;
    total_fail += fail;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 2;
    }

    char *vectors_raw = read_file("../conformance/vectors.json");
    char *interop_raw = read_file("../conformance/interop.json");
    char *fuzz_raw = read_file("../conformance/fuzz.json");
    if (!vectors_raw || !interop_raw || !fuzz_raw) {
        free(vectors_raw);
        free(interop_raw);
        free(fuzz_raw);
        return 2;
    }
    cJSON *vectors = cJSON_Parse(vectors_raw);
    cJSON *interop = cJSON_Parse(interop_raw);
    cJSON *fuzz = cJSON_Parse(fuzz_raw);
    if (!vectors || !interop || !fuzz) {
        fprintf(stderr, "failed to parse conformance JSON\n");
        return 2;
    }

    printf("=== ADP C conformance ===\n");
    run_canonicalization(vectors);
    run_fuzz(fuzz);
    run_sha256(vectors);
    run_interop_disclosures(interop);
    run_emitter(interop);
    run_redactions(interop);
    run_revocations(interop);
    run_transparency(interop);
    run_interop_handshakes(interop);

    printf("-------------------------\n");
    printf("TOTAL: %d passed, %d failed\n", total_pass, total_fail);

    cJSON_Delete(vectors);
    cJSON_Delete(interop);
    cJSON_Delete(fuzz);
    free(vectors_raw);
    free(interop_raw);
    free(fuzz_raw);
    return total_fail == 0 ? 0 : 1;
}
