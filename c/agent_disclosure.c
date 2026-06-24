/* Agent Disclosure Protocol (ADP) - native C verifier implementation.
 * See agent_disclosure.h and SPEC.md for the normative algorithm. */

#include "agent_disclosure.h"

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

/* ── small dynamic string builder ──────────────────────────────────────────── */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    int oom;
} sb;

static void sb_init(sb *s) {
    s->cap = 64;
    s->len = 0;
    s->oom = 0;
    s->buf = (char *)malloc(s->cap);
    if (!s->buf) s->oom = 1;
    else s->buf[0] = '\0';
}

static void sb_ensure(sb *s, size_t extra) {
    if (s->oom) return;
    if (s->len + extra + 1 <= s->cap) return;
    size_t ncap = s->cap;
    while (s->len + extra + 1 > ncap) ncap *= 2;
    char *nb = (char *)realloc(s->buf, ncap);
    if (!nb) {
        s->oom = 1;
        return;
    }
    s->buf = nb;
    s->cap = ncap;
}

static void sb_putc(sb *s, char c) {
    sb_ensure(s, 1);
    if (s->oom) return;
    s->buf[s->len++] = c;
    s->buf[s->len] = '\0';
}

static void sb_puts(sb *s, const char *str) {
    size_t n = strlen(str);
    sb_ensure(s, n);
    if (s->oom) return;
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

/* ── JSON string escaping, byte-matching JSON.stringify ────────────────────────
 * Escapes the JSON-required set: '"' '\\' and the control chars < 0x20, using the
 * short forms \b \t \n \f \r and \u00XX otherwise. Does NOT escape '/'. Non-control
 * bytes (including UTF-8 multibyte sequences) are emitted verbatim, exactly as V8's
 * JSON.stringify does. The TS reference signs over UTF-8 bytes, so emitting the raw
 * bytes is correct. */
static void sb_put_json_string(sb *s, const char *str) {
    static const char *hex = "0123456789abcdef";
    sb_putc(s, '"');
    for (const unsigned char *p = (const unsigned char *)str; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"':  sb_puts(s, "\\\""); break;
            case '\\': sb_puts(s, "\\\\"); break;
            case '\b': sb_puts(s, "\\b"); break;
            case '\t': sb_puts(s, "\\t"); break;
            case '\n': sb_puts(s, "\\n"); break;
            case '\f': sb_puts(s, "\\f"); break;
            case '\r': sb_puts(s, "\\r"); break;
            default:
                if (c < 0x20) {
                    sb_puts(s, "\\u00");
                    sb_putc(s, hex[(c >> 4) & 0xF]);
                    sb_putc(s, hex[c & 0xF]);
                } else {
                    sb_putc(s, (char)c);
                }
        }
    }
    sb_putc(s, '"');
}

/* ── number formatting, matching JSON.stringify for the integer-only schema ────
 * The schema restricts numeric fields to integers; JS prints an integral double as
 * an integer (5, not 5.0). cJSON stores numbers as double, so we detect an integral
 * value within the safe-integer range and print it as a 64-bit integer. A genuine
 * non-integer falls back to a %.17g-style shortest round-trip (not exercised by the
 * conformance fixtures, which are integer-only). */
static void sb_put_number(sb *s, double d) {
    if (isnan(d) || isinf(d)) {
        /* JSON.stringify emits null for non-finite numbers. */
        sb_puts(s, "null");
        return;
    }
    /* Integral and within a range that prints without exponent in JS. */
    if (d == floor(d) && fabs(d) < 1e15) {
        char tmp[32];
        long long v = (long long)d;
        snprintf(tmp, sizeof(tmp), "%lld", v);
        sb_puts(s, tmp);
        return;
    }
    /* Non-integer fallback: shortest representation that round-trips. */
    char tmp[40];
    for (int prec = 1; prec <= 17; prec++) {
        snprintf(tmp, sizeof(tmp), "%.*g", prec, d);
        if (strtod(tmp, NULL) == d) break;
    }
    sb_puts(s, tmp);
}

/* ── key sorting ───────────────────────────────────────────────────────────────
 * Sort object member keys lexicographically by byte order (strcmp). All ADP schema
 * keys are ASCII, for which UTF-8 byte order equals JS's UTF-16 code-unit order. */
static int key_cmp(const void *a, const void *b) {
    const cJSON *ca = *(const cJSON *const *)a;
    const cJSON *cb = *(const cJSON *const *)b;
    const char *ka = ca->string ? ca->string : "";
    const char *kb = cb->string ? cb->string : "";
    return strcmp(ka, kb);
}

static void canon_into(const cJSON *v, sb *s);

static void canon_object(const cJSON *v, sb *s) {
    /* collect members (cJSON drops nothing; "undefined" never appears in parsed
     * JSON, so there is nothing to filter for parsed inputs). */
    size_t n = 0;
    for (const cJSON *m = v->child; m; m = m->next) n++;
    sb_putc(s, '{');
    if (n == 0) {
        sb_putc(s, '}');
        return;
    }
    const cJSON **members = (const cJSON **)malloc(n * sizeof(*members));
    if (!members) {
        s->oom = 1;
        return;
    }
    size_t i = 0;
    for (const cJSON *m = v->child; m; m = m->next) members[i++] = m;
    qsort(members, n, sizeof(*members), key_cmp);
    for (i = 0; i < n; i++) {
        if (i) sb_putc(s, ',');
        sb_put_json_string(s, members[i]->string ? members[i]->string : "");
        sb_putc(s, ':');
        canon_into(members[i], s);
    }
    free(members);
    sb_putc(s, '}');
}

static void canon_array(const cJSON *v, sb *s) {
    sb_putc(s, '[');
    int first = 1;
    for (const cJSON *e = v->child; e; e = e->next) {
        if (!first) sb_putc(s, ',');
        first = 0;
        canon_into(e, s);
    }
    sb_putc(s, ']');
}

static void canon_into(const cJSON *v, sb *s) {
    if (v == NULL || cJSON_IsNull(v)) {
        sb_puts(s, "null");
        return;
    }
    if (cJSON_IsBool(v)) {
        sb_puts(s, cJSON_IsTrue(v) ? "true" : "false");
        return;
    }
    if (cJSON_IsString(v)) {
        sb_put_json_string(s, v->valuestring ? v->valuestring : "");
        return;
    }
    if (cJSON_IsNumber(v)) {
        sb_put_number(s, v->valuedouble);
        return;
    }
    if (cJSON_IsArray(v)) {
        canon_array(v, s);
        return;
    }
    if (cJSON_IsObject(v)) {
        canon_object(v, s);
        return;
    }
    if (cJSON_IsRaw(v)) {
        sb_puts(s, v->valuestring ? v->valuestring : "null");
        return;
    }
    /* cJSON_Invalid or anything unexpected → null (matches JS for undefined). */
    sb_puts(s, "null");
}

char *adp_canonicalize(const cJSON *value) {
    sb s;
    sb_init(&s);
    canon_into(value, &s);
    if (s.oom) {
        free(s.buf);
        return NULL;
    }
    return s.buf;
}

/* ── sha256 hex ────────────────────────────────────────────────────────────── */
void adp_sha256_hex(const unsigned char *input, size_t len, char out[65]) {
    unsigned char digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(digest, input, len);
    sodium_bin2hex(out, 65, digest, sizeof(digest));
}

/* ── hex helpers ───────────────────────────────────────────────────────────── */
static int hex_decode(const char *hex, unsigned char *out, size_t out_max, size_t *out_len) {
    size_t bin_len = 0;
    if (sodium_hex2bin(out, out_max, hex, strlen(hex), NULL, &bin_len, NULL) != 0)
        return -1;
    if (out_len) *out_len = bin_len;
    return 0;
}

/* ── signature + identity binding (SPEC.md §5) ─────────────────────────────── */
bool adp_verify_disclosure_signature(const cJSON *signed_env, const char **reason) {
    const cJSON *disclosure = cJSON_GetObjectItemCaseSensitive(signed_env, "disclosure");
    const cJSON *signature = cJSON_GetObjectItemCaseSensitive(signed_env, "signature");
    if (!cJSON_IsObject(disclosure) || !cJSON_IsObject(signature)) {
        if (reason) *reason = "malformed envelope";
        return false;
    }
    const cJSON *agentId = cJSON_GetObjectItemCaseSensitive(disclosure, "agentId");
    const cJSON *publicKey = cJSON_GetObjectItemCaseSensitive(signature, "publicKey");
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(signature, "value");
    if (!cJSON_IsString(agentId) || !cJSON_IsString(publicKey) || !cJSON_IsString(value)) {
        if (reason) *reason = "malformed envelope";
        return false;
    }

    /* Identity binding is checked FIRST, before the signature value (per the TS
     * reference: verifyDisclosureSignature returns the binding failure when
     * agentId !== publicKey). */
    if (strcmp(agentId->valuestring, publicKey->valuestring) != 0) {
        if (reason) *reason = "agentId does not match the signing public key";
        return false;
    }

    char *canon = adp_canonicalize(disclosure);
    if (!canon) {
        if (reason) *reason = "out of memory";
        return false;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sig[crypto_sign_BYTES];
    size_t pk_len = 0, sig_len = 0;
    int ok = 0;
    if (hex_decode(publicKey->valuestring, pk, sizeof(pk), &pk_len) == 0 &&
        pk_len == crypto_sign_PUBLICKEYBYTES &&
        hex_decode(value->valuestring, sig, sizeof(sig), &sig_len) == 0 &&
        sig_len == crypto_sign_BYTES) {
        ok = (crypto_sign_verify_detached(sig, (const unsigned char *)canon,
                                          strlen(canon), pk) == 0);
    }
    free(canon);
    if (!ok) {
        if (reason) *reason = "signature mismatch";
        return false;
    }
    if (reason) *reason = NULL;
    return true;
}

/* ── freshness (SPEC.md §6): ISO-8601 lexical comparison ───────────────────── */
bool adp_is_fresh(const cJSON *disclosure, const char *now) {
    const cJSON *issuedAt = cJSON_GetObjectItemCaseSensitive(disclosure, "issuedAt");
    const cJSON *validUntil = cJSON_GetObjectItemCaseSensitive(disclosure, "validUntil");
    if (!cJSON_IsString(issuedAt) || !cJSON_IsString(validUntil) || !now)
        return false;
    return strcmp(now, issuedAt->valuestring) >= 0 &&
           strcmp(now, validUntil->valuestring) <= 0;
}

/* ── verify a UTF-8 message signature against a hex public key ──────────────── */
static bool verify_message(const char *message, const char *public_key_hex, const char *signature_hex) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sig[crypto_sign_BYTES];
    size_t pk_len = 0, sig_len = 0;
    if (hex_decode(public_key_hex, pk, sizeof(pk), &pk_len) != 0 || pk_len != sizeof(pk))
        return false;
    if (hex_decode(signature_hex, sig, sizeof(sig), &sig_len) != 0 || sig_len != sizeof(sig))
        return false;
    return crypto_sign_verify_detached(sig, (const unsigned char *)message,
                                       strlen(message), pk) == 0;
}

/* ── ISO-8601 (UTC) → epoch milliseconds, matching Date.parse for the fixtures ─
 * Parses YYYY-MM-DDTHH:MM:SS[.fff]Z. The conformance timestamps are all UTC `Z`. */
static int days_from_civil(int y, int m, int d) {
    /* Howard Hinnant's algorithm: days since 1970-01-01. */
    y -= (m <= 2);
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int)doe - 719468;
}

static int parse_iso_ms(const char *s, int64_t *out_ms) {
    int y, mo, d, h, mi, se;
    int ms = 0;
    int n = 0;
    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &se, &n) != 6)
        return -1;
    const char *p = s + n;
    if (*p == '.') {
        /* fractional seconds → milliseconds (read up to 3 digits) */
        p++;
        int digits = 0;
        int frac = 0;
        while (*p >= '0' && *p <= '9') {
            if (digits < 3) frac = frac * 10 + (*p - '0');
            digits++;
            p++;
        }
        while (digits < 3) {
            frac *= 10;
            digits++;
        }
        ms = frac;
    }
    int64_t days = days_from_civil(y, mo, d);
    int64_t secs = days * 86400 + (int64_t)h * 3600 + (int64_t)mi * 60 + se;
    *out_ms = secs * 1000 + ms;
    return 0;
}

/* ── handshake (SPEC.md §7) ────────────────────────────────────────────────── */
bool adp_verify_challenge_response(const cJSON *response,
                                   const cJSON *challenge,
                                   const char *expected_agent_id,
                                   const char *now,
                                   long max_age_ms,
                                   const char **reason) {
    const cJSON *r_nonce = cJSON_GetObjectItemCaseSensitive(response, "nonce");
    const cJSON *r_agent = cJSON_GetObjectItemCaseSensitive(response, "agentId");
    const cJSON *r_head = cJSON_GetObjectItemCaseSensitive(response, "auditHead");
    const cJSON *r_signedAt = cJSON_GetObjectItemCaseSensitive(response, "signedAt");
    const cJSON *r_sig = cJSON_GetObjectItemCaseSensitive(response, "signature");
    const cJSON *c_nonce = cJSON_GetObjectItemCaseSensitive(challenge, "nonce");
    const cJSON *c_verifier = cJSON_GetObjectItemCaseSensitive(challenge, "verifierId");

    if (!cJSON_IsString(r_nonce) || !cJSON_IsString(r_agent) || !cJSON_IsString(r_head) ||
        !cJSON_IsString(r_signedAt) || !cJSON_IsString(r_sig) || !cJSON_IsString(c_nonce)) {
        if (reason) *reason = "malformed handshake";
        return false;
    }

    /* 1. nonce match */
    if (strcmp(r_nonce->valuestring, c_nonce->valuestring) != 0) {
        if (reason) *reason = "nonce mismatch (replayed or wrong challenge)";
        return false;
    }
    /* 2. agentId match */
    if (!expected_agent_id || strcmp(r_agent->valuestring, expected_agent_id) != 0) {
        if (reason) *reason = "response agentId does not match the disclosure";
        return false;
    }
    /* 3. signature over canonicalize({nonce, agentId, auditHead, signedAt, verifierId})
     *    verifierId comes from the CHALLENGE; absent → dropped by canonicalization. */
    cJSON *body = cJSON_CreateObject();
    if (!body) {
        if (reason) *reason = "out of memory";
        return false;
    }
    cJSON_AddStringToObject(body, "nonce", r_nonce->valuestring);
    cJSON_AddStringToObject(body, "agentId", r_agent->valuestring);
    cJSON_AddStringToObject(body, "auditHead", r_head->valuestring);
    cJSON_AddStringToObject(body, "signedAt", r_signedAt->valuestring);
    if (cJSON_IsString(c_verifier))
        cJSON_AddStringToObject(body, "verifierId", c_verifier->valuestring);
    /* A verifierId set to JSON null would be emitted as null (not dropped); the
     * reference only drops an absent/undefined verifierId, which we model by simply
     * not adding the key. */
    char *msg = adp_canonicalize(body);
    cJSON_Delete(body);
    if (!msg) {
        if (reason) *reason = "out of memory";
        return false;
    }
    bool sig_ok = verify_message(msg, r_agent->valuestring, r_sig->valuestring);
    free(msg);
    if (!sig_ok) {
        if (reason) *reason = "challenge signature invalid (no live key possession)";
        return false;
    }
    /* 4. freshness */
    if (now) {
        int64_t now_ms = 0, signed_ms = 0;
        if (parse_iso_ms(now, &now_ms) != 0 || parse_iso_ms(r_signedAt->valuestring, &signed_ms) != 0) {
            if (reason) *reason = "challenge response is stale";
            return false;
        }
        int64_t age = now_ms - signed_ms;
        long max_age = (max_age_ms < 0) ? 60000L : max_age_ms;
        if (age < 0 || age > max_age) {
            if (reason) *reason = "challenge response is stale";
            return false;
        }
    }
    /* 5. audit-head currency: the reference treats this as a non-fatal signal. */
    if (reason) *reason = NULL;
    return true;
}

/* ── policy evaluation (SPEC.md §8) ────────────────────────────────────────── */
static const char *GRADES[] = {"F", "D", "C", "B", "A"}; /* rank = index */
static int grade_rank(const char *g) {
    for (int i = 0; i < 5; i++)
        if (g && strcmp(g, GRADES[i]) == 0) return i;
    return -1;
}
static int attestation_rank(const char *l) {
    if (!l) return -1;
    if (strcmp(l, "none") == 0) return 0;
    if (strcmp(l, "signed") == 0) return 1;
    if (strcmp(l, "registry_attested") == 0) return 2;
    return -1;
}

typedef struct {
    char **names;
    size_t count;
    size_t cap;
    int checks_run;
} failset;

/* strdup is POSIX, not C11. Under -std=c11 on glibc it is undeclared, so the compiler
 * assumes it returns int and truncates the 64-bit pointer (a segfault waiting to
 * happen). A self-contained dup keeps the build portable across glibc / MinGW / macOS. */
static char *adp_strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}
static void fs_init(failset *f) {
    f->cap = 8;
    f->count = 0;
    f->checks_run = 0;
    f->names = (char **)malloc(f->cap * sizeof(char *));
}
static void fs_add(failset *f, const char *name) {
    if (f->count == f->cap) {
        f->cap *= 2;
        f->names = (char **)realloc(f->names, f->cap * sizeof(char *));
    }
    f->names[f->count++] = adp_strdup(name);
}
static int str_cmp_qsort(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static bool policy_true(const cJSON *policy, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(policy, key);
    return cJSON_IsBool(v) && cJSON_IsTrue(v);
}

void adp_evaluate_disclosure(const cJSON *signed_env, const cJSON *policy, adp_verdict *out) {
    failset fs;
    fs_init(&fs);
    const cJSON *d = cJSON_GetObjectItemCaseSensitive(signed_env, "disclosure");

    /* signature (default on unless requireValidSignature === false) */
    const cJSON *reqSig = cJSON_GetObjectItemCaseSensitive(policy, "requireValidSignature");
    if (!(cJSON_IsBool(reqSig) && cJSON_IsFalse(reqSig))) {
        fs.checks_run++;
        const char *why = NULL;
        if (!adp_verify_disclosure_signature(signed_env, &why))
            fs_add(&fs, "signature");
    }

    /* freshness (default on unless requireFresh === false) */
    const cJSON *reqFresh = cJSON_GetObjectItemCaseSensitive(policy, "requireFresh");
    if (!(cJSON_IsBool(reqFresh) && cJSON_IsFalse(reqFresh))) {
        fs.checks_run++;
        const cJSON *now = cJSON_GetObjectItemCaseSensitive(policy, "now");
        if (!(cJSON_IsString(now) && adp_is_fresh(d, now->valuestring)))
            fs_add(&fs, "freshness");
    }

    /* requireEnforcedConstitution */
    if (policy_true(policy, "requireEnforcedConstitution")) {
        fs.checks_run++;
        const cJSON *con = cJSON_GetObjectItemCaseSensitive(d, "constitution");
        const cJSON *enf = cJSON_GetObjectItemCaseSensitive(con, "enforced");
        if (!(cJSON_IsBool(enf) && cJSON_IsTrue(enf)))
            fs_add(&fs, "enforcedConstitution");
    }

    /* requiredHardConstraints: every listed id must be present */
    const cJSON *rhc = cJSON_GetObjectItemCaseSensitive(policy, "requiredHardConstraints");
    if (cJSON_IsArray(rhc) && cJSON_GetArraySize(rhc) > 0) {
        fs.checks_run++;
        const cJSON *con = cJSON_GetObjectItemCaseSensitive(d, "constitution");
        const cJSON *hcs = cJSON_GetObjectItemCaseSensitive(con, "hardConstraints");
        int missing = 0;
        const cJSON *need;
        cJSON_ArrayForEach(need, rhc) {
            if (!cJSON_IsString(need)) continue;
            int found = 0;
            const cJSON *have;
            cJSON_ArrayForEach(have, hcs) {
                const cJSON *id = cJSON_GetObjectItemCaseSensitive(have, "id");
                if (cJSON_IsString(id) && strcmp(id->valuestring, need->valuestring) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) missing = 1;
        }
        if (missing) fs_add(&fs, "requiredHardConstraints");
    }

    /* red-team: presence, grade, hard-fails */
    const cJSON *redTeam = cJSON_GetObjectItemCaseSensitive(d, "redTeam");
    int requireRedTeam = policy_true(policy, "requireRedTeam");
    if (requireRedTeam && !cJSON_IsObject(redTeam)) {
        fs.checks_run++;
        fs_add(&fs, "redTeamPresent");
    } else if (cJSON_IsObject(redTeam)) {
        const cJSON *result = cJSON_GetObjectItemCaseSensitive(redTeam, "result");
        const cJSON *minGrade = cJSON_GetObjectItemCaseSensitive(policy, "minRedTeamGrade");
        if (cJSON_IsString(minGrade)) {
            fs.checks_run++;
            const cJSON *grade = cJSON_GetObjectItemCaseSensitive(result, "grade");
            int gr = cJSON_IsString(grade) ? grade_rank(grade->valuestring) : -1;
            int mr = grade_rank(minGrade->valuestring);
            if (!(gr >= 0 && mr >= 0 && gr >= mr))
                fs_add(&fs, "redTeamGrade");
        }
        const cJSON *maxFailsV = cJSON_GetObjectItemCaseSensitive(policy, "maxRedTeamHardFails");
        int maxFails = cJSON_IsNumber(maxFailsV) ? (int)maxFailsV->valuedouble : 0;
        const cJSON *hardFails = cJSON_GetObjectItemCaseSensitive(result, "hardFails");
        int nFails = cJSON_IsArray(hardFails) ? cJSON_GetArraySize(hardFails) : 0;
        fs.checks_run++;
        if (!(nFails <= maxFails))
            fs_add(&fs, "redTeamHardFails");
    }

    /* requireNonCustodial */
    if (policy_true(policy, "requireNonCustodial")) {
        fs.checks_run++;
        const cJSON *cap = cJSON_GetObjectItemCaseSensitive(d, "capital");
        const cJSON *cust = cJSON_GetObjectItemCaseSensitive(cap, "custody");
        if (!(cJSON_IsString(cust) && strcmp(cust->valuestring, "non_custodial") == 0))
            fs_add(&fs, "nonCustodial");
    }

    /* minAttestationLevel */
    const cJSON *minAtt = cJSON_GetObjectItemCaseSensitive(policy, "minAttestationLevel");
    if (cJSON_IsString(minAtt)) {
        fs.checks_run++;
        const cJSON *op = cJSON_GetObjectItemCaseSensitive(d, "operator");
        const cJSON *att = cJSON_GetObjectItemCaseSensitive(op, "attestation");
        const cJSON *lvl = cJSON_GetObjectItemCaseSensitive(att, "level");
        int have = cJSON_IsString(lvl) ? attestation_rank(lvl->valuestring) : -1;
        int need = attestation_rank(minAtt->valuestring);
        if (!(have >= 0 && need >= 0 && have >= need))
            fs_add(&fs, "attestationLevel");
    }

    /* requireDeploymentHistory: totalDecisions > 0 */
    if (policy_true(policy, "requireDeploymentHistory")) {
        fs.checks_run++;
        const cJSON *hist = cJSON_GetObjectItemCaseSensitive(d, "history");
        const cJSON *sum = cJSON_GetObjectItemCaseSensitive(hist, "summary");
        const cJSON *total = cJSON_GetObjectItemCaseSensitive(sum, "totalDecisions");
        if (!(cJSON_IsNumber(total) && total->valuedouble > 0))
            fs_add(&fs, "deploymentHistory");
    }

    /* requireAuditAnchor */
    if (policy_true(policy, "requireAuditAnchor")) {
        fs.checks_run++;
        const cJSON *anchor = cJSON_GetObjectItemCaseSensitive(d, "auditAnchor");
        if (!cJSON_IsString(anchor))
            fs_add(&fs, "auditAnchor");
    }

    /* requireModelFingerprint */
    if (policy_true(policy, "requireModelFingerprint")) {
        fs.checks_run++;
        const cJSON *model = cJSON_GetObjectItemCaseSensitive(d, "model");
        if (!cJSON_IsObject(model))
            fs_add(&fs, "modelFingerprint");
    }

    /* allowedModelDigests */
    const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(policy, "allowedModelDigests");
    if (cJSON_IsArray(allowed) && cJSON_GetArraySize(allowed) > 0) {
        fs.checks_run++;
        const cJSON *model = cJSON_GetObjectItemCaseSensitive(d, "model");
        const cJSON *digest = model ? cJSON_GetObjectItemCaseSensitive(model, "digest") : NULL;
        int ok = 0;
        if (cJSON_IsString(digest)) {
            const cJSON *cand;
            cJSON_ArrayForEach(cand, allowed) {
                if (cJSON_IsString(cand) && strcmp(cand->valuestring, digest->valuestring) == 0) {
                    ok = 1;
                    break;
                }
            }
        }
        if (!ok) fs_add(&fs, "modelDigest");
    }

    /* requireProvenanceFor */
    const cJSON *reqProv = cJSON_GetObjectItemCaseSensitive(policy, "requireProvenanceFor");
    if (cJSON_IsArray(reqProv) && cJSON_GetArraySize(reqProv) > 0) {
        fs.checks_run++;
        const cJSON *prov = cJSON_GetObjectItemCaseSensitive(d, "provenance");
        int missing = 0;
        const cJSON *field;
        cJSON_ArrayForEach(field, reqProv) {
            if (!cJSON_IsString(field)) continue;
            const cJSON *entry = cJSON_IsObject(prov)
                ? cJSON_GetObjectItemCaseSensitive(prov, field->valuestring) : NULL;
            if (!entry) missing = 1;
        }
        if (missing) fs_add(&fs, "provenance");
    }

    /* sort failed names (the fixtures compare a sorted set) */
    if (fs.count > 1)
        qsort(fs.names, fs.count, sizeof(char *), str_cmp_qsort);

    out->failed = fs.names;
    out->failed_count = fs.count;
    out->checks_run = fs.checks_run;
    snprintf(out->decision, sizeof(out->decision), "%s",
             fs.count == 0 ? "transact" : "refuse");
}

void adp_verdict_free(adp_verdict *v) {
    if (!v) return;
    for (size_t i = 0; i < v->failed_count; i++) free(v->failed[i]);
    free(v->failed);
    v->failed = NULL;
    v->failed_count = 0;
}
