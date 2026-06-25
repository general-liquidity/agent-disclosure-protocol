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

/* ── key sorting (RFC 8785 / JCS: UTF-16 code-unit order) ───────────────────────
 * JCS sorts object member keys by their UTF-16 code units, NOT by UTF-8 byte order
 * and NOT by Unicode code point. The three orders agree on the Basic Multilingual
 * Plane (where one code point is one code unit and UTF-8 byte order preserves code-
 * point order), but DIVERGE for supplementary characters (U+10000+): UTF-8 encodes
 * them with a lead byte >= 0xF0 (sorting them AFTER any 3-byte BMP char), while UTF-16
 * encodes them as a surrogate pair whose lead unit is 0xD800..0xDBFF (sorting them
 * BEFORE BMP chars >= 0xE000). The conformance vector { "😀": 1, "דּ": 2 } is exactly
 * this case: 😀 (U+1F600 → surrogate lead 0xD83D) must sort BEFORE דּ (U+FB33). A
 * byte-order strcmp would reverse them and break cross-stack signatures.
 *
 * next_code_unit() walks a UTF-8 string and yields the next UTF-16 code unit (advancing
 * over a 1–4 byte sequence; a supplementary code point yields its lead surrogate first,
 * then its trail surrogate on the following call). Returns 0 at end of string. Malformed
 * bytes are passed through as their raw value so the comparison stays total and never
 * reads out of bounds. */
static unsigned int next_code_unit(const unsigned char **pp, int *pending_trail) {
    if (*pending_trail >= 0) {
        unsigned int t = (unsigned int)*pending_trail;
        *pending_trail = -1;
        return t;
    }
    const unsigned char *p = *pp;
    unsigned char c = *p;
    if (c == 0) return 0;
    unsigned int cp;
    if (c < 0x80) {
        cp = c;
        p += 1;
    } else if ((c & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
        cp = ((unsigned int)(c & 0x1F) << 6) | (p[1] & 0x3F);
        p += 2;
    } else if ((c & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
        cp = ((unsigned int)(c & 0x0F) << 12) | ((unsigned int)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
        p += 3;
    } else if ((c & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 &&
               (p[3] & 0xC0) == 0x80) {
        cp = ((unsigned int)(c & 0x07) << 18) | ((unsigned int)(p[1] & 0x3F) << 12) |
             ((unsigned int)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
        p += 4;
    } else {
        /* malformed lead byte: pass it through so the scan still terminates. */
        *pp = p + 1;
        return c;
    }
    *pp = p;
    if (cp >= 0x10000) {
        /* supplementary: emit lead surrogate now, stash trail for the next call. */
        cp -= 0x10000;
        *pending_trail = (int)(0xDC00 + (cp & 0x3FF));
        return 0xD800 + (cp >> 10);
    }
    return cp;
}

/* Compare two UTF-8 keys by UTF-16 code-unit sequence (lexicographic). */
static int utf16_key_cmp(const char *a, const char *b) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    int ta = -1, tb = -1;
    for (;;) {
        unsigned int ua = next_code_unit(&pa, &ta);
        unsigned int ub = next_code_unit(&pb, &tb);
        if (ua != ub) return ua < ub ? -1 : 1;
        if (ua == 0) return 0; /* both ended together */
    }
}

static int key_cmp(const void *a, const void *b) {
    const cJSON *ca = *(const cJSON *const *)a;
    const cJSON *cb = *(const cJSON *const *)b;
    const char *ka = ca->string ? ca->string : "";
    const char *kb = cb->string ? cb->string : "";
    return utf16_key_cmp(ka, kb);
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

/* ── unpadded URL-safe base64 decode (RFC 4648 §5, no padding) ──────────────────
 * JOSE base64url: alphabet A–Z a–z 0–9 '-' '_', no '=' padding. Decodes `in` (length
 * `inlen`) into a freshly malloc'd buffer; *outlen receives the byte count. Returns the
 * buffer (caller frees) or NULL on a malformed character / illegal length / OOM. An
 * input length of 1 mod 4 is invalid (cannot encode any whole byte). */
static unsigned char *b64url_decode(const char *in, size_t inlen, size_t *outlen) {
    static signed char T[256];
    static int inited = 0;
    if (!inited) {
        for (int i = 0; i < 256; i++) T[i] = -1;
        for (int i = 'A'; i <= 'Z'; i++) T[i] = (signed char)(i - 'A');
        for (int i = 'a'; i <= 'z'; i++) T[i] = (signed char)(i - 'a' + 26);
        for (int i = '0'; i <= '9'; i++) T[i] = (signed char)(i - '0' + 52);
        T[(unsigned char)'-'] = 62;
        T[(unsigned char)'_'] = 63;
        inited = 1;
    }
    if (inlen % 4 == 1) return NULL;
    size_t cap = inlen / 4 * 3 + 3;
    unsigned char *out = (unsigned char *)malloc(cap ? cap : 1);
    if (!out) return NULL;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        signed char v = T[(unsigned char)in[i]];
        if (v < 0) {
            free(out);
            return NULL;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    *outlen = o;
    return out;
}

/* ── Disclosure enum grammar (mirror of schema/constraints.json) ───────────────
 * Single source of truth lives in schema/constraints.json (generated from
 * src/schema.ts). These NULL-terminated arrays are the C mirror; conformance_test.c
 * asserts they equal the manifest, so a source-side change not mirrored here fails CI.
 * They are the value sets consumed directly by adp_disclosure_schema_valid /
 * adp_evaluate_disclosure below — no inline literal duplicates the grammar. */
const char *const ADP_CUSTODY[] = {"non_custodial", "custodial", NULL};
const char *const ADP_ATTESTATION_LEVEL[] = {"none", "signed", "registry_attested", NULL};
const char *const ADP_ATTESTATION_SCHEME_KNOWN[] = {"AIP", "VisaTAP", "ERC8004", "DID", "none", NULL};
const char *const ADP_CONSTRAINT_KIND[] = {"deny", "cap", "velocity", "rationale", "scope", "other", NULL};
const char *const ADP_TOOL_ACCESS[] = {"gated", "read_only", "operator_only", NULL};
const char *const ADP_MANDATE_PERIOD[] = {"day", "week", "month", NULL};
const char *const ADP_RED_TEAM_GRADE[] = {"A", "B", "C", "D", "F", NULL};

bool adp_in_set(const char *const *set, const char *value) {
    if (!value) return false;
    for (const char *const *p = set; *p; p++)
        if (strcmp(*p, value) == 0) return true;
    return false;
}

/* Reverse-domain id check: ^[a-z0-9]+(\.[a-z0-9-]+)+$ — at least one dot, each label
 * lowercase-alnum (hyphen allowed only in non-leading labels), matching ReverseDomain in
 * src/schema.ts (ADP_REVERSE_DOMAIN_PATTERN). So "Unknown" (no dot, uppercase) fails;
 * "com.visa.tap" passes. */
static bool is_reverse_domain(const char *s) {
    if (!s || !*s) return false;
    size_t label_len = 0;
    int dots = 0;
    int first_label = 1;
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (c == '.') {
            if (label_len == 0) return false; /* empty label (leading/double dot) */
            dots++;
            label_len = 0;
            first_label = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            label_len++;
        } else if (c == '-') {
            /* hyphen permitted only in a non-first label (regex: first group has no '-') */
            if (first_label) return false;
            label_len++;
        } else {
            return false;
        }
    }
    if (label_len == 0) return false; /* trailing dot */
    return dots >= 1;
}

/* ── schema validation (SPEC.md §3) ─────────────────────────────────────────── */
bool adp_disclosure_schema_valid(const cJSON *disclosure) {
    if (!cJSON_IsObject(disclosure)) return false;

    /* version: z.literal(1) — must be the number 1 (string "1" or 9999 are rejected). */
    const cJSON *version = cJSON_GetObjectItemCaseSensitive(disclosure, "version");
    if (!cJSON_IsNumber(version) || version->valuedouble != 1.0) return false;

    /* systemPrompt.algorithm: z.literal("sha256") (manifest digestAlgorithm). */
    const cJSON *sp = cJSON_GetObjectItemCaseSensitive(disclosure, "systemPrompt");
    const cJSON *sp_alg = cJSON_GetObjectItemCaseSensitive(sp, "algorithm");
    if (!cJSON_IsString(sp_alg) || strcmp(sp_alg->valuestring, ADP_DIGEST_ALGORITHM) != 0) return false;

    /* capital.custody: z.enum(["non_custodial","custodial"]) (manifest custody). */
    const cJSON *cap = cJSON_GetObjectItemCaseSensitive(disclosure, "capital");
    const cJSON *custody = cJSON_GetObjectItemCaseSensitive(cap, "custody");
    if (!cJSON_IsString(custody) || !adp_in_set(ADP_CUSTODY, custody->valuestring))
        return false;

    /* operator.attestation.scheme: known enum OR reverse-domain id. */
    const cJSON *op = cJSON_GetObjectItemCaseSensitive(disclosure, "operator");
    const cJSON *att = cJSON_GetObjectItemCaseSensitive(op, "attestation");
    const cJSON *scheme = cJSON_GetObjectItemCaseSensitive(att, "scheme");
    if (!cJSON_IsString(scheme)) return false;
    if (!adp_in_set(ADP_ATTESTATION_SCHEME_KNOWN, scheme->valuestring) &&
        !is_reverse_domain(scheme->valuestring))
        return false;

    /* operator.attestation.level: z.enum(["none","signed","registry_attested"]). */
    const cJSON *level = cJSON_GetObjectItemCaseSensitive(att, "level");
    if (!cJSON_IsString(level) || !adp_in_set(ADP_ATTESTATION_LEVEL, level->valuestring))
        return false;

    return true;
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
    const cJSON *algorithm = cJSON_GetObjectItemCaseSensitive(signature, "algorithm");
    const cJSON *publicKey = cJSON_GetObjectItemCaseSensitive(signature, "publicKey");
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(signature, "value");
    if (!cJSON_IsString(agentId) || !cJSON_IsString(publicKey) || !cJSON_IsString(value)) {
        if (reason) *reason = "malformed envelope";
        return false;
    }

    /* The signature scheme is fixed at ed25519 (signature.algorithm is z.literal in
     * the TS schema). An envelope declaring any other algorithm — even one carrying a
     * valid-looking ed25519 publicKey/value — must be refused, not silently
     * ed25519-verified. */
    if (!cJSON_IsString(algorithm) || strcmp(algorithm->valuestring, "ed25519") != 0) {
        if (reason) *reason = "unsupported signature algorithm";
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

/* ── v2 JWS-EdDSA envelope (SPEC.md §5) ─────────────────────────────────────── */
bool adp_is_jws_envelope(const cJSON *signed_env) {
    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(signed_env, "payload");
    const cJSON *prot = cJSON_GetObjectItemCaseSensitive(signed_env, "protected");
    return cJSON_IsString(payload) && cJSON_IsString(prot);
}

bool adp_verify_disclosure_jws(const cJSON *signed_env, const char **reason) {
    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(signed_env, "payload");
    const cJSON *prot = cJSON_GetObjectItemCaseSensitive(signed_env, "protected");
    const cJSON *header = cJSON_GetObjectItemCaseSensitive(signed_env, "header");
    const cJSON *sig = cJSON_GetObjectItemCaseSensitive(signed_env, "signature");
    if (!cJSON_IsString(payload) || !cJSON_IsString(prot) ||
        !cJSON_IsObject(header) || !cJSON_IsString(sig)) {
        if (reason) *reason = "malformed jws envelope";
        return false;
    }
    const cJSON *jwk = cJSON_GetObjectItemCaseSensitive(header, "jwk");
    const cJSON *x = cJSON_GetObjectItemCaseSensitive(jwk, "x");
    if (!cJSON_IsString(x)) {
        if (reason) *reason = "malformed jwk";
        return false;
    }

    /* protected header must declare alg == "EdDSA". */
    size_t prot_len = 0;
    unsigned char *prot_json = b64url_decode(prot->valuestring, strlen(prot->valuestring), &prot_len);
    if (!prot_json) {
        if (reason) *reason = "unreadable protected header";
        return false;
    }
    cJSON *prot_obj = cJSON_ParseWithLength((const char *)prot_json, prot_len);
    free(prot_json);
    if (!prot_obj) {
        if (reason) *reason = "unreadable protected header";
        return false;
    }
    const cJSON *alg = cJSON_GetObjectItemCaseSensitive(prot_obj, "alg");
    int alg_ok = cJSON_IsString(alg) && strcmp(alg->valuestring, "EdDSA") == 0;
    cJSON_Delete(prot_obj);
    if (!alg_ok) {
        if (reason) *reason = "unsupported JWS alg";
        return false;
    }

    /* jwk.x → 32-byte ed25519 public key. */
    size_t pk_len = 0;
    unsigned char *pk = b64url_decode(x->valuestring, strlen(x->valuestring), &pk_len);
    if (!pk || pk_len != crypto_sign_PUBLICKEYBYTES) {
        free(pk);
        if (reason) *reason = "jwk.x is not a 32-byte ed25519 key";
        return false;
    }

    /* signature over ASCII(protected + "." + payload). */
    size_t sig_len = 0;
    unsigned char *sig_bytes = b64url_decode(sig->valuestring, strlen(sig->valuestring), &sig_len);
    if (!sig_bytes || sig_len != crypto_sign_BYTES) {
        free(pk);
        free(sig_bytes);
        if (reason) *reason = "jws signature mismatch";
        return false;
    }
    size_t plen = strlen(prot->valuestring);
    size_t paylen = strlen(payload->valuestring);
    size_t total = plen + 1 + paylen;
    unsigned char *signing_input = (unsigned char *)malloc(total);
    if (!signing_input) {
        free(pk);
        free(sig_bytes);
        if (reason) *reason = "out of memory";
        return false;
    }
    memcpy(signing_input, prot->valuestring, plen);
    signing_input[plen] = '.';
    memcpy(signing_input + plen + 1, payload->valuestring, paylen);
    int sig_ok = crypto_sign_verify_detached(sig_bytes, signing_input, total, pk) == 0;
    free(signing_input);
    free(sig_bytes);
    if (!sig_ok) {
        free(pk);
        if (reason) *reason = "jws signature mismatch";
        return false;
    }

    /* binding: decode the JCS payload, confirm its agentId == the JWK key (hex). The TS
     * reference also accepts did:key(key) or a rotation chain; ALL interop JWS fixtures
     * use the direct hex form, so did:key/base58 is scoped OUT of the C port (no fixture
     * exercises it; documented in the deliverable). */
    char pk_hex[2 * crypto_sign_PUBLICKEYBYTES + 1];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, pk_len);
    free(pk);

    size_t pay_dec_len = 0;
    unsigned char *pay_json = b64url_decode(payload->valuestring, paylen, &pay_dec_len);
    if (!pay_json) {
        if (reason) *reason = "unreadable payload";
        return false;
    }
    cJSON *doc = cJSON_ParseWithLength((const char *)pay_json, pay_dec_len);
    free(pay_json);
    if (!doc) {
        if (reason) *reason = "unreadable payload";
        return false;
    }
    const cJSON *agentId = cJSON_GetObjectItemCaseSensitive(doc, "agentId");
    int bound = cJSON_IsString(agentId) && strcmp(agentId->valuestring, pk_hex) == 0;
    cJSON_Delete(doc);
    if (!bound) {
        if (reason) *reason = "agentId does not match the signing public key";
        return false;
    }
    if (reason) *reason = NULL;
    return true;
}

/* Decode the disclosure document from either envelope shape. */
cJSON *adp_get_disclosure(const cJSON *signed_env, int *owned) {
    if (owned) *owned = 0;
    if (adp_is_jws_envelope(signed_env)) {
        const cJSON *payload = cJSON_GetObjectItemCaseSensitive(signed_env, "payload");
        size_t dec_len = 0;
        unsigned char *json = b64url_decode(payload->valuestring, strlen(payload->valuestring), &dec_len);
        if (!json) return NULL;
        cJSON *doc = cJSON_ParseWithLength((const char *)json, dec_len);
        free(json);
        if (owned) *owned = 1;
        return doc;
    }
    cJSON *d = cJSON_GetObjectItemCaseSensitive(signed_env, "disclosure");
    return cJSON_IsObject(d) ? d : NULL;
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

/* ── robust raw-input gate ─────────────────────────────────────────────────────
 * The verification path here is adp_verify_disclosure_signature, which already
 * guards every member access (cJSON_GetObjectItemCaseSensitive returns NULL for a
 * missing key OR a non-object container, and every value is type-checked before
 * dereference). So the only extra work is parsing untrusted bytes and treating a
 * parse failure — or any non-accepting verdict — as a rejection. Accept (return 0)
 * ONLY when the signature verifies and the identity binding holds. */
int adp_verify_raw(const char *raw) {
    if (!raw) return 1;
    cJSON *parsed = cJSON_Parse(raw);
    if (!parsed) return 1; /* not JSON / truncated / malformed → reject */
    /* A top-level non-object (null, number, array, string) has no disclosure /
     * signature members; adp_verify_disclosure_signature handles that safely and
     * returns false, but short-circuit for clarity. */
    int rejected = 1;
    if (cJSON_IsObject(parsed)) {
        /* Structural schema validation comes FIRST (mirrors parseAnySignedDisclosure →
         * zod in verifyAndEvaluate): a signed-but-schema-invalid envelope (valid ed25519
         * signature over a bad enum / literal) MUST be rejected on schema grounds, not
         * silently accepted because the signature checks out. Decode the disclosure from
         * whichever envelope shape, validate the grammar, then verify the signature. */
        int owned = 0;
        cJSON *disclosure = adp_get_disclosure(parsed, &owned);
        if (adp_disclosure_schema_valid(disclosure)) {
            const char *reason = NULL;
            int sig_ok = adp_is_jws_envelope(parsed)
                             ? adp_verify_disclosure_jws(parsed, &reason)
                             : adp_verify_disclosure_signature(parsed, &reason);
            rejected = sig_ok ? 0 : 1;
        }
        if (owned && disclosure) cJSON_Delete(disclosure);
    }
    cJSON_Delete(parsed);
    return rejected;
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

/* ── RFC 9421 (HTTP Message Signatures) handshake base ──────────────────────────
 * The handshake response signs over an RFC 9421 *signature base*: covered-component
 * lines then an @signature-params line. Mirrors signatureBase() in src/handshake.ts.
 * This is the non-HTTP profile — every covered component is an `adp-*` derived
 * component. ADP deviations: `created` is the ISO-8601 string (not unix-seconds) and the
 * signature bytes are hex (not the sf-binary :base64: wrapper). `disclosure_version` may
 * be NULL (no version line / not in the covered set) or a decimal string; `verifier_id`
 * may be NULL (no `;tag=`). Returns a freshly malloc'd base (caller frees) or NULL. */
static char *handshake_signature_base(const char *agent_id, const char *audit_head,
                                      const char *signed_at, const char *nonce,
                                      const char *verifier_id,
                                      const char *disclosure_version) {
    sb s;
    sb_init(&s);

    /* covered-component lines */
    sb_puts(&s, "\"adp-agent-id\": ");
    sb_puts(&s, agent_id);
    sb_puts(&s, "\n\"adp-audit-head\": ");
    sb_puts(&s, audit_head);
    if (disclosure_version) {
        sb_puts(&s, "\n\"adp-disclosure-version\": ");
        sb_puts(&s, disclosure_version);
    }

    /* @signature-params line: (<inner quoted names>);created=...;keyid=...;alg;nonce[;tag] */
    sb_puts(&s, "\n\"@signature-params\": (\"adp-agent-id\" \"adp-audit-head\"");
    if (disclosure_version) sb_puts(&s, " \"adp-disclosure-version\"");
    sb_puts(&s, ");created=\"");
    sb_puts(&s, signed_at);
    sb_puts(&s, "\";keyid=\"");
    sb_puts(&s, agent_id);
    sb_puts(&s, "\";alg=\"ed25519\";nonce=\"");
    sb_puts(&s, nonce);
    sb_putc(&s, '"');
    if (verifier_id) {
        sb_puts(&s, ";tag=\"");
        sb_puts(&s, verifier_id);
        sb_putc(&s, '"');
    }

    if (s.oom) {
        free(s.buf);
        return NULL;
    }
    return s.buf;
}

/* The `Signature-Input` value (labelled `sig`): `sig=` + the @signature-params value
 * (the same suffix that appears on the @signature-params line of the base). */
static char *handshake_signature_input(const char *agent_id, const char *signed_at,
                                       const char *nonce, const char *verifier_id,
                                       const char *disclosure_version) {
    sb s;
    sb_init(&s);
    sb_puts(&s, "sig=(\"adp-agent-id\" \"adp-audit-head\"");
    if (disclosure_version) sb_puts(&s, " \"adp-disclosure-version\"");
    sb_puts(&s, ");created=\"");
    sb_puts(&s, signed_at);
    sb_puts(&s, "\";keyid=\"");
    sb_puts(&s, agent_id);
    sb_puts(&s, "\";alg=\"ed25519\";nonce=\"");
    sb_puts(&s, nonce);
    sb_putc(&s, '"');
    if (verifier_id) {
        sb_puts(&s, ";tag=\"");
        sb_puts(&s, verifier_id);
        sb_putc(&s, '"');
    }
    if (s.oom) {
        free(s.buf);
        return NULL;
    }
    return s.buf;
}

/* ── handshake responder (SPEC.md §7) ──────────────────────────────────────── */
int adp_respond_to_challenge(const cJSON *challenge, const unsigned char sk[64],
                             const char *pk_hex, const char *audit_head,
                             const char *now, char out_sig_hex[129]) {
    const cJSON *c_nonce = cJSON_GetObjectItemCaseSensitive(challenge, "nonce");
    const cJSON *c_verifier = cJSON_GetObjectItemCaseSensitive(challenge, "verifierId");
    if (!cJSON_IsString(c_nonce) || !pk_hex || !audit_head || !now) return -1;

    /* Sign the RFC 9421 signature base built from agentId(=pk_hex), auditHead, signedAt
     * (=now), nonce, and the challenge's verifierId (the `tag`, dropped when absent).
     * No disclosure_version is declared by the responder here. Mirrors
     * respondToChallenge() in src/handshake.ts. */
    const char *verifier_id = cJSON_IsString(c_verifier) ? c_verifier->valuestring : NULL;
    char *base = handshake_signature_base(pk_hex, audit_head, now, c_nonce->valuestring,
                                          verifier_id, NULL);
    if (!base) return -1;
    adp_sign_message((const unsigned char *)base, strlen(base), sk, out_sig_hex);
    free(base);
    return 0;
}

/* ── handshake verifier (SPEC.md §7) ───────────────────────────────────────── */
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
    const cJSON *r_siginput = cJSON_GetObjectItemCaseSensitive(response, "signatureInput");
    const cJSON *r_version = cJSON_GetObjectItemCaseSensitive(response, "disclosureVersion");
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

    /* Reconstruct the RFC 9421 signature base + Signature-Input from OUR challenge
     * (nonce, verifierId) and the response's claimed values. `disclosureVersion`, when
     * present, is a SIGNED covered component (formatted as its decimal string). The
     * response's signatureInput must match exactly (no param smuggling), then the
     * ed25519 signature must verify over the reconstructed base. Mirrors
     * verifyChallengeResponse() in src/handshake.ts. */
    const char *verifier_id = cJSON_IsString(c_verifier) ? c_verifier->valuestring : NULL;
    char ver_buf[32];
    const char *version_str = NULL;
    if (cJSON_IsNumber(r_version)) {
        snprintf(ver_buf, sizeof(ver_buf), "%lld", (long long)r_version->valuedouble);
        version_str = ver_buf;
    }

    /* 3a. Signature-Input must match the issued challenge (only checked when the response
     *     carries one; a response with no signatureInput skips this and relies on the
     *     base-signature check below). */
    if (cJSON_IsString(r_siginput)) {
        char *expected_input = handshake_signature_input(
            r_agent->valuestring, r_signedAt->valuestring, c_nonce->valuestring,
            verifier_id, version_str);
        if (!expected_input) {
            if (reason) *reason = "out of memory";
            return false;
        }
        int input_ok = strcmp(r_siginput->valuestring, expected_input) == 0;
        free(expected_input);
        if (!input_ok) {
            if (reason) *reason = "signature-input does not match the issued challenge";
            return false;
        }
    }

    /* 3b. signature over the RFC 9421 signature base */
    char *base = handshake_signature_base(r_agent->valuestring, r_head->valuestring,
                                          r_signedAt->valuestring, c_nonce->valuestring,
                                          verifier_id, version_str);
    if (!base) {
        if (reason) *reason = "out of memory";
        return false;
    }
    bool sig_ok = verify_message(base, r_agent->valuestring, r_sig->valuestring);
    free(base);
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
/* Ranks are derived from the manifest arrays so the grade/level value sets stay the
 * single source. ADP_RED_TEAM_GRADE is best→worst (A..F): higher rank == better grade,
 * so rank = (last index) - manifest index. ADP_ATTESTATION_LEVEL is weakest→strongest
 * (none,signed,registry_attested): rank == manifest index. */
static int grade_rank(const char *g) {
    if (!g) return -1;
    int n = 0;
    while (ADP_RED_TEAM_GRADE[n]) n++;
    for (int i = 0; i < n; i++)
        if (strcmp(g, ADP_RED_TEAM_GRADE[i]) == 0) return (n - 1) - i;
    return -1;
}
static int attestation_rank(const char *l) {
    if (!l) return -1;
    for (int i = 0; ADP_ATTESTATION_LEVEL[i]; i++)
        if (strcmp(l, ADP_ATTESTATION_LEVEL[i]) == 0) return i;
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
    /* Accept either envelope shape (v1 object or v2 flattened JWS). For JWS the
     * disclosure document is the base64url JCS payload, decoded here; the policy then
     * runs against it exactly as for v1. Even when the JWS signature fails (tampered /
     * forged), the decoded payload is still evaluated — the reference reports both the
     * signature failure AND any policy failure over the carried document. */
    int d_owned = 0;
    cJSON *d = adp_get_disclosure(signed_env, &d_owned);
    int is_jws = adp_is_jws_envelope(signed_env);

    /* signature (default on unless requireValidSignature === false) */
    const cJSON *reqSig = cJSON_GetObjectItemCaseSensitive(policy, "requireValidSignature");
    if (!(cJSON_IsBool(reqSig) && cJSON_IsFalse(reqSig))) {
        fs.checks_run++;
        const char *why = NULL;
        int sig_ok = is_jws ? adp_verify_disclosure_jws(signed_env, &why)
                            : adp_verify_disclosure_signature(signed_env, &why);
        if (!sig_ok)
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
        if (!(cJSON_IsString(cust) && strcmp(cust->valuestring, ADP_CUSTODY[0]) == 0))
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

    if (d_owned && d) cJSON_Delete(d);
}

void adp_verdict_free(adp_verdict *v) {
    if (!v) return;
    for (size_t i = 0; i < v->failed_count; i++) free(v->failed[i]);
    free(v->failed);
    v->failed = NULL;
    v->failed_count = 0;
}

/* ── emitter: ed25519 signing (SPEC.md §5) ─────────────────────────────────────
 * PKCS8 DER for an ed25519 private key is a fixed 48-byte structure: the 16-byte
 * prefix below, then the 32-byte seed. crypto_sign_seed_keypair expands the seed
 * into libsodium's 64-byte secret key (seed||pubkey), matching what node:crypto's
 * createPrivateKey + sign(null, ...) does internally. */
static const char PKCS8_ED25519_PREFIX[] = "302e020100300506032b657004220420";

int adp_seed_from_pkcs8_hex(const char *pkcs8_hex, unsigned char seed[32]) {
    if (!pkcs8_hex) return -1;
    size_t prefix_len = strlen(PKCS8_ED25519_PREFIX);
    if (strncmp(pkcs8_hex, PKCS8_ED25519_PREFIX, prefix_len) != 0) return -1;
    const char *seed_hex = pkcs8_hex + prefix_len;
    size_t bin_len = 0;
    if (sodium_hex2bin(seed, 32, seed_hex, strlen(seed_hex), NULL, &bin_len, NULL) != 0)
        return -1;
    if (bin_len != 32) return -1;
    return 0;
}

void adp_keypair_from_seed(const unsigned char seed[32],
                           unsigned char pk[32], unsigned char sk[64]) {
    crypto_sign_seed_keypair(pk, sk, seed);
}

void adp_sign_message(const unsigned char *msg, size_t msglen,
                      const unsigned char sk[64], char out_hex[129]) {
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, msg, msglen, sk);
    sodium_bin2hex(out_hex, 129, sig, sizeof(sig));
}

int adp_sign_disclosure(const cJSON *disclosure, const unsigned char sk[64],
                        char out_sig_hex[129]) {
    char *canon = adp_canonicalize(disclosure);
    if (!canon) return -1;
    adp_sign_message((const unsigned char *)canon, strlen(canon), sk, out_sig_hex);
    free(canon);
    return 0;
}

/* ── redactable disclosure (src/redaction.ts) ──────────────────────────────────
 * commit(value, salt) = sha256Hex(canonicalize(value) + ":" + salt). */
void adp_free_str_list(char **list, size_t count) {
    if (!list) return;
    for (size_t i = 0; i < count; i++) free(list[i]);
    free(list);
}

static int commit_field(const cJSON *value, const char *salt, char out_hex[65]) {
    char *cv = adp_canonicalize(value);
    if (!cv) return -1;
    size_t clen = strlen(cv);
    size_t slen = strlen(salt);
    size_t total = clen + 1 + slen;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        free(cv);
        return -1;
    }
    memcpy(buf, cv, clen);
    buf[clen] = ':';
    memcpy(buf + clen + 1, salt, slen);
    adp_sha256_hex(buf, total, out_hex);
    free(buf);
    free(cv);
    return 0;
}

bool adp_verify_redacted(const cJSON *view, char ***out_revealed,
                         size_t *out_count, const char **reason) {
    if (out_revealed) *out_revealed = NULL;
    if (out_count) *out_count = 0;

    const cJSON *meta = cJSON_GetObjectItemCaseSensitive(view, "meta");
    const cJSON *commitments = cJSON_GetObjectItemCaseSensitive(view, "commitments");
    const cJSON *revealed = cJSON_GetObjectItemCaseSensitive(view, "revealed");
    const cJSON *signature = cJSON_GetObjectItemCaseSensitive(view, "signature");
    if (!cJSON_IsObject(meta) || !cJSON_IsObject(commitments) ||
        !cJSON_IsObject(signature)) {
        if (reason) *reason = "malformed redacted view";
        return false;
    }
    const cJSON *agentId = cJSON_GetObjectItemCaseSensitive(meta, "agentId");
    const cJSON *publicKey = cJSON_GetObjectItemCaseSensitive(signature, "publicKey");
    const cJSON *sigValue = cJSON_GetObjectItemCaseSensitive(signature, "value");
    if (!cJSON_IsString(agentId) || !cJSON_IsString(publicKey) || !cJSON_IsString(sigValue)) {
        if (reason) *reason = "malformed redacted view";
        return false;
    }

    /* 1. identity binding */
    if (strcmp(agentId->valuestring, publicKey->valuestring) != 0) {
        if (reason) *reason = "agentId does not match the signing public key";
        return false;
    }

    /* 2. signature over canonicalize({meta, commitments}) */
    cJSON *signed_body = cJSON_CreateObject();
    if (!signed_body) {
        if (reason) *reason = "out of memory";
        return false;
    }
    cJSON_AddItemReferenceToObject(signed_body, "meta", (cJSON *)meta);
    cJSON_AddItemReferenceToObject(signed_body, "commitments", (cJSON *)commitments);
    char *signed_canon = adp_canonicalize(signed_body);
    cJSON_Delete(signed_body);
    if (!signed_canon) {
        if (reason) *reason = "out of memory";
        return false;
    }
    bool sig_ok = verify_message(signed_canon, publicKey->valuestring, sigValue->valuestring);
    free(signed_canon);
    if (!sig_ok) {
        if (reason) *reason = "signature mismatch";
        return false;
    }

    /* 3. each revealed field recomputes to its commitment */
    size_t cap = 8, count = 0;
    char **names = (char **)malloc(cap * sizeof(char *));
    if (!names) {
        if (reason) *reason = "out of memory";
        return false;
    }
    const cJSON *field;
    cJSON_ArrayForEach(field, revealed) {
        const char *fname = field->string ? field->string : "";
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(field, "value");
        const cJSON *salt = cJSON_GetObjectItemCaseSensitive(field, "salt");
        const cJSON *expected = cJSON_GetObjectItemCaseSensitive(commitments, fname);
        if (!cJSON_IsString(expected)) {
            adp_free_str_list(names, count);
            if (reason) *reason = "revealed field has no commitment";
            return false;
        }
        char got[65];
        if (!cJSON_IsString(salt) ||
            commit_field(value, salt->valuestring, got) != 0 ||
            strcmp(got, expected->valuestring) != 0) {
            adp_free_str_list(names, count);
            if (reason) *reason = "revealed field does not match its commitment";
            return false;
        }
        if (count == cap) {
            cap *= 2;
            char **grown = (char **)realloc(names, cap * sizeof(char *));
            if (!grown) {
                adp_free_str_list(names, count);
                if (reason) *reason = "out of memory";
                return false;
            }
            names = grown;
        }
        names[count++] = adp_strdup(fname);
    }

    if (count > 1)
        qsort(names, count, sizeof(char *), str_cmp_qsort);

    if (out_revealed) *out_revealed = names;
    else adp_free_str_list(names, count);
    if (out_count) *out_count = count;
    if (reason) *reason = NULL;
    return true;
}

/* ── revocation (src/revocation.ts) ────────────────────────────────────────────
 * Signature covers canonicalize({id, reason, revokedAt}). */
bool adp_verify_revocation(const cJSON *record) {
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(record, "id");
    const cJSON *reason = cJSON_GetObjectItemCaseSensitive(record, "reason");
    const cJSON *revokedAt = cJSON_GetObjectItemCaseSensitive(record, "revokedAt");
    const cJSON *publicKey = cJSON_GetObjectItemCaseSensitive(record, "publicKey");
    const cJSON *signature = cJSON_GetObjectItemCaseSensitive(record, "signature");
    if (!cJSON_IsString(id) || !cJSON_IsString(reason) || !cJSON_IsString(revokedAt) ||
        !cJSON_IsString(publicKey) || !cJSON_IsString(signature))
        return false;

    cJSON *body = cJSON_CreateObject();
    if (!body) return false;
    cJSON_AddStringToObject(body, "id", id->valuestring);
    cJSON_AddStringToObject(body, "reason", reason->valuestring);
    cJSON_AddStringToObject(body, "revokedAt", revokedAt->valuestring);
    char *canon = adp_canonicalize(body);
    cJSON_Delete(body);
    if (!canon) return false;
    bool ok = verify_message(canon, publicKey->valuestring, signature->valuestring);
    free(canon);
    return ok;
}

/* ── transparency inclusion proof (src/transparencyTransport.ts) ───────────────
 * Recompute sha256Hex(canonicalize({index, disclosureDigest, agentId, issuedAt,
 * prevHash})) and compare against entry.hash. The fields are added by reference so
 * the number/string types (and thus the canonical form) match the source entry. */
bool adp_verify_inclusion_proof(const cJSON *entry) {
    const cJSON *index = cJSON_GetObjectItemCaseSensitive(entry, "index");
    const cJSON *disclosureDigest = cJSON_GetObjectItemCaseSensitive(entry, "disclosureDigest");
    const cJSON *agentId = cJSON_GetObjectItemCaseSensitive(entry, "agentId");
    const cJSON *issuedAt = cJSON_GetObjectItemCaseSensitive(entry, "issuedAt");
    const cJSON *prevHash = cJSON_GetObjectItemCaseSensitive(entry, "prevHash");
    const cJSON *hash = cJSON_GetObjectItemCaseSensitive(entry, "hash");
    if (!cJSON_IsNumber(index) || !cJSON_IsString(disclosureDigest) ||
        !cJSON_IsString(agentId) || !cJSON_IsString(issuedAt) ||
        !cJSON_IsString(prevHash) || !cJSON_IsString(hash))
        return false;

    cJSON *body = cJSON_CreateObject();
    if (!body) return false;
    cJSON_AddItemReferenceToObject(body, "index", (cJSON *)index);
    cJSON_AddItemReferenceToObject(body, "disclosureDigest", (cJSON *)disclosureDigest);
    cJSON_AddItemReferenceToObject(body, "agentId", (cJSON *)agentId);
    cJSON_AddItemReferenceToObject(body, "issuedAt", (cJSON *)issuedAt);
    cJSON_AddItemReferenceToObject(body, "prevHash", (cJSON *)prevHash);
    char *canon = adp_canonicalize(body);
    cJSON_Delete(body);
    if (!canon) return false;
    char expected[65];
    adp_sha256_hex((const unsigned char *)canon, strlen(canon), expected);
    free(canon);
    return strcmp(expected, hash->valuestring) == 0;
}
