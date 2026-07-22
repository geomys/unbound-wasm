// Replaces validator/val_secalgo.c: DNSSEC cryptography is delegated to the
// host through the crypto_* and nsec3_hash imports, so no crypto library is
// linked into the guest and key material never meets upstream C parsing
// beyond wire splitting. The host decides which DNSKEY algorithms verify;
// the digest and NSEC3 tables below must stay in sync with the host's
// (crypto.go in the reference SDK).

#include "config.h"
#include "abi/unbound_wasm_abi.h"
#include "util/data/packed_rrset.h"
#include "validator/val_secalgo.h"
#include "sldns/rrdef.h"
#include "sldns/sbuffer.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// NSEC3 hash algorithm 1 is SHA-1 (RFC 5155), the only one assigned.
// The host implements the full iterated hash, so the salt and iteration
// arguments here are unused: Unbound hands over buf = name || salt already
// concatenated, once per iteration.

size_t nsec3_hash_algo_size_supported(int id) { return id == 1 ? 20 : 0; }

int secalgo_nsec3_hash(int algo, unsigned char *buf, size_t len, unsigned char *res) {
    if (algo != 1 || len > INT32_MAX)
        return 0;
    return uw_nsec3_hash(NULL, 0, 0, buf, (int32_t)len, res) != 0;
}

void secalgo_hash_sha256(unsigned char *buf, size_t len, unsigned char *res) {
    if (len <= INT32_MAX)
        (void)uw_crypto_digest(2, buf, (int32_t)len, res); // DS digest 2 = SHA-256
}

// The streaming hash API buffers input and digests once at the end: the
// host import is one-shot, and the inputs (DNSKEY RRsets for key tag and
// ZONEMD computation) are small.

struct secalgo_hash {
    int alg; // host digest selector: 4 = SHA-384, 5 = SHA-512 (ABI-private)
    uint8_t *data;
    size_t len, cap;
};

static struct secalgo_hash *hash_create(int alg) {
    struct secalgo_hash *h = calloc(1, sizeof(*h));
    if (h)
        h->alg = alg;
    return h;
}

struct secalgo_hash *secalgo_hash_create_sha384(void) { return hash_create(4); }
struct secalgo_hash *secalgo_hash_create_sha512(void) { return hash_create(5); }

int secalgo_hash_update(struct secalgo_hash *h, uint8_t *data, size_t len) {
    if (!h || len > SIZE_MAX - h->len)
        return 0;
    if (h->len + len > h->cap) {
        size_t cap = h->cap ? h->cap : 256;
        while (cap < h->len + len) {
            if (cap > SIZE_MAX / 2)
                return 0;
            cap *= 2;
        }
        uint8_t *p = realloc(h->data, cap);
        if (!p)
            return 0;
        h->data = p;
        h->cap = cap;
    }
    memcpy(h->data + h->len, data, len);
    h->len += len;
    return 1;
}

int secalgo_hash_final(struct secalgo_hash *h, uint8_t *result, size_t maxlen,
                       size_t *resultlen) {
    if (!h || !resultlen || h->len > INT32_MAX)
        return 0;
    size_t need = h->alg == 4 ? 48 : 64;
    if (maxlen < need) {
        *resultlen = 0;
        return 0;
    }
    *resultlen = need;
    return uw_crypto_digest(h->alg, h->data, (int32_t)h->len, result) != 0;
}

void secalgo_hash_delete(struct secalgo_hash *h) {
    if (h) {
        free(h->data);
        free(h);
    }
}

// DS digest types (RFC 8624): 1 SHA-1, 2 SHA-256, 4 SHA-384. GOST (3) is
// unsupported, so zones with only GOST DS records validate as insecure.

size_t ds_digest_size_supported(int alg) {
    switch (alg) {
    case 1:
        return 20;
    case 2:
        return 32;
    case 4:
        return 48;
    default:
        return 0;
    }
}

int secalgo_ds_digest(int alg, unsigned char *buf, size_t len, unsigned char *res) {
    if (!ds_digest_size_supported(alg) || len > INT32_MAX)
        return 0;
    return uw_crypto_digest(alg, buf, (int32_t)len, res) != 0;
}

int dnskey_algo_id_is_supported(int id) { return uw_crypto_supported(id) != 0; }

enum sec_status verify_canonrrset(struct sldns_buffer *buf, int algo,
                                  unsigned char *sig, unsigned int siglen,
                                  unsigned char *key, unsigned int keylen,
                                  char **reason) {
    size_t len = sldns_buffer_limit(buf);
    if (reason)
        *reason = NULL;
    if (len > INT32_MAX || keylen > INT32_MAX || siglen > INT32_MAX) {
        if (reason)
            *reason = "crypto input too large";
        return sec_status_unchecked;
    }
    if (!uw_crypto_supported(algo)) {
        if (reason)
            *reason = "unsupported DNSKEY algorithm";
        return sec_status_unchecked;
    }
    if (uw_crypto_verify(algo, key, (int32_t)keylen, sldns_buffer_begin(buf),
                         (int32_t)len, sig, (int32_t)siglen))
        return sec_status_secure;
    if (reason)
        *reason = "signature crypto failed";
    return sec_status_bogus;
}
