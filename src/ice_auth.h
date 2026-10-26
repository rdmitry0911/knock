/* Authenticated passive ICE transport. Shared by packet capture and OpenWrt
 * controller; no STUN responder or listening UDP socket is needed. */
#ifndef KNOCK_ICE_AUTH_H
#define KNOCK_ICE_AUTH_H
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define KNC_ICE_LENGTH 165
#define KNC_ICE_PREFIX 101
#define KNC_ICE_TCP_PROOF 6
static inline int knc_ice_split(const char *token) {
    return !memcmp(token, "KNI2", 4);
}
static inline int knc_hex(const char *s, size_t n, uint64_t *out) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned c = (unsigned char)s[i], x;
        if (c >= '0' && c <= '9')
            x = c - '0';
        else if (c >= 'a' && c <= 'f')
            x = c - 'a' + 10;
        else
            return 0;
        v = (v << 4) | x;
    }
    if (out)
        *out = v;
    return 1;
}
static inline int knc_ice_verify(const char *token, const char *secret, const char *door,
                                 unsigned revision, const char *source, int protect, time_t now) {
    unsigned char key[20], actual[32], expected[32];
    unsigned bits = 0, acc = 0, used = 0, len = 0;
    uint64_t rev, step, issued;
    int split = strlen(token) == KNC_ICE_LENGTH && knc_ice_split(token);
    uint64_t target = 0;
    if (strlen(token) != KNC_ICE_LENGTH || (!split && memcmp(token, "KNI1", 4)) || strlen(secret) != 32 ||
        strlen(door) < 29 || memcmp(token + 4, door, 24) || door[24] != '.' ||
        (token[28] == 'O'   ? strcmp(door + 25, "open")
         : token[28] == 'C' ? strcmp(door + 25, "close")
                            : 1) ||
        !knc_hex(token + 4, 24, NULL) || !knc_hex(token + 29, 8, &rev) || rev != revision ||
        !knc_hex(token + 37, split ? 8 : 16, &step) ||
        (split && (!knc_hex(token + 45, 8, &target) || (target >> 24) == 0 || (target >> 24) >= 224)) ||
        !knc_hex(token + 53, 16, &issued) ||
        !knc_hex(token + 69, 32, NULL) || !knc_hex(token + 101, 64, NULL) ||
        step > (uint64_t)now / 30 + 1 || step + 1 < (uint64_t)now / 30 ||
        issued > (uint64_t)now * 1000 + 60000 || issued + 60000 < (uint64_t)now * 1000)
        return 0;
    for (unsigned i = 0; i < 32; i++) {
        unsigned c = (unsigned char)secret[i], v;
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= '2' && c <= '7')
            v = c - '2' + 26;
        else
            return 0;
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            key[used++] = (unsigned char)(acc >> bits);
        }
    }
    char message[256];
    int n = snprintf(message, sizeof(message), "knock-control:ice:v%d:%.*s:%s", split ? 2 : 1,
                     KNC_ICE_PREFIX, token, protect ? source : "-");
    if (n < 0 || (size_t)n >= sizeof(message) ||
        !HMAC(EVP_sha256(), key, sizeof(key), (unsigned char *)message, (size_t)n, actual, &len) ||
        len != 32)
        return 0;
    for (unsigned i = 0; i < 32; i++) {
        uint64_t v;
        if (!knc_hex(token + 101 + i * 2, 2, &v))
            return 0;
        expected[i] = (unsigned char)v;
    }
    return CRYPTO_memcmp(actual, expected, 32) == 0;
}
/* KNI2 additionally needs a TCP SYN proof from this authenticated target. */
static inline void knc_ice_target(const char *token, const char *source, char out[16]) {
    if (!knc_ice_split(token)) {
        snprintf(out, 16, "%s", source);
        return;
    }
    uint64_t ip = 0;
    knc_hex(token + 45, 8, &ip);
    snprintf(out, 16, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)((ip >> 16) & 255),
             (unsigned)((ip >> 8) & 255), (unsigned)(ip & 255));
}
static inline unsigned short knc_ice_proof_port(const char *token, unsigned base, unsigned index) {
    unsigned short ports[KNC_ICE_TCP_PROOF];
    if (index >= KNC_ICE_TCP_PROOF) return 0;
    for (unsigned i = 0; i <= index; i++) {
        uint64_t v = 0;
        knc_hex(token + 101 + 2 * i, 2, &v);
        unsigned offset = (unsigned)v % 255;
        for (unsigned j = 0; j < i; j++) {
            if (ports[j] == base + 1 + offset) { offset = (offset + 1) % 255; j = (unsigned)-1; }
        }
        ports[i] = (unsigned short)(base + 1 + offset);
    }
    return ports[index];
}
/* Strict bounded RFC 8489 Binding request parser. Return only our canonical
 * remote ufrag, never interpolate untrusted STUN text into commands. */
static inline int knc_ice_stun(const unsigned char *p, size_t size,
                               char token[KNC_ICE_LENGTH + 1]) {
    if (size < 20 || size > 1024 || p[0] != 0 || p[1] != 1 || p[4] != 0x21 || p[5] != 0x12 ||
        p[6] != 0xa4 || p[7] != 0x42)
        return 0;
    size_t length = ((size_t)p[2] << 8) | p[3];
    if (length % 4 || length + 20 != size)
        return 0;
    int found = 0;
    for (size_t offset = 20; offset < size;) {
        if (size - offset < 4)
            return 0;
        unsigned type = ((unsigned)p[offset] << 8) | p[offset + 1];
        size_t n = ((size_t)p[offset + 2] << 8) | p[offset + 3], padded = (n + 3) & ~(size_t)3;
        if (padded > size - offset - 4)
            return 0;
        if (type == 6) {
            if (found || n < KNC_ICE_LENGTH + 2 || n > KNC_ICE_LENGTH + 1 + 256 ||
                (memcmp(p + offset + 4, "KNI1", 4) && memcmp(p + offset + 4, "KNI2", 4)) ||
                p[offset + 4 + KNC_ICE_LENGTH] != ':')
                return 0;
            const unsigned char *s = p + offset + 4;
            for (size_t i = KNC_ICE_LENGTH + 1; i < n; i++)
                if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
                      (s[i] >= '0' && s[i] <= '9') || s[i] == '+' || s[i] == '/'))
                    return 0;
            memcpy(token, s, KNC_ICE_LENGTH);
            token[KNC_ICE_LENGTH] = 0;
            found = 1;
        }
        offset += 4 + padded;
    }
    if (!found || !knc_hex(token + 4, 24, NULL) || (token[28] != 'O' && token[28] != 'C') ||
        !knc_hex(token + 29, KNC_ICE_LENGTH - 29, NULL))
        return 0;
    return 1;
}
#endif
