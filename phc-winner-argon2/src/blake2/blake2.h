#ifndef PORTABLE_BLAKE2_H
#define PORTABLE_BLAKE2_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#if defined(__cplusplus)
extern "C" {
#endif

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES = 64,
    BLAKE2B_KEYBYTES = 64,
    BLAKE2B_SALTBYTES = 16,
    BLAKE2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct __blake2b_param {
    uint8_t digest_length;                   /* 1 */
    uint8_t key_length;                      /* 2 */
    uint8_t fanout;                          /* 3 */
    uint8_t depth;                           /* 4 */
    uint32_t leaf_length;                    /* 8 */
    uint64_t node_offset;                    /* 16 */
    uint8_t node_depth;                      /* 17 */
    uint8_t inner_length;                    /* 18 */
    uint8_t reserved[14];                    /* 32 */
    uint8_t salt[BLAKE2B_SALTBYTES];         /* 48 */
    uint8_t personal[BLAKE2B_PERSONALBYTES]; /* 64 */
} blake2b_param;
#pragma pack(pop)

typedef struct __blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    unsigned buflen;
    unsigned outlen;
    uint8_t last_node;
} blake2b_state;

/* Ensure param structs have not been wrongly padded */
/* Poor man's static_assert */
enum {
    blake2_size_check_0 = 1 / !!(CHAR_BIT == 8),
    blake2_size_check_2 =
        1 / !!(sizeof(blake2b_param) == sizeof(uint64_t) * CHAR_BIT)
};

/* Streaming API */
int blake2b_init_mangled(blake2b_state *S, size_t outlen);
int blake2b_init_key_mangled(blake2b_state *S, size_t outlen, const void *key,
                     size_t keylen);
int blake2b_init_param_mangled(blake2b_state *S, const blake2b_param *P);
int blake2b_update_mangled(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final_mangled(blake2b_state *S, void *out, size_t outlen);

/* Simple API */
int blake2b_mangled(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen);

/* Argon2 Team - Begin Code */
int blake2b_long(void *out, size_t outlen, const void *in, size_t inlen);
/* Argon2 Team - End Code */

#if defined(__cplusplus)
}
#endif

#endif
