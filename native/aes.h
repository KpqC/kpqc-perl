#ifndef KPQC_KAT_AES_H
#define KPQC_KAT_AES_H

#include <stddef.h>
#include <stdint.h>

#define AES256_KEYBYTES 32
#define AES_BLOCKBYTES 16
#define AES256_ROUND_KEYBYTES 240

typedef struct {
    uint8_t round_keys[AES256_ROUND_KEYBYTES];
} aes256ctx;

void aes256_ecb_keyexp(aes256ctx *ctx, const uint8_t key[AES256_KEYBYTES]);
void aes256_ecb(uint8_t *output, const uint8_t *input, size_t blocks,
                const aes256ctx *ctx);
void aes256_ctx_release(aes256ctx *ctx);

#endif
