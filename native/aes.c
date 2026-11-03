/* Test-only AES-256 implementation for the CTR-DRBG known-answer-test hook. */
#include "aes.h"

#include <string.h>

#define AES256_ROUNDS 14

static uint8_t xtime(uint8_t value) {
    return (uint8_t)((uint8_t)(value << 1) ^
                     (uint8_t)(((uint8_t)(value >> 7)) * 0x1bu));
}

static uint8_t gf_multiply(uint8_t left, uint8_t right) {
    uint8_t product = 0;
    for (unsigned int bit = 0; bit < 8; ++bit) {
        if ((right & 1u) != 0) product ^= left;
        left = xtime(left);
        right >>= 1;
    }
    return product;
}

static uint8_t gf_inverse(uint8_t value) {
    uint8_t result = 1;
    uint8_t power = value;
    unsigned int exponent = 254;

    if (value == 0) return 0;
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = gf_multiply(result, power);
        power = gf_multiply(power, power);
        exponent >>= 1;
    }
    return result;
}

static uint8_t rotate_left(uint8_t value, unsigned int count) {
    return (uint8_t)((uint8_t)(value << count) |
                     (uint8_t)(value >> (8u - count)));
}

static uint8_t substitute(uint8_t value) {
    uint8_t inverse = gf_inverse(value);
    return (uint8_t)(inverse ^ rotate_left(inverse, 1) ^
                     rotate_left(inverse, 2) ^ rotate_left(inverse, 3) ^
                     rotate_left(inverse, 4) ^ 0x63u);
}

static void add_round_key(uint8_t state[AES_BLOCKBYTES],
                          const uint8_t *round_key) {
    for (size_t index = 0; index < AES_BLOCKBYTES; ++index) {
        state[index] ^= round_key[index];
    }
}

static void substitute_bytes(uint8_t state[AES_BLOCKBYTES]) {
    for (size_t index = 0; index < AES_BLOCKBYTES; ++index) {
        state[index] = substitute(state[index]);
    }
}

static void shift_rows(uint8_t state[AES_BLOCKBYTES]) {
    uint8_t shifted[AES_BLOCKBYTES];

    shifted[0] = state[0];
    shifted[1] = state[5];
    shifted[2] = state[10];
    shifted[3] = state[15];
    shifted[4] = state[4];
    shifted[5] = state[9];
    shifted[6] = state[14];
    shifted[7] = state[3];
    shifted[8] = state[8];
    shifted[9] = state[13];
    shifted[10] = state[2];
    shifted[11] = state[7];
    shifted[12] = state[12];
    shifted[13] = state[1];
    shifted[14] = state[6];
    shifted[15] = state[11];

    memcpy(state, shifted, sizeof(shifted));
}

static void mix_columns(uint8_t state[AES_BLOCKBYTES]) {
    for (size_t column = 0; column < AES_BLOCKBYTES; column += 4) {
        uint8_t first = state[column];
        uint8_t combined = (uint8_t)(state[column] ^ state[column + 1] ^
                                     state[column + 2] ^ state[column + 3]);

        state[column] ^= (uint8_t)(combined ^
                                   xtime((uint8_t)(state[column] ^
                                                   state[column + 1])));
        state[column + 1] ^=
            (uint8_t)(combined ^ xtime((uint8_t)(state[column + 1] ^
                                                  state[column + 2])));
        state[column + 2] ^=
            (uint8_t)(combined ^ xtime((uint8_t)(state[column + 2] ^
                                                  state[column + 3])));
        state[column + 3] ^=
            (uint8_t)(combined ^ xtime((uint8_t)(state[column + 3] ^ first)));
    }
}

static void aes_secure_zero(void *value, size_t length) {
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- != 0) *bytes++ = 0;
}

void aes256_ecb_keyexp(aes256ctx *ctx, const uint8_t key[AES256_KEYBYTES]) {
    uint8_t temporary[4];
    size_t generated = AES256_KEYBYTES;
    uint8_t round_constant = 1;

    memcpy(ctx->round_keys, key, AES256_KEYBYTES);
    while (generated < AES256_ROUND_KEYBYTES) {
        memcpy(temporary, ctx->round_keys + generated - sizeof(temporary),
               sizeof(temporary));

        if (generated % AES256_KEYBYTES == 0) {
            uint8_t first = temporary[0];
            temporary[0] = substitute(temporary[1]);
            temporary[1] = substitute(temporary[2]);
            temporary[2] = substitute(temporary[3]);
            temporary[3] = substitute(first);
            temporary[0] ^= round_constant;
            round_constant = xtime(round_constant);
        } else if (generated % AES256_KEYBYTES == 16) {
            for (size_t index = 0; index < sizeof(temporary); ++index) {
                temporary[index] = substitute(temporary[index]);
            }
        }

        for (size_t index = 0;
             index < sizeof(temporary) && generated < AES256_ROUND_KEYBYTES;
             ++index, ++generated) {
            ctx->round_keys[generated] =
                (uint8_t)(ctx->round_keys[generated - AES256_KEYBYTES] ^
                          temporary[index]);
        }
    }
    aes_secure_zero(temporary, sizeof(temporary));
}

static void encrypt_block(uint8_t output[AES_BLOCKBYTES],
                          const uint8_t input[AES_BLOCKBYTES],
                          const aes256ctx *ctx) {
    uint8_t state[AES_BLOCKBYTES];

    memcpy(state, input, sizeof(state));
    add_round_key(state, ctx->round_keys);
    for (size_t round = 1; round < AES256_ROUNDS; ++round) {
        substitute_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->round_keys + round * AES_BLOCKBYTES);
    }
    substitute_bytes(state);
    shift_rows(state);
    add_round_key(state,
                  ctx->round_keys + AES256_ROUNDS * AES_BLOCKBYTES);
    memcpy(output, state, sizeof(state));
    aes_secure_zero(state, sizeof(state));
}

void aes256_ecb(uint8_t *output, const uint8_t *input, size_t blocks,
                const aes256ctx *ctx) {
    for (size_t block = 0; block < blocks; ++block) {
        encrypt_block(output + block * AES_BLOCKBYTES,
                      input + block * AES_BLOCKBYTES, ctx);
    }
}

void aes256_ctx_release(aes256ctx *ctx) {
    aes_secure_zero(ctx, sizeof(*ctx));
}
