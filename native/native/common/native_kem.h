#include <stdint.h>

#define KPQC_JOIN_(left, right) left##right
#define KPQC_JOIN(left, right) KPQC_JOIN_(left, right)
#define KPQC_API(name) KPQC_JOIN(KPQC_NATIVE_PREFIX, name)

int KPQC_API(keypair)(uint8_t *public_key, uint8_t *secret_key) {
    return crypto_kem_keypair(public_key, secret_key);
}

int KPQC_API(encapsulate)(uint8_t *ciphertext, uint8_t *shared_secret,
                          const uint8_t *public_key) {
    return crypto_kem_enc(ciphertext, shared_secret, public_key);
}

int KPQC_API(decapsulate)(uint8_t *shared_secret, const uint8_t *ciphertext,
                          const uint8_t *secret_key) {
    return crypto_kem_dec(shared_secret, ciphertext, secret_key);
}

#if defined(KPQC_TEST_ENTROPY)
int KPQC_API(set_test_entropy)(const uint8_t *input, size_t length) {
    return kpqc_set_test_entropy(input, length);
}

size_t KPQC_API(test_entropy_remaining)(void) {
    return kpqc_test_entropy_remaining();
}

void KPQC_API(clear_test_entropy)(void) {
    kpqc_clear_test_entropy();
}
#endif
