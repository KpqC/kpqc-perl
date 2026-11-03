#include <stddef.h>
#include <stdint.h>

#define KPQC_JOIN_(left, right) left##right
#define KPQC_JOIN(left, right) KPQC_JOIN_(left, right)
#define KPQC_API(name) KPQC_JOIN(KPQC_NATIVE_PREFIX, name)

int KPQC_API(keypair)(uint8_t *public_key, uint8_t *secret_key) {
    return crypto_sign_keypair(public_key, secret_key);
}

int KPQC_API(sign)(uint8_t *signature, uint64_t *signature_len,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *context, size_t context_len,
                   const uint8_t *secret_key) {
    size_t length = 0;
    int status = crypto_sign_signature(signature, &length, message, message_len,
                                       context, context_len, secret_key);
    *signature_len = (uint64_t)length;
    return status;
}

int KPQC_API(verify)(const uint8_t *signature, size_t signature_len,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *context, size_t context_len,
                     const uint8_t *public_key) {
    return crypto_sign_verify(signature, signature_len, message, message_len,
                              context, context_len, public_key);
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
