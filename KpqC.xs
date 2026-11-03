#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdint.h>
#include <stddef.h>

#if defined(KPQC_TEST_ENTROPY)
#include "native/aes.h"
#endif

typedef int (*signature_keypair_fn)(uint8_t *, uint8_t *);
typedef int (*signature_sign_fn)(uint8_t *, uint64_t *, const uint8_t *,
                                 size_t, const uint8_t *, size_t,
                                 const uint8_t *);
typedef int (*signature_verify_fn)(const uint8_t *, size_t, const uint8_t *,
                                   size_t, const uint8_t *, size_t,
                                   const uint8_t *);
typedef int (*kem_keypair_fn)(uint8_t *, uint8_t *);
typedef int (*kem_encapsulate_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*kem_decapsulate_fn)(uint8_t *, const uint8_t *,
                                  const uint8_t *);

#if defined(KPQC_TEST_ENTROPY)
typedef int (*set_test_entropy_fn)(const uint8_t *, size_t);
typedef size_t (*test_entropy_remaining_fn)(void);
typedef void (*clear_test_entropy_fn)(void);
#endif

#define DECLARE_SIGNATURE(prefix)                                             \
    extern int prefix##_keypair(uint8_t *, uint8_t *);                       \
    extern int prefix##_sign(uint8_t *, uint64_t *, const uint8_t *, size_t, \
                             const uint8_t *, size_t, const uint8_t *);       \
    extern int prefix##_verify(const uint8_t *, size_t, const uint8_t *,     \
                               size_t, const uint8_t *, size_t,              \
                               const uint8_t *);

#define DECLARE_KEM(prefix)                                                   \
    extern int prefix##_keypair(uint8_t *, uint8_t *);                       \
    extern int prefix##_encapsulate(uint8_t *, uint8_t *, const uint8_t *); \
    extern int prefix##_decapsulate(uint8_t *, const uint8_t *,             \
                                    const uint8_t *);

#if defined(KPQC_TEST_ENTROPY)
#define DECLARE_TEST_ENTROPY(prefix)                                         \
    extern int prefix##_set_test_entropy(const uint8_t *, size_t);           \
    extern size_t prefix##_test_entropy_remaining(void);                     \
    extern void prefix##_clear_test_entropy(void);
#else
#define DECLARE_TEST_ENTROPY(prefix)
#endif

#define DECLARE_SIGNATURE_ALGORITHM(prefix) \
    DECLARE_SIGNATURE(prefix)               \
    DECLARE_TEST_ENTROPY(prefix)

#define DECLARE_KEM_ALGORITHM(prefix) \
    DECLARE_KEM(prefix)               \
    DECLARE_TEST_ENTROPY(prefix)

DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer128f)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer128s)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer192f)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer192s)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer256f)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer256s)
DECLARE_SIGNATURE_ALGORITHM(kpqc_haetae2)
DECLARE_SIGNATURE_ALGORITHM(kpqc_haetae3)
DECLARE_SIGNATURE_ALGORITHM(kpqc_haetae5)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus768)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus864)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus1152)
DECLARE_KEM_ALGORITHM(kpqc_smaugt128)
DECLARE_KEM_ALGORITHM(kpqc_smaugt192)
DECLARE_KEM_ALGORITHM(kpqc_smaugt256)
DECLARE_KEM_ALGORITHM(kpqc_timer)

typedef struct {
    size_t public_key_size;
    size_t secret_key_size;
    size_t signature_size;
    signature_keypair_fn keypair;
    signature_sign_fn sign;
    signature_verify_fn verify;
} signature_algorithm;

typedef struct {
    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
    kem_keypair_fn keypair;
    kem_encapsulate_fn encapsulate;
    kem_decapsulate_fn decapsulate;
} kem_algorithm;

#define SIGNATURE_ALGORITHM(prefix, public_size, secret_size, signature_size) \
    {                                                                         \
        public_size, secret_size, signature_size, prefix##_keypair,           \
            prefix##_sign, prefix##_verify                                   \
    }

#define KEM_ALGORITHM(prefix, public_size, secret_size, ciphertext_size,     \
                      shared_size)                                           \
    {                                                                         \
        public_size, secret_size, ciphertext_size, shared_size,              \
            prefix##_keypair, prefix##_encapsulate, prefix##_decapsulate     \
    }

static const signature_algorithm signature_algorithms[] = {
    SIGNATURE_ALGORITHM(kpqc_aimer128f, 32, 48, 6944),
    SIGNATURE_ALGORITHM(kpqc_aimer128s, 32, 48, 4704),
    SIGNATURE_ALGORITHM(kpqc_aimer192f, 48, 72, 15408),
    SIGNATURE_ALGORITHM(kpqc_aimer192s, 48, 72, 10320),
    SIGNATURE_ALGORITHM(kpqc_aimer256f, 64, 96, 31360),
    SIGNATURE_ALGORITHM(kpqc_aimer256s, 64, 96, 20224),
    SIGNATURE_ALGORITHM(kpqc_haetae2, 992, 1408, 1474),
    SIGNATURE_ALGORITHM(kpqc_haetae3, 1472, 2112, 2349),
    SIGNATURE_ALGORITHM(kpqc_haetae5, 2080, 2752, 2948),
};

static const kem_algorithm kem_algorithms[] = {
    KEM_ALGORITHM(kpqc_ntruplus768, 1152, 2336, 1152, 32),
    KEM_ALGORITHM(kpqc_ntruplus864, 1296, 2624, 1296, 32),
    KEM_ALGORITHM(kpqc_ntruplus1152, 1728, 3488, 1728, 32),
    KEM_ALGORITHM(kpqc_smaugt128, 672, 832, 672, 32),
    KEM_ALGORITHM(kpqc_smaugt192, 1088, 1312, 992, 32),
    KEM_ALGORITHM(kpqc_smaugt256, 1440, 1728, 1376, 32),
    KEM_ALGORITHM(kpqc_timer, 672, 832, 608, 32),
};

#define SIGNATURE_COUNT \
    (sizeof(signature_algorithms) / sizeof(signature_algorithms[0]))
#define KEM_COUNT (sizeof(kem_algorithms) / sizeof(kem_algorithms[0]))

static const uint8_t empty_bytes[1] = {0};

static void secure_clear(void *pointer, size_t size) {
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    while (size-- != 0) *bytes++ = 0;
}

static const signature_algorithm *get_signature_algorithm(int index) {
    if (index < 0 || (size_t)index >= SIGNATURE_COUNT) {
        croak("invalid signature algorithm");
    }
    return &signature_algorithms[index];
}

static const kem_algorithm *get_kem_algorithm(int index) {
    if (index < 0 || (size_t)index >= KEM_COUNT) {
        croak("invalid KEM algorithm");
    }
    return &kem_algorithms[index];
}

static const uint8_t *get_bytes(SV *value, STRLEN *length,
                                const char *label) {
    if (!SvOK(value)) croak("%s must be a byte string", label);
    return (const uint8_t *)SvPVbyte(value, *length);
}

static const uint8_t *get_sized_bytes(SV *value, size_t expected,
                                      const char *label) {
    STRLEN length = 0;
    const uint8_t *bytes = get_bytes(value, &length, label);
    if ((size_t)length != expected) {
        croak("%s must contain %lu bytes, received %lu", label,
              (unsigned long)expected, (unsigned long)length);
    }
    return bytes;
}

#if defined(KPQC_TEST_ENTROPY)
typedef struct {
    set_test_entropy_fn set;
    test_entropy_remaining_fn remaining;
    clear_test_entropy_fn clear;
} test_entropy_functions;

#define TEST_ENTROPY_FUNCTIONS(prefix)                                       \
    {                                                                         \
        prefix##_set_test_entropy, prefix##_test_entropy_remaining,          \
            prefix##_clear_test_entropy                                      \
    }

static const test_entropy_functions test_entropy_algorithms[] = {
    TEST_ENTROPY_FUNCTIONS(kpqc_aimer128f),
    TEST_ENTROPY_FUNCTIONS(kpqc_aimer128s),
    TEST_ENTROPY_FUNCTIONS(kpqc_aimer192f),
    TEST_ENTROPY_FUNCTIONS(kpqc_aimer192s),
    TEST_ENTROPY_FUNCTIONS(kpqc_aimer256f),
    TEST_ENTROPY_FUNCTIONS(kpqc_aimer256s),
    TEST_ENTROPY_FUNCTIONS(kpqc_haetae2),
    TEST_ENTROPY_FUNCTIONS(kpqc_haetae3),
    TEST_ENTROPY_FUNCTIONS(kpqc_haetae5),
    TEST_ENTROPY_FUNCTIONS(kpqc_ntruplus768),
    TEST_ENTROPY_FUNCTIONS(kpqc_ntruplus864),
    TEST_ENTROPY_FUNCTIONS(kpqc_ntruplus1152),
    TEST_ENTROPY_FUNCTIONS(kpqc_smaugt128),
    TEST_ENTROPY_FUNCTIONS(kpqc_smaugt192),
    TEST_ENTROPY_FUNCTIONS(kpqc_smaugt256),
    TEST_ENTROPY_FUNCTIONS(kpqc_timer),
};

static const test_entropy_functions *get_test_entropy(int index) {
    if (index < 0 ||
        (size_t)index >= sizeof(test_entropy_algorithms) /
                             sizeof(test_entropy_algorithms[0])) {
        croak("invalid algorithm");
    }
    return &test_entropy_algorithms[index];
}
#endif

MODULE = Crypt::KpqC    PACKAGE = Crypt::KpqC

PROTOTYPES: DISABLE

void
_signature_generate_key_pair(index)
    int index
PREINIT:
    const signature_algorithm *algorithm;
    uint8_t *public_key;
    uint8_t *secret_key;
    int status;
PPCODE:
    algorithm = get_signature_algorithm(index);
    Newx(public_key, algorithm->public_key_size, uint8_t);
    Newx(secret_key, algorithm->secret_key_size, uint8_t);
    status = algorithm->keypair(public_key, secret_key);
    if (status != 0) {
        secure_clear(secret_key, algorithm->secret_key_size);
        Safefree(secret_key);
        Safefree(public_key);
        croak("KpqC key generation failed with status %d", status);
    }
    EXTEND(SP, 2);
    PUSHs(sv_2mortal(newSVpvn((const char *)public_key,
                              algorithm->public_key_size)));
    PUSHs(sv_2mortal(newSVpvn((const char *)secret_key,
                              algorithm->secret_key_size)));
    secure_clear(secret_key, algorithm->secret_key_size);
    Safefree(secret_key);
    Safefree(public_key);

SV *
_signature_sign(index, message_value, secret_key_value, context_value)
    int index
    SV *message_value
    SV *secret_key_value
    SV *context_value
PREINIT:
    const signature_algorithm *algorithm;
    const uint8_t *message;
    const uint8_t *secret_key;
    const uint8_t *context;
    STRLEN message_size = 0;
    STRLEN context_size = 0;
    uint8_t *signature;
    uint64_t actual_size = 0;
    int status;
CODE:
    algorithm = get_signature_algorithm(index);
    message = get_bytes(message_value, &message_size, "message");
    secret_key = get_sized_bytes(secret_key_value, algorithm->secret_key_size,
                                 "secret_key");
    if (SvOK(context_value)) {
        context = get_bytes(context_value, &context_size, "context");
    } else {
        context = empty_bytes;
    }
    if (context_size > 255) croak("context must not exceed 255 bytes");
    Newx(signature, algorithm->signature_size, uint8_t);
    status = algorithm->sign(signature, &actual_size, message,
                             (size_t)message_size, context,
                             (size_t)context_size, secret_key);
    if (status != 0 || actual_size != algorithm->signature_size) {
        secure_clear(signature, algorithm->signature_size);
        Safefree(signature);
        if (status != 0) {
            croak("KpqC signing failed with status %d", status);
        }
        croak("KpqC signing returned an unexpected signature length");
    }
    RETVAL = newSVpvn((const char *)signature, algorithm->signature_size);
    secure_clear(signature, algorithm->signature_size);
    Safefree(signature);
OUTPUT:
    RETVAL

int
_signature_verify(index, message_value, signature_value, public_key_value, context_value)
    int index
    SV *message_value
    SV *signature_value
    SV *public_key_value
    SV *context_value
PREINIT:
    const signature_algorithm *algorithm;
    const uint8_t *message;
    const uint8_t *signature;
    const uint8_t *public_key;
    const uint8_t *context;
    STRLEN message_size = 0;
    STRLEN signature_size = 0;
    STRLEN context_size = 0;
CODE:
    algorithm = get_signature_algorithm(index);
    message = get_bytes(message_value, &message_size, "message");
    signature = get_bytes(signature_value, &signature_size, "signature");
    public_key = get_sized_bytes(public_key_value, algorithm->public_key_size,
                                 "public_key");
    if (SvOK(context_value)) {
        context = get_bytes(context_value, &context_size, "context");
    } else {
        context = empty_bytes;
    }
    if (context_size > 255) croak("context must not exceed 255 bytes");
    if ((size_t)signature_size != algorithm->signature_size) {
        RETVAL = 0;
    } else {
        RETVAL = algorithm->verify(signature, (size_t)signature_size, message,
                                   (size_t)message_size, context,
                                   (size_t)context_size, public_key) == 0;
    }
OUTPUT:
    RETVAL

void
_kem_generate_key_pair(index)
    int index
PREINIT:
    const kem_algorithm *algorithm;
    uint8_t *public_key;
    uint8_t *secret_key;
    int status;
PPCODE:
    algorithm = get_kem_algorithm(index);
    Newx(public_key, algorithm->public_key_size, uint8_t);
    Newx(secret_key, algorithm->secret_key_size, uint8_t);
    status = algorithm->keypair(public_key, secret_key);
    if (status != 0) {
        secure_clear(secret_key, algorithm->secret_key_size);
        Safefree(secret_key);
        Safefree(public_key);
        croak("KpqC key generation failed with status %d", status);
    }
    EXTEND(SP, 2);
    PUSHs(sv_2mortal(newSVpvn((const char *)public_key,
                              algorithm->public_key_size)));
    PUSHs(sv_2mortal(newSVpvn((const char *)secret_key,
                              algorithm->secret_key_size)));
    secure_clear(secret_key, algorithm->secret_key_size);
    Safefree(secret_key);
    Safefree(public_key);

void
_kem_encapsulate(index, public_key_value)
    int index
    SV *public_key_value
PREINIT:
    const kem_algorithm *algorithm;
    const uint8_t *public_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    int status;
PPCODE:
    algorithm = get_kem_algorithm(index);
    public_key = get_sized_bytes(public_key_value, algorithm->public_key_size,
                                 "public_key");
    Newx(ciphertext, algorithm->ciphertext_size, uint8_t);
    Newx(shared_secret, algorithm->shared_secret_size, uint8_t);
    status = algorithm->encapsulate(ciphertext, shared_secret, public_key);
    if (status != 0) {
        secure_clear(shared_secret, algorithm->shared_secret_size);
        Safefree(shared_secret);
        Safefree(ciphertext);
        croak("KpqC encapsulation failed with status %d", status);
    }
    EXTEND(SP, 2);
    PUSHs(sv_2mortal(newSVpvn((const char *)ciphertext,
                              algorithm->ciphertext_size)));
    PUSHs(sv_2mortal(newSVpvn((const char *)shared_secret,
                              algorithm->shared_secret_size)));
    secure_clear(shared_secret, algorithm->shared_secret_size);
    Safefree(shared_secret);
    Safefree(ciphertext);

SV *
_kem_decapsulate(index, ciphertext_value, secret_key_value)
    int index
    SV *ciphertext_value
    SV *secret_key_value
PREINIT:
    const kem_algorithm *algorithm;
    const uint8_t *ciphertext;
    const uint8_t *secret_key;
    uint8_t *shared_secret;
    int status;
CODE:
    algorithm = get_kem_algorithm(index);
    ciphertext = get_sized_bytes(ciphertext_value, algorithm->ciphertext_size,
                                 "ciphertext");
    secret_key = get_sized_bytes(secret_key_value, algorithm->secret_key_size,
                                 "secret_key");
    Newx(shared_secret, algorithm->shared_secret_size, uint8_t);
    status = algorithm->decapsulate(shared_secret, ciphertext, secret_key);
    if (status != 0) {
        secure_clear(shared_secret, algorithm->shared_secret_size);
        Safefree(shared_secret);
        croak("KpqC decapsulation failed with status %d", status);
    }
    RETVAL = newSVpvn((const char *)shared_secret,
                      algorithm->shared_secret_size);
    secure_clear(shared_secret, algorithm->shared_secret_size);
    Safefree(shared_secret);
OUTPUT:
    RETVAL

int
_kat_enabled()
CODE:
#if defined(KPQC_TEST_ENTROPY)
    RETVAL = 1;
#else
    RETVAL = 0;
#endif
OUTPUT:
    RETVAL

void
_set_test_entropy(index, entropy_value)
    int index
    SV *entropy_value
PREINIT:
#if defined(KPQC_TEST_ENTROPY)
    const test_entropy_functions *functions;
    const uint8_t *entropy;
    STRLEN entropy_size = 0;
    int status;
#endif
CODE:
#if defined(KPQC_TEST_ENTROPY)
    functions = get_test_entropy(index);
    entropy = get_bytes(entropy_value, &entropy_size, "entropy");
    status = functions->set(entropy, (size_t)entropy_size);
    if (status != 0) croak("KpqC test entropy failed with status %d", status);
#else
    (void)index;
    (void)entropy_value;
    croak("deterministic entropy hooks are not enabled");
#endif

UV
_test_entropy_remaining(index)
    int index
CODE:
#if defined(KPQC_TEST_ENTROPY)
    RETVAL = (UV)get_test_entropy(index)->remaining();
#else
    (void)index;
    croak("deterministic entropy hooks are not enabled");
    RETVAL = 0;
#endif
OUTPUT:
    RETVAL

void
_clear_test_entropy(index)
    int index
CODE:
#if defined(KPQC_TEST_ENTROPY)
    get_test_entropy(index)->clear();
#else
    (void)index;
    croak("deterministic entropy hooks are not enabled");
#endif

SV *
_aes256_ecb(key_value, input_value)
    SV *key_value
    SV *input_value
PREINIT:
#if defined(KPQC_TEST_ENTROPY)
    const uint8_t *key;
    const uint8_t *input;
    uint8_t output[16];
    aes256ctx context;
#endif
CODE:
#if defined(KPQC_TEST_ENTROPY)
    key = get_sized_bytes(key_value, 32, "key");
    input = get_sized_bytes(input_value, 16, "input");
    aes256_ecb_keyexp(&context, key);
    aes256_ecb(output, input, 1, &context);
    aes256_ctx_release(&context);
    RETVAL = newSVpvn((const char *)output, sizeof(output));
    secure_clear(output, sizeof(output));
#else
    (void)key_value;
    (void)input_value;
    croak("deterministic entropy hooks are not enabled");
    RETVAL = &PL_sv_undef;
#endif
OUTPUT:
    RETVAL
