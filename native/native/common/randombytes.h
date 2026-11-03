/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdint.h>
#if defined(KPQC_TEST_ENTROPY)
#include <string.h>
#include <stdlib.h>
#endif

#if defined(_WIN32)
#include <limits.h>
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
#include <stdlib.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <errno.h>
#include <sys/random.h>
#else
#error "kpqc supports operating-system entropy on Windows, Linux, Android, macOS, and BSD"
#endif

#if defined(KPQC_TEST_ENTROPY)
/*
 * This override is compiled only for kpqc_kat builds and is exposed through
 * internal/native. It lets the KAT tests reproduce the NIST CTR-DRBG stream
 * without changing the public API or the operating-system entropy used in
 * normal builds.
 */
static uint8_t *kpqc_test_entropy = NULL;
static size_t kpqc_test_entropy_length = 0;
static size_t kpqc_test_entropy_offset = 0;
static int kpqc_test_entropy_active = 0;

static void kpqc_clear_test_entropy(void) {
    if (kpqc_test_entropy != NULL) {
        volatile uint8_t *bytes = kpqc_test_entropy;
        for (size_t i = 0; i < kpqc_test_entropy_length; ++i) bytes[i] = 0;
        free(kpqc_test_entropy);
    }
    kpqc_test_entropy = NULL;
    kpqc_test_entropy_length = 0;
    kpqc_test_entropy_offset = 0;
    kpqc_test_entropy_active = 0;
}

static int kpqc_set_test_entropy(const uint8_t *input, size_t length) {
    kpqc_clear_test_entropy();
    if (length != 0) {
        kpqc_test_entropy = (uint8_t *)malloc(length);
        if (kpqc_test_entropy == NULL) return -1;
        memcpy(kpqc_test_entropy, input, length);
    }
    kpqc_test_entropy_length = length;
    kpqc_test_entropy_active = 1;
    return 0;
}

static size_t kpqc_test_entropy_remaining(void) {
    return kpqc_test_entropy_length - kpqc_test_entropy_offset;
}
#endif

static int kpqc_fill_random(uint8_t *output, size_t length) {
#if defined(KPQC_TEST_ENTROPY)
    if (kpqc_test_entropy_active) {
        if (length > kpqc_test_entropy_remaining()) return -1;
        if (length != 0) {
            memcpy(output, kpqc_test_entropy + kpqc_test_entropy_offset, length);
            kpqc_test_entropy_offset += length;
        }
        return 0;
    }
#endif
#if defined(_WIN32)
    while (length != 0) {
        ULONG chunk = length > (size_t)ULONG_MAX ? ULONG_MAX : (ULONG)length;
        if (BCryptGenRandom(NULL, output, chunk,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            return -1;
        }
        output += chunk;
        length -= chunk;
    }
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
    arc4random_buf(output, length);
    return 0;
#else
    while (length != 0) {
        ssize_t count = getrandom(output, length, 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        output += (size_t)count;
        length -= (size_t)count;
    }
    return 0;
#endif
}

#if defined(KPQC_AIMER)
int randombytes(unsigned char *output, unsigned long long length) {
    if (length > (unsigned long long)SIZE_MAX) return -1;
    return kpqc_fill_random(output, (size_t)length);
}
#else
int randombytes(uint8_t *output, size_t length) {
    return kpqc_fill_random(output, length);
}
#endif
