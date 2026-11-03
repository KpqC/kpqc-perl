#define KPQC_VARIANT aimer128f
#include "../common/pqc_fips202.h"
#define crypto_sign_keypair_internal KPQC_SYMBOL(crypto_sign_keypair_internal)
#define crypto_sign_signature_internal KPQC_SYMBOL(crypto_sign_signature_internal)
#define crypto_sign_verify_internal KPQC_SYMBOL(crypto_sign_verify_internal)
#define randombytes KPQC_SYMBOL(randombytes)
#define KPQC_AIMER 1
#define PARAMS 128f
#include "../common/randombytes.h"
#include "../../third_party/AIMer/aim3.c"
#include "../../third_party/AIMer/field_common.c"
#include "../../third_party/AIMer/hash.c"
#include "../../third_party/AIMer/sign.c"
#include "../../third_party/AIMer/tree.c"
#include "../../third_party/AIMer/field128.c"
#include "../../third_party/AIMer/common/fips202.c"
#define KPQC_NATIVE_PREFIX kpqc_aimer128f_
#include "../common/native_signature.h"
