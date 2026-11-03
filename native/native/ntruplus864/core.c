#define KPQC_VARIANT ntruplus864
#include "../common/ntruplus.h"
#include "../common/randombytes.h"
#include "../../third_party/NTRUplus/NTRU+864/kem.c"
#include "../../third_party/NTRUplus/NTRU+864/ntt.c"
#include "../../third_party/NTRUplus/NTRU+864/poly.c"
#include "../../third_party/NTRUplus/NTRU+864/symmetric.c"
#include "../../third_party/NTRUplus/NTRU+864/fips202/fips202.c"
#define KPQC_NATIVE_PREFIX kpqc_ntruplus864_
#include "../common/native_kem.h"
