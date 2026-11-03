#include "pqc_fips202.h"

/* Keep NTRU+ entry points internal to the bundled native component. */
#define NTRUPLUS_ABI_H
#define NTRUPLUS_INTERNAL
#define NTRUPLUS_EXTERNAL
#define NTRUPLUS_SYSV

#define baseinv KPQC_SYMBOL(baseinv)
#define basemul KPQC_SYMBOL(basemul)
#define basemul_add KPQC_SYMBOL(basemul_add)
#define crypto_kem_dec KPQC_SYMBOL(crypto_kem_dec)
#define crypto_kem_enc KPQC_SYMBOL(crypto_kem_enc)
#define crypto_kem_keypair KPQC_SYMBOL(crypto_kem_keypair)
#define hash_f KPQC_SYMBOL(hash_f)
#define hash_g KPQC_SYMBOL(hash_g)
#define hash_h KPQC_SYMBOL(hash_h)
#define invntt KPQC_SYMBOL(invntt)
#define ntt KPQC_SYMBOL(ntt)
#define poly_baseinv KPQC_SYMBOL(poly_baseinv)
#define poly_basemul KPQC_SYMBOL(poly_basemul)
#define poly_basemul_add KPQC_SYMBOL(poly_basemul_add)
#define poly_cbd1 KPQC_SYMBOL(poly_cbd1)
#define poly_crepmod3 KPQC_SYMBOL(poly_crepmod3)
#define poly_frombytes KPQC_SYMBOL(poly_frombytes)
#define poly_invntt KPQC_SYMBOL(poly_invntt)
#define poly_ntt KPQC_SYMBOL(poly_ntt)
#define poly_sotp_decode KPQC_SYMBOL(poly_sotp_decode)
#define poly_sotp_encode KPQC_SYMBOL(poly_sotp_encode)
#define poly_sub KPQC_SYMBOL(poly_sub)
#define poly_tobytes KPQC_SYMBOL(poly_tobytes)
#define poly_triple KPQC_SYMBOL(poly_triple)
#define zetas KPQC_SYMBOL(zetas)
#define randombytes KPQC_SYMBOL(randombytes)
