#ifndef KPQC_NATIVE_PREFIX_H
#define KPQC_NATIVE_PREFIX_H

#define KPQC_PREFIXED_(variant, name) kpqc_##variant##_##name
#define KPQC_PREFIXED(variant, name) KPQC_PREFIXED_(variant, name)
#define KPQC_SYMBOL(name) KPQC_PREFIXED(KPQC_VARIANT, name)

#endif
