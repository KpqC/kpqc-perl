# Third-party notices

This package includes code from the following upstream reference
implementations:

- [AIMer](https://github.com/samsungsds-opensource/AIMer/tree/734cc76fa4695ca8c8eaa070508db8ff62205e68), Copyright (c) 2022–2026 SAMSUNG SDS
- [HAETAE](https://github.com/CryptoLabInc/HAETAE/tree/743c31df48183fc8c8a39a4f50a634da1c4af03a), Copyright (c) 2026 Team HAETAE
- [NTRU+](https://github.com/ntruplus/ntruplus/tree/3991b2ae08d6f0008d37e41b8aceaaab27b4ec89), Copyright (c) 2024–2026 NTRU+ TEAM
- [SMAUG-T](https://github.com/CryptoLabInc/SMAUG-T/tree/bbc463cd788eae36c6d155cef667ac9dbd9054cd), Copyright (c) 2026 Team SMAUG-T

These components are distributed under the MIT License. Their original license
texts are included under `native/third_party/`.

## Local portability changes

The bundled SMAUG-T sources use unsigned intermediate arithmetic in
`native/third_party/SMAUG-T/src/dg.c`,
`native/third_party/SMAUG-T/src/indcpa.c`, and
`native/third_party/SMAUG-T/src/poly.c` to preserve the reference
implementation's 16-bit results without relying on undefined signed left
shifts. All SMAUG-T and TiMER outputs remain byte-for-byte validated against
the referenced known-answer test vectors. The SMAUG-T fixed-weight sampler
also uses size-correct loop indices to avoid signed/unsigned comparison
warnings without changing algorithm outputs.
