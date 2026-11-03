# KpqC

KpqC provides synchronous Perl APIs for the AIMer and HAETAE signature
schemes and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs). This
Perl package is independently maintained and is not an official distribution
from the algorithm authors.

## Requirements

- Perl 5.20 or newer
- A C11 compiler
- macOS or Linux

The distribution bundles its native algorithm sources and compiles them
locally. It does not download native libraries during installation.

## Install

From CPAN:

```sh
cpanm KpqC
```

The same API is also available through the `Crypt::KpqC` namespace.

From a source checkout:

```sh
perl Makefile.PL
make
make test
make install
```

## Available schemes

| Algorithm | Type | Constructors |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f`, `aimer128s`, `aimer192f`, `aimer192s`, `aimer256f`, `aimer256s` |
| **HAETAE** | Signature | `haetae2`, `haetae3`, `haetae5` |
| **NTRU+** | KEM | `ntruplus768`, `ntruplus864`, `ntruplus1152` |
| **SMAUG&#8209;T** | KEM | `smaugt128`, `smaugt192`, `smaugt256`, `timer` |

### Signatures

```perl
use KpqC qw(aimer128f);

my $algorithm = aimer128f;
my $keys = $algorithm->generate_key_pair;
my $message = 'release-manifest:v3';
my $signature = $algorithm->sign($message, $keys->{secret_key});

die 'invalid signature' unless $algorithm->verify(
    $message, $signature, $keys->{public_key}
);
```

`sign` and `verify` accept an optional domain-separation context containing at
most 255 bytes. Verification returns false when the supplied context differs
from the signing context.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain
private.

```perl
use KpqC qw(smaugt192);

my $algorithm = smaugt192;
my $recipient = $algorithm->generate_key_pair;
my $outbound = $algorithm->encapsulate($recipient->{public_key});
my $inbound = $algorithm->decapsulate(
    $outbound->{ciphertext}, $recipient->{secret_key}
);

die 'shared-secret mismatch' unless $inbound eq $outbound->{shared_secret};
```

## Data and failures

Keys, signatures, ciphertexts, shared secrets, messages, and contexts are Perl
byte strings. Invalid input sizes and excessive context lengths raise
exceptions; invalid signatures return false.

NTRU+ rejects non-canonical public keys and invalid ciphertexts. SMAUG-T uses
implicit rejection and returns a replacement secret for an invalid ciphertext;
it will not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Constructor | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `aimer128f` | 32 | 48 | 6,944 |
| `aimer128s` | 32 | 48 | 4,704 |
| `aimer192f` | 48 | 72 | 15,408 |
| `aimer192s` | 48 | 72 | 10,320 |
| `aimer256f` | 64 | 96 | 31,360 |
| `aimer256s` | 64 | 96 | 20,224 |
| `haetae2` | 992 | 1,408 | 1,474 |
| `haetae3` | 1,472 | 2,112 | 2,349 |
| `haetae5` | 2,080 | 2,752 | 2,948 |

#### KEMs

| Constructor | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `ntruplus768` | 1,152 | 2,336 | 1,152 | 32 |
| `ntruplus864` | 1,296 | 2,624 | 1,296 | 32 |
| `ntruplus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `smaugt128` | 672 | 832 | 672 | 32 |
| `smaugt192` | 1,088 | 1,312 | 992 | 32 |
| `smaugt256` | 1,440 | 1,728 | 1,376 | 32 |
| `timer` | 672 | 832 | 608 | 32 |

The same values are available through each algorithm object's `sizes` method.
`signature_algorithms` and `kem_algorithms` list every supported parameter set.

## Tests

```sh
perl Makefile.PL
make
make test
```

The optional known-answer suite validates all 1,600 records from the pinned
[`kpqc-test-vectors` revision `d75490bf824f`](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da):

```sh
make clean
KPQC_KAT=1 perl Makefile.PL
make
KPQC_KAT=1 KPQC_TEST_VECTORS=../kpqc-test-vectors make test
```

Deterministic entropy hooks are enabled only when `KPQC_KAT=1` is set during
configuration and are inactive in normal builds.

## Security

The native cores are compiled from the upstream reference implementations.
This package has not received an independent security audit and does not
guarantee constant-time execution. Perl may copy byte strings internally, so
callers must not assume that every in-memory copy of a secret can be reliably
scrubbed. Assess these constraints before using the package with sensitive
production keys.

Algorithm encodings and parameter sizes follow the exact upstream revisions
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and may differ from
other revisions of the same algorithms.
