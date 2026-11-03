package Crypt::KpqC;

use 5.020;
use strict;
use warnings;

use Exporter qw(import);
use Hash::Util qw(lock_hashref);
use XSLoader ();

our $VERSION = '0.1.0';

our @EXPORT_OK = qw(
    aimer128f aimer128s aimer192f aimer192s aimer256f aimer256s
    haetae2 haetae3 haetae5
    ntruplus768 ntruplus864 ntruplus1152
    smaugt128 smaugt192 smaugt256 timer
    signature_algorithms kem_algorithms
);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

XSLoader::load(__PACKAGE__, $VERSION);

sub _algorithm {
    my ($code, $test_code, $id, $type) = @_;
    my $algorithm = bless {
        code      => $code,
        test_code => $test_code,
        id        => $id,
        type      => $type,
    }, 'Crypt::KpqC::Algorithm';
    lock_hashref($algorithm);
    return $algorithm;
}

my @SIGNATURE_SIZES = (
    [32, 48, 6_944],
    [32, 48, 4_704],
    [48, 72, 15_408],
    [48, 72, 10_320],
    [64, 96, 31_360],
    [64, 96, 20_224],
    [992, 1_408, 1_474],
    [1_472, 2_112, 2_349],
    [2_080, 2_752, 2_948],
);

my @KEM_SIZES = (
    [1_152, 2_336, 1_152, 32],
    [1_296, 2_624, 1_296, 32],
    [1_728, 3_488, 1_728, 32],
    [672, 832, 672, 32],
    [1_088, 1_312, 992, 32],
    [1_440, 1_728, 1_376, 32],
    [672, 832, 608, 32],
);

my @SIGNATURE_ALGORITHMS = (
    _algorithm(0, 0, 'aimer-128f',   'signature'),
    _algorithm(1, 1, 'aimer-128s',   'signature'),
    _algorithm(2, 2, 'aimer-192f',   'signature'),
    _algorithm(3, 3, 'aimer-192s',   'signature'),
    _algorithm(4, 4, 'aimer-256f',   'signature'),
    _algorithm(5, 5, 'aimer-256s',   'signature'),
    _algorithm(6, 6, 'haetae-mode2', 'signature'),
    _algorithm(7, 7, 'haetae-mode3', 'signature'),
    _algorithm(8, 8, 'haetae-mode5', 'signature'),
);

my @KEM_ALGORITHMS = (
    _algorithm(0, 9,  'NTRU+768',   'kem'),
    _algorithm(1, 10, 'NTRU+864',   'kem'),
    _algorithm(2, 11, 'NTRU+1152',  'kem'),
    _algorithm(3, 12, 'SMAUG-T128', 'kem'),
    _algorithm(4, 13, 'SMAUG-T192', 'kem'),
    _algorithm(5, 14, 'SMAUG-T256', 'kem'),
    _algorithm(6, 15, 'TiMER',      'kem'),
);

sub aimer128f   () { $SIGNATURE_ALGORITHMS[0] }
sub aimer128s   () { $SIGNATURE_ALGORITHMS[1] }
sub aimer192f   () { $SIGNATURE_ALGORITHMS[2] }
sub aimer192s   () { $SIGNATURE_ALGORITHMS[3] }
sub aimer256f   () { $SIGNATURE_ALGORITHMS[4] }
sub aimer256s   () { $SIGNATURE_ALGORITHMS[5] }
sub haetae2     () { $SIGNATURE_ALGORITHMS[6] }
sub haetae3     () { $SIGNATURE_ALGORITHMS[7] }
sub haetae5     () { $SIGNATURE_ALGORITHMS[8] }
sub ntruplus768 () { $KEM_ALGORITHMS[0] }
sub ntruplus864 () { $KEM_ALGORITHMS[1] }
sub ntruplus1152() { $KEM_ALGORITHMS[2] }
sub smaugt128   () { $KEM_ALGORITHMS[3] }
sub smaugt192   () { $KEM_ALGORITHMS[4] }
sub smaugt256   () { $KEM_ALGORITHMS[5] }
sub timer       () { $KEM_ALGORITHMS[6] }

sub signature_algorithms { return @SIGNATURE_ALGORITHMS }
sub kem_algorithms       { return @KEM_ALGORITHMS }

package Crypt::KpqC::Algorithm;

use strict;
use warnings;
use Carp qw(croak);

sub id   { return $_[0]->{id} }
sub type { return $_[0]->{type} }

sub sizes {
    my ($self) = @_;
    my @names = $self->{type} eq 'signature'
        ? qw(public_key secret_key signature)
        : qw(public_key secret_key ciphertext shared_secret);
    my $values = $self->{type} eq 'signature'
        ? $SIGNATURE_SIZES[$self->{code}]
        : $KEM_SIZES[$self->{code}];
    my %sizes;
    @sizes{@names} = @{$values};
    return \%sizes;
}

sub generate_key_pair {
    my ($self) = @_;
    my ($public_key, $secret_key) = $self->{type} eq 'signature'
        ? Crypt::KpqC::_signature_generate_key_pair($self->{code})
        : Crypt::KpqC::_kem_generate_key_pair($self->{code});
    return { public_key => $public_key, secret_key => $secret_key };
}

sub sign {
    my ($self, $message, $secret_key, $context) = @_;
    croak 'sign is available only for signature algorithms'
        unless $self->{type} eq 'signature';
    return Crypt::KpqC::_signature_sign(
        $self->{code}, $message, $secret_key, $context
    );
}

sub verify {
    my ($self, $message, $signature, $public_key, $context) = @_;
    croak 'verify is available only for signature algorithms'
        unless $self->{type} eq 'signature';
    return Crypt::KpqC::_signature_verify(
        $self->{code}, $message, $signature, $public_key, $context
    ) ? 1 : 0;
}

sub encapsulate {
    my ($self, $public_key) = @_;
    croak 'encapsulate is available only for KEM algorithms'
        unless $self->{type} eq 'kem';
    my ($ciphertext, $shared_secret) =
        Crypt::KpqC::_kem_encapsulate($self->{code}, $public_key);
    return { ciphertext => $ciphertext, shared_secret => $shared_secret };
}

sub decapsulate {
    my ($self, $ciphertext, $secret_key) = @_;
    croak 'decapsulate is available only for KEM algorithms'
        unless $self->{type} eq 'kem';
    return Crypt::KpqC::_kem_decapsulate(
        $self->{code}, $ciphertext, $secret_key
    );
}

sub _set_test_entropy {
    my ($self, $entropy) = @_;
    return Crypt::KpqC::_set_test_entropy($self->{test_code}, $entropy);
}

sub _test_entropy_remaining {
    my ($self) = @_;
    return Crypt::KpqC::_test_entropy_remaining($self->{test_code});
}

sub _clear_test_entropy {
    my ($self) = @_;
    return Crypt::KpqC::_clear_test_entropy($self->{test_code});
}

1;

__END__

=head1 NAME

Crypt::KpqC - Perl bindings for KpqC post-quantum algorithms

=head1 SYNOPSIS

    use Crypt::KpqC qw(aimer128f smaugt192);

    my $signature_algorithm = aimer128f;
    my $keys = $signature_algorithm->generate_key_pair;
    my $signature = $signature_algorithm->sign(
        'message', $keys->{secret_key}, 'application-context'
    );
    die 'invalid signature' unless $signature_algorithm->verify(
        'message', $signature, $keys->{public_key}, 'application-context'
    );

    my $kem_algorithm = smaugt192;
    my $recipient = $kem_algorithm->generate_key_pair;
    my $outbound = $kem_algorithm->encapsulate($recipient->{public_key});
    my $inbound = $kem_algorithm->decapsulate(
        $outbound->{ciphertext}, $recipient->{secret_key}
    );

=head1 DESCRIPTION

Crypt::KpqC provides synchronous Perl APIs for the AIMer and HAETAE signature
schemes and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs). The
distribution compiles the bundled native algorithm sources during installation
and does not download native libraries.

This package is independently maintained and is not an official distribution
from the algorithm authors.

=head1 ALGORITHMS

The signature constructors are C<aimer128f>, C<aimer128s>, C<aimer192f>,
C<aimer192s>, C<aimer256f>, C<aimer256s>, C<haetae2>, C<haetae3>, and
C<haetae5>. The KEM constructors are C<ntruplus768>, C<ntruplus864>,
C<ntruplus1152>, C<smaugt128>, C<smaugt192>, C<smaugt256>, and C<timer>.

C<signature_algorithms> and C<kem_algorithms> return the corresponding lists.
Nothing is exported by default; import individual names or use the C<:all> tag.

=head1 ALGORITHM OBJECTS

=head2 id

Returns the stable algorithm identifier used by the KpqC test vectors.

=head2 type

Returns C<signature> or C<kem>.

=head2 sizes

Returns a new hash reference containing the algorithm's byte sizes.

=head2 generate_key_pair

Returns a hash reference with C<public_key> and C<secret_key> byte strings.

=head2 sign

    $signature = $algorithm->sign($message, $secret_key, $context);

Signs a byte string. The optional domain-separation context may contain at most
255 bytes and defaults to the empty string.

=head2 verify

    $valid = $algorithm->verify(
        $message, $signature, $public_key, $context
    );

Returns a boolean. A malformed signature returns false; malformed keys and
contexts raise an exception.

=head2 encapsulate

Returns a hash reference with C<ciphertext> and C<shared_secret> byte strings.

=head2 decapsulate

Returns the shared-secret byte string. NTRU+ rejects an invalid ciphertext by
raising an exception. SMAUG-T uses implicit rejection and returns a replacement
secret that does not equal the sender's secret.

=head1 SECURITY

The native cores are compiled from the upstream reference implementations.
This package has not received an independent security audit and does not
guarantee constant-time execution. Perl byte strings containing secret material
may be copied by the interpreter and cannot be reliably erased by this API.
Assess these constraints before using the package with sensitive production
keys.

Algorithm encodings and parameter sizes follow the exact upstream revisions
listed in F<THIRD_PARTY_NOTICES.md> and may differ from other revisions of the
same algorithms.

=head1 LICENSE

The Perl integration code is licensed under the MIT License. Bundled algorithm
sources retain their respective notices; see F<THIRD_PARTY_NOTICES.md>.

=head1 AUTHOR

Owen Suolfou E<lt>osuolfou@gmail.comE<gt>

=cut
