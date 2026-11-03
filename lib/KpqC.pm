package KpqC;

use 5.020;
use strict;
use warnings;

use Crypt::KpqC ();
use Exporter qw(import);

our $VERSION = '0.1.1';

our @EXPORT_OK = @Crypt::KpqC::EXPORT_OK;
our %EXPORT_TAGS = (all => \@EXPORT_OK);

{
    no strict 'refs';
    for my $name (@EXPORT_OK) {
        *{"KpqC::$name"} = \&{"Crypt::KpqC::$name"};
    }
}

1;

__END__

=head1 NAME

KpqC - Perl APIs for KpqC post-quantum algorithms

=head1 SYNOPSIS

    use KpqC qw(aimer128f smaugt192);

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

KpqC provides synchronous Perl APIs for the AIMer and HAETAE signature schemes
and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs). The distribution
compiles the bundled native algorithm sources during installation and does not
download native libraries.

Nothing is exported by default. Import individual constructor names or use the
C<:all> tag. C<signature_algorithms> and C<kem_algorithms> return the supported
algorithm objects. See L<Crypt::KpqC> for the complete API documentation.

This package is independently maintained and is not an official distribution
from the algorithm authors.

=head1 ALTERNATE NAMESPACE

The same public API is available through L<Crypt::KpqC>. Both namespaces are
provided by the same distribution and use the same native implementation.

=head1 LICENSE

The Perl integration code is licensed under the MIT License. Bundled algorithm
sources retain their respective notices; see F<THIRD_PARTY_NOTICES.md>.

=head1 AUTHOR

Owen Suolfou E<lt>osuolfou@gmail.comE<gt>

=cut
