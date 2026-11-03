use 5.020;
use strict;
use warnings;

use Test::More;
use Crypt::KpqC qw(:all);

sub dies (&) {
    my ($operation) = @_;
    local $@;
    eval { $operation->() };
    return length($@) > 0;
}

sub tamper {
    my ($value) = @_;
    return chr((ord(substr($value, 0, 1)) + 1) % 256) . substr($value, 1);
}

is($Crypt::KpqC::VERSION, '0.1.0', 'version');

my @signatures = signature_algorithms();
my @kems = kem_algorithms();
is(scalar @signatures, 9, 'nine signature parameter sets');
is(scalar @kems, 7, 'seven KEM parameter sets');
is(aimer128f->id, 'aimer-128f', 'AIMer identifier');
is(ntruplus768->id, 'NTRU+768', 'NTRU+ identifier');
is(aimer128f->type, 'signature', 'signature type');
is(ntruplus768->type, 'kem', 'KEM type');
ok(dies { aimer128f->{type} = 'kem' }, 'algorithm objects are immutable');
is_deeply(
    haetae5->sizes,
    { public_key => 2_080, secret_key => 2_752, signature => 2_948 },
    'HAETAE mode 5 sizes',
);
is_deeply(
    timer->sizes,
    {
        public_key   => 672,
        secret_key   => 832,
        ciphertext   => 608,
        shared_secret => 32,
    },
    'TiMER sizes',
);

my $message = 'release-manifest:v3';
my $context = 'kpqc-perl';

for my $algorithm (@signatures) {
    my $sizes = $algorithm->sizes;
    my $keys = $algorithm->generate_key_pair;
    is(length($keys->{public_key}), $sizes->{public_key}, $algorithm->id . ' public key size');
    is(length($keys->{secret_key}), $sizes->{secret_key}, $algorithm->id . ' secret key size');

    my $signature = $algorithm->sign($message, $keys->{secret_key}, $context);
    is(length($signature), $sizes->{signature}, $algorithm->id . ' signature size');
    ok($algorithm->verify($message, $signature, $keys->{public_key}, $context),
       $algorithm->id . ' verifies');
    ok(!$algorithm->verify($message, $signature, $keys->{public_key}),
       $algorithm->id . ' rejects a different context');
    ok(!$algorithm->verify($message, tamper($signature), $keys->{public_key}, $context),
       $algorithm->id . ' rejects a changed signature');
    ok(!$algorithm->verify($message, '', $keys->{public_key}, $context),
       $algorithm->id . ' rejects a malformed signature');
}

{
    my $algorithm = aimer128f;
    my $keys = $algorithm->generate_key_pair;
    ok(dies { $algorithm->sign($message, '') }, 'sign rejects a malformed secret key');
    ok(dies { $algorithm->verify($message, "\0" x $algorithm->sizes->{signature}, '') },
       'verify rejects a malformed public key');
    ok(dies { $algorithm->sign($message, $keys->{secret_key}, 'x' x 256) },
       'sign rejects a context longer than 255 bytes');

    my $empty_signature = $algorithm->sign('', $keys->{secret_key});
    ok($algorithm->verify('', $empty_signature, $keys->{public_key}),
       'empty message and context are supported');

    my $maximum_context = 'x' x 255;
    my $signature = $algorithm->sign($message, $keys->{secret_key}, $maximum_context);
    ok($algorithm->verify($message, $signature, $keys->{public_key}, $maximum_context),
       '255-byte context is supported');
}

for my $algorithm (@kems) {
    my $sizes = $algorithm->sizes;
    my $keys = $algorithm->generate_key_pair;
    is(length($keys->{public_key}), $sizes->{public_key}, $algorithm->id . ' public key size');
    is(length($keys->{secret_key}), $sizes->{secret_key}, $algorithm->id . ' secret key size');

    my $outbound = $algorithm->encapsulate($keys->{public_key});
    is(length($outbound->{ciphertext}), $sizes->{ciphertext}, $algorithm->id . ' ciphertext size');
    is(length($outbound->{shared_secret}), $sizes->{shared_secret}, $algorithm->id . ' shared secret size');
    is($algorithm->decapsulate($outbound->{ciphertext}, $keys->{secret_key}),
       $outbound->{shared_secret}, $algorithm->id . ' decapsulates');
}

{
    my $algorithm = ntruplus768;
    my $keys = $algorithm->generate_key_pair;
    ok(dies { $algorithm->encapsulate('') }, 'encapsulate rejects a malformed public key');
    ok(dies { $algorithm->decapsulate('', $keys->{secret_key}) },
       'decapsulate rejects a malformed ciphertext');
    ok(dies { $algorithm->decapsulate("\0" x $algorithm->sizes->{ciphertext}, '') },
       'decapsulate rejects a malformed secret key');
}

for my $algorithm (ntruplus768, ntruplus864, ntruplus1152) {
    my $keys = $algorithm->generate_key_pair;
    my $outbound = $algorithm->encapsulate($keys->{public_key});
    ok(dies { $algorithm->decapsulate(tamper($outbound->{ciphertext}), $keys->{secret_key}) },
       $algorithm->id . ' rejects an invalid ciphertext');
    ok(dies { $algorithm->encapsulate("\xff" x $algorithm->sizes->{public_key}) },
       $algorithm->id . ' rejects a non-canonical public key');
}

for my $algorithm (smaugt128, smaugt192, smaugt256, timer) {
    my $keys = $algorithm->generate_key_pair;
    my $outbound = $algorithm->encapsulate($keys->{public_key});
    my $replacement = $algorithm->decapsulate(
        tamper($outbound->{ciphertext}), $keys->{secret_key}
    );
    is(length($replacement), $algorithm->sizes->{shared_secret},
       $algorithm->id . ' implicit-rejection secret size');
    isnt($replacement, $outbound->{shared_secret},
         $algorithm->id . ' implicit rejection changes the secret');
}

ok(dies { aimer128f->encapsulate('') }, 'signature algorithm rejects KEM operation');
ok(dies { ntruplus768->sign('', '') }, 'KEM algorithm rejects signature operation');
done_testing;
