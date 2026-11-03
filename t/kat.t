use 5.020;
use strict;
use warnings;
use bytes;

use File::Spec;
use Test::More;
use Crypt::KpqC qw(:all);

my $vector_root = $ENV{KPQC_TEST_VECTORS};
plan skip_all => 'set KPQC_TEST_VECTORS to run known-answer tests'
    unless defined($vector_root) && length($vector_root);
plan skip_all => 'reconfigure with KPQC_KAT=1 to build deterministic entropy hooks'
    unless Crypt::KpqC::_kat_enabled();

sub vector_path {
    return File::Spec->catfile($vector_root, split(m{/}, $_[0]), 'kat.rsp');
}

sub hex_to_bytes {
    my ($value) = @_;
    die 'hex value has an odd length' if length($value) % 2;
    return pack('H*', $value);
}

sub read_vectors {
    my ($path) = @_;
    open my $handle, '<', $path or die "cannot open $path: $!";
    my @vectors;
    my %current;
    while (my $line = <$handle>) {
        chomp $line;
        next unless $line =~ /^([^=]+?)\s*=\s*(.*)$/;
        my ($name, $value) = ($1, $2);
        if ($name eq 'count' && %current) {
            push @vectors, { %current };
            %current = ();
        }
        $current{$name} = $value;
    }
    close $handle or die "cannot close $path: $!";
    push @vectors, { %current } if %current;
    return \@vectors;
}

sub field {
    my ($vector, $name) = @_;
    die "missing vector field: $name" unless exists $vector->{$name};
    return hex_to_bytes($vector->{$name});
}

sub increment_counter {
    my ($counter) = @_;
    my @octets = unpack('C*', $counter);
    for (my $index = $#octets; $index >= 0; --$index) {
        $octets[$index] = ($octets[$index] + 1) % 256;
        last if $octets[$index] != 0;
    }
    return pack('C*', @octets);
}

sub generate_blocks {
    my ($state, $count) = @_;
    my $output = '';
    for (1 .. $count) {
        $state->{counter} = increment_counter($state->{counter});
        $output .= Crypt::KpqC::_aes256_ecb($state->{key}, $state->{counter});
    }
    return $output;
}

sub update_drbg {
    my ($state, $provided) = @_;
    die 'DRBG update data must not exceed 48 bytes' if length($provided) > 48;
    my $material = generate_blocks($state, 3);
    $material ^= $provided . ("\0" x (48 - length($provided)));
    $state->{key} = substr($material, 0, 32);
    $state->{counter} = substr($material, 32, 16);
}

sub new_drbg {
    my ($seed) = @_;
    die 'CTR-DRBG seed must contain 48 bytes' unless length($seed) == 48;
    my $state = { key => "\0" x 32, counter => "\0" x 16 };
    update_drbg($state, $seed);
    return $state;
}

sub copy_drbg {
    my ($state) = @_;
    return { key => $state->{key}, counter => $state->{counter} };
}

sub generate {
    my ($state, $length) = @_;
    my $output = generate_blocks($state, int(($length + 15) / 16));
    update_drbg($state, '');
    return substr($output, 0, $length);
}

sub with_exact_entropy {
    my ($algorithm, $entropy, $operation) = @_;
    $algorithm->_set_test_entropy($entropy);
    my ($result, $error);
    eval { $result = $operation->(); 1 } or $error = $@;
    my $remaining = $algorithm->_test_entropy_remaining;
    $algorithm->_clear_test_entropy;
    die $error if defined $error;
    die "deterministic entropy has $remaining unused bytes" if $remaining != 0;
    return $result;
}

sub with_repeated_entropy {
    my ($algorithm, $state, $call_bytes, $operation) = @_;
    my $probe = copy_drbg($state);
    my $entropy = join '', map { generate($probe, $call_bytes) } 1 .. 128;

    $algorithm->_set_test_entropy($entropy);
    my ($result, $error);
    eval { $result = $operation->(); 1 } or $error = $@;
    my $consumed = length($entropy) - $algorithm->_test_entropy_remaining;
    $algorithm->_clear_test_entropy;
    die $error if defined $error;
    die 'deterministic entropy was not consumed' if $consumed == 0;
    die 'entropy consumption was not aligned' if $consumed % $call_bytes;
    generate($state, $call_bytes) for 1 .. ($consumed / $call_bytes);
    return $result;
}

my @signatures = (
    [aimer128f, 'aimer/128f', 0, 16],
    [aimer128s, 'aimer/128s', 0, 16],
    [aimer192f, 'aimer/192f', 0, 24],
    [aimer192s, 'aimer/192s', 0, 24],
    [aimer256f, 'aimer/256f', 0, 32],
    [aimer256s, 'aimer/256s', 0, 32],
    [haetae2, 'haetae/mode2', 1, 32],
    [haetae3, 'haetae/mode3', 1, 32],
    [haetae5, 'haetae/mode5', 1, 32],
);

my @kems = (
    [ntruplus768,  'ntruplus/768',  0, 96],
    [ntruplus864,  'ntruplus/864',  0, 108],
    [ntruplus1152, 'ntruplus/1152', 0, 144],
    [smaugt128,     'smaugt/mode1',  2, 32],
    [smaugt192,     'smaugt/mode3',  2, 32],
    [smaugt256,     'smaugt/mode5',  2, 32],
    [timer,         'smaugt/modet',  2, 16],
);

my $total = 0;

for my $configuration (@signatures) {
    my ($algorithm, $path, $is_haetae, $seed_bytes) = @$configuration;
    my $vectors = read_vectors(vector_path($path));
    is(scalar @$vectors, 100, "$path contains 100 vectors");

    my $count = 0;
    for my $vector (@$vectors) {
        my $state = new_drbg(field($vector, 'seed'));
        my $keys = $is_haetae
            ? with_exact_entropy(
                $algorithm, generate($state, $seed_bytes),
                sub { $algorithm->generate_key_pair },
            )
            : with_repeated_entropy(
                $algorithm, $state, $seed_bytes,
                sub { $algorithm->generate_key_pair },
            );
        die "$path public key mismatch at vector $count"
            unless $keys->{public_key} eq field($vector, 'pk');
        die "$path secret key mismatch at vector $count"
            unless $keys->{secret_key} eq field($vector, 'sk');

        my $message = field($vector, 'msg');
        my $expected_signature = exists($vector->{sig})
            ? field($vector, 'sig')
            : substr(field($vector, 'sm'), length($message));
        my $signing_entropy = generate($state, $seed_bytes);
        my $context = '';
        if ($is_haetae) {
            my $context_length = ord(generate($state, 1));
            $context = generate($state, $context_length);
        }
        my $signature = with_exact_entropy(
            $algorithm, $signing_entropy,
            sub { $algorithm->sign($message, $keys->{secret_key}, $context) },
        );
        die "$path signature mismatch at vector $count"
            unless $signature eq $expected_signature;
        die "$path signature verification failed at vector $count"
            unless $algorithm->verify(
                $message, $expected_signature, $keys->{public_key}, $context
            );
        ++$count;
    }
    pass("$path known-answer records");
    $total += scalar @$vectors;
}

for my $configuration (@kems) {
    my ($algorithm, $path, $key_calls, $encapsulation_bytes) = @$configuration;
    my $vectors = read_vectors(vector_path($path));
    is(scalar @$vectors, 100, "$path contains 100 vectors");

    my $count = 0;
    for my $vector (@$vectors) {
        my $state = new_drbg(field($vector, 'seed'));
        my $keys;
        if ($key_calls == 0) {
            $keys = with_repeated_entropy(
                $algorithm, $state, 32,
                sub { $algorithm->generate_key_pair },
            );
        } else {
            my $entropy = join '', map { generate($state, 32) } 1 .. $key_calls;
            $keys = with_exact_entropy(
                $algorithm, $entropy,
                sub { $algorithm->generate_key_pair },
            );
        }
        die "$path public key mismatch at vector $count"
            unless $keys->{public_key} eq field($vector, 'pk');
        die "$path secret key mismatch at vector $count"
            unless $keys->{secret_key} eq field($vector, 'sk');

        my $outbound = with_exact_entropy(
            $algorithm, generate($state, $encapsulation_bytes),
            sub { $algorithm->encapsulate($keys->{public_key}) },
        );
        die "$path ciphertext mismatch at vector $count"
            unless $outbound->{ciphertext} eq field($vector, 'ct');
        die "$path shared secret mismatch at vector $count"
            unless $outbound->{shared_secret} eq field($vector, 'ss');
        die "$path decapsulation mismatch at vector $count"
            unless $algorithm->decapsulate(
                $outbound->{ciphertext}, $keys->{secret_key}
            ) eq $outbound->{shared_secret};
        ++$count;
    }
    pass("$path known-answer records");
    $total += scalar @$vectors;
}

is($total, 1_600, 'all 1,600 known-answer records passed');
done_testing;
