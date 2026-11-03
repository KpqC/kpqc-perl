use 5.020;
use strict;
use warnings;

use Config;
use ExtUtils::MakeMaker;

my @core_sources = map { "native/core_$_.c" } qw(
    aimer128f aimer128s aimer192f aimer192s aimer256f aimer256s
    haetae2 haetae3 haetae5
    ntruplus768 ntruplus864 ntruplus1152
    smaugt128 smaugt192 smaugt256 timer
);

my @objects = map {
    (my $object = $_) =~ s{\Anative/}{};
    $object =~ s/\.c\z/\$(OBJ_EXT)/;
    $object;
} @core_sources;

my $kat_enabled = $ENV{KPQC_KAT} ? 1 : 0;
push @objects, 'aes$(OBJ_EXT)' if $kat_enabled;

my $define = $kat_enabled ? '-DKPQC_TEST_ENTROPY' : '';
my $uses_msvc = $Config{ccname} =~ /\Acl(?:ang-cl)?\z/i;
my $c_standard = $uses_msvc ? '/std:c11' : '-std=c11';
my $perl_header_flags = $^O eq 'darwin' || $Config{ccname} =~ /clang/i
    ? '-Wno-compound-token-split-by-macro'
    : '';
my $system_library = $^O eq 'MSWin32'
    ? ($uses_msvc ? 'bcrypt.lib' : '-lbcrypt')
    : '-lm';
WriteMakefile(
    NAME             => 'Crypt::KpqC',
    VERSION_FROM     => 'lib/Crypt/KpqC.pm',
    ABSTRACT_FROM    => 'lib/Crypt/KpqC.pm',
    AUTHOR           => 'Owen Suolfou <osuolfou@gmail.com>',
    LICENSE          => 'mit',
    MIN_PERL_VERSION => '5.020',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '7.00',
    },
    PREREQ_PM => {
        'Carp'     => 0,
        'Exporter' => 0,
        'Hash::Util' => 0,
        'XSLoader' => 0,
    },
    TEST_REQUIRES => {
        'File::Spec' => 0,
        'Test::More' => '0.98',
    },
    XS     => { 'KpqC.xs' => 'KpqC.c' },
    OBJECT => join(' ', 'KpqC$(OBJ_EXT)', @objects),
    DEFINE => $define,
    CCFLAGS => join(' ', grep { length } $Config{ccflags}, $c_standard,
                    $perl_header_flags),
    LIBS    => [$system_library],
    clean   => { FILES => 'KpqC.c KpqC.c.bak' },
    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources => {
            bugtracker => {
                web => 'https://github.com/KpqC/kpqc-perl/issues',
            },
            homepage => 'https://github.com/KpqC/kpqc-perl',
            repository => {
                type => 'git',
                url  => 'https://github.com/KpqC/kpqc-perl.git',
                web  => 'https://github.com/KpqC/kpqc-perl',
            },
        },
    },
);

sub MY::postamble {
    my $rules = '';
    for my $source (@core_sources, ($kat_enabled ? 'native/aes.c' : ())) {
        (my $object = $source) =~ s{\Anative/}{};
        $object =~ s/\.c\z/\$(OBJ_EXT)/;

        my $include = '';
        my $include_switch = $uses_msvc ? '/I' : '-I';
        $include = $include_switch . 'native/third_party/HAETAE/include'
            if $source =~ /core_haetae/;
        $include = $include_switch . 'native/third_party/NTRUplus/NTRU+768'
            if $source =~ /core_ntruplus768/;
        $include = $include_switch . 'native/third_party/NTRUplus/NTRU+864'
            if $source =~ /core_ntruplus864/;
        $include = $include_switch . 'native/third_party/NTRUplus/NTRU+1152'
            if $source =~ /core_ntruplus1152/;
        $include = $include_switch . 'native/third_party/SMAUG-T/include'
            if $source =~ /core_(?:smaugt|timer)/;
        $include = $include_switch . 'native' if $source =~ /aes\.c\z/;

        $rules .= "$object: $source \$(FIRST_MAKEFILE)\n";
        $rules .= "\t\$(CCCMD) \$(DEFINE) $include \$(CCCDLFLAGS) $source\n\n";
    }
    return $rules;
}
