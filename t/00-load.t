use 5.020;
use strict;
use warnings;

use Test::More tests => 1;

BEGIN {
    use_ok('Crypt::KpqC');
}

diag("Testing Crypt::KpqC $Crypt::KpqC::VERSION with Perl $]");
