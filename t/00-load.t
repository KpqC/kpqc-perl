use 5.020;
use strict;
use warnings;

use Test::More tests => 2;

BEGIN {
    use_ok('KpqC');
    use_ok('Crypt::KpqC');
}

diag("Testing KpqC $KpqC::VERSION with Perl $]");
