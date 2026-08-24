use strictures 2;

use File::Spec;
use FindBin;
use Test::More;

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-auth-agent.pl');

ok -f $script, 'auth-agent daemon script exists'
  or BAIL_OUT('auth-agent daemon script is required');

my $syntax = system($^X, '-Ilib', '-c', $script);
is $syntax >> 8, 0, 'auth-agent daemon script has valid syntax';

my $help = qx{$^X -Ilib $script --help 2>&1};
is $? >> 8, 0, '--help exits cleanly';
like $help, qr/Usage:\ .*overnet-auth-agent\.pl\ --config-file\ PATH/mx, '--help prints a usable synopsis';

done_testing;
