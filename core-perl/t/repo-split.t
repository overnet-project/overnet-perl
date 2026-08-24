use strictures 2;
use File::Spec;
use FindBin;
use Test::More;

my $root = File::Spec->catdir($FindBin::Bin, '..');

use_ok('Overnet::Core::Validator');
use_ok('Overnet::Program::Runtime');
use_ok('Overnet::Authority::HostedChannel');

ok !-e File::Spec->catfile($root, 'lib', 'Overnet', 'Relay.pm'),
  'core-perl no longer ships the relay entrypoint module';
ok !-d File::Spec->catdir($root, 'lib', 'Overnet', 'Relay'), 'core-perl no longer ships the relay module tree';
ok !-e File::Spec->catfile($root, 'bin', 'overnet-relay.pl'),      'core-perl no longer ships the relay daemon';
ok !-e File::Spec->catfile($root, 'bin', 'overnet-relay-sync.pl'), 'core-perl no longer ships the relay sync CLI';
ok !-e File::Spec->catfile($root, 'bin', 'overnet-release-gate.pl'),
  'core-perl no longer ships the relay-heavy release gate';

done_testing;
