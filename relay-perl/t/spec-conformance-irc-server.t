use strictures 2;
use File::Spec;
use FindBin;
use constant IRC_SERVER_ROOT => -f File::Spec->catfile($FindBin::Bin, '..', '..', 'irc-server', 'Makefile.PL')
  ? File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server')
  : File::Spec->catdir($FindBin::Bin, '..', '..', '..', 'irc-server');

use Test::More;

use lib File::Spec->catdir(IRC_SERVER_ROOT,       'lib');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'adapter-irc-perl', 'lib');

use Overnet::Test::SpecConformance qw(
  run_irc_server_conformance
);

run_irc_server_conformance();

done_testing;
