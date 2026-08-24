use strictures 2;

use FindBin;
use File::Spec;
use Test::More;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'adapter-irc-perl', 'lib');

my $IRC_ADAPTER_LIB = File::Spec->rel2abs(File::Spec->catdir($FindBin::Bin, '..', '..', 'adapter-irc-perl', 'lib'));

plan skip_all => "adapter-irc-perl checkout not found at $IRC_ADAPTER_LIB"
  if !-d $IRC_ADAPTER_LIB;

use Overnet::Test::SpecConformance qw(
  run_auth_agent_conformance
  run_irc_adapter_map_conformance
  run_irc_adapter_derived_presence_conformance
  run_irc_adapter_authoritative_conformance
);

run_auth_agent_conformance();
run_irc_adapter_map_conformance();
run_irc_adapter_derived_presence_conformance();
run_irc_adapter_authoritative_conformance();

done_testing;
