use strictures 2;
use FindBin;
use File::Spec;
use Test2::V0;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib');

use Overnet::Test::SpecConformance qw(
  run_irc_adapter_map_conformance
  run_irc_adapter_derived_presence_conformance
  run_irc_adapter_authoritative_conformance
);

run_irc_adapter_map_conformance();
run_irc_adapter_derived_presence_conformance();
run_irc_adapter_authoritative_conformance();

done_testing;
