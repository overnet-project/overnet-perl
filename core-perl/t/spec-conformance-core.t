use strictures 2;

use Test::More;

use Overnet::Test::SpecConformance qw(
  run_core_validator_conformance
  run_core_provenance_conformance
  run_private_messaging_conformance
);

run_core_validator_conformance();
run_core_provenance_conformance();
run_private_messaging_conformance();

done_testing;
