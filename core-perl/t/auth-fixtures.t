use strictures 2;

use Test::More;

use Overnet::Test::SpecConformance qw(
  run_auth_agent_conformance
);

run_auth_agent_conformance();

done_testing;
