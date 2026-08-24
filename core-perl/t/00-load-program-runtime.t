use strictures 2;
use Test::More;

use_ok('Overnet');
use_ok('Overnet::Core::Nostr');
use_ok('Overnet::Core::ProfileContract');
use_ok('Overnet::Authority::Delegation');
use_ok('Overnet::Program::Runtime');
use_ok('Overnet::Program::Protocol');
use_ok('Overnet::Program::Services');
use_ok('Overnet::Program::AdapterFactory');
use_ok('Overnet::Program::AdapterRegistry');
use_ok('Overnet::Program::AdapterSession');
use_ok('Overnet::Program::Host');
use_ok('Overnet::Program::Instance');
use_ok('Overnet::Program::Permissions');
use_ok('Overnet::Program::SecretProvider');
use_ok('Overnet::Program::Store');
use_ok('Overnet::Program::Subscription');
use_ok('Overnet::Program::TLSConfig');
use_ok('Overnet::Program::Timer');

done_testing;
