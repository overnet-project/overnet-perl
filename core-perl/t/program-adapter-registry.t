use strictures 2;

use Test2::V0;

use Overnet::Program::AdapterFactory;
use Overnet::Program::AdapterRegistry;

{

  package t::adapter_registry::Plain;

  sub new {
    my ($class, %args) = @_;
    return bless {%args}, $class;
  }
}

{

  package t::adapter_registry::BrokenNew;

  sub new { return 'not-a-reference' }
}

subtest 'factory builds object and class adapters' => sub {
  my $factory = Overnet::Program::AdapterFactory->new;

  like(dies { $factory->build }, qr/definition is required/, 'a definition is required');
  like(dies { $factory->build(definition => 'junk') }, qr/definition is required/,
    'non-object definitions are refused');

  my $adapter = t::adapter_registry::Plain->new;
  is($factory->build(definition => {adapter => $adapter}), exact_ref($adapter),
    'the kind defaults to object and returns the adapter');
  is($factory->build(definition => {kind => 'object', adapter => $adapter}), exact_ref($adapter),
    'object definitions return their adapter');
  like(
    dies { $factory->build(definition => {kind => 'object'}) },
    qr/definition[.]adapter is required/,
    'object definitions require an adapter',
  );

  my $built = $factory->build(
    definition => {
      kind             => 'class',
      class            => 't::adapter_registry::Plain',
      constructor_args => {flavor => 'test'},
    },
  );
  isa_ok($built, ['t::adapter_registry::Plain'], 'class definitions construct the adapter');
  is($built->{flavor}, 'test', 'constructor args are passed through');

  like(
    dies { $factory->build(definition => {kind => 'class', class => q{}}) },
    qr/definition[.]class is required/,
    'class definitions require a class name',
  );
  like(
    dies {
      $factory->build(
        definition => {kind => 'class', class => 't::adapter_registry::Plain', constructor_args => 'junk'},
      )
    },
    qr/definition[.]constructor_args must be an object/,
    'constructor args must be an object',
  );
  like(
    dies {
      $factory->build(
        definition => {kind => 'class', class => 't::adapter_registry::Plain', lib_dirs => 'junk'},
      )
    },
    qr/definition[.]lib_dirs must be an array/,
    'lib_dirs must be an array',
  );
  like(
    dies {
      $factory->build(definition => {kind => 'class', class => 'No::Such::Adapter::Class', lib_dirs => []})
    },
    qr/Unable to load adapter class No::Such::Adapter::Class/,
    'unloadable adapter classes croak',
  );
  like(
    dies { $factory->build(definition => {kind => 'class', class => 't::adapter_registry::BrokenNew'}) },
    qr/did not return an object from new/,
    'constructors must return an object',
  );
  like(
    dies { $factory->build(definition => {kind => 'mystery'}) },
    qr/Unsupported adapter definition kind: mystery/,
    'unknown definition kinds croak',
  );
};

subtest 'registry registration and lookup' => sub {
  like(
    dies { Overnet::Program::AdapterRegistry->new('odd') },
    qr/constructor arguments must be a hash/,
    'odd constructor arguments die',
  );
  like(
    dies { Overnet::Program::AdapterRegistry->new(adapter_factory => t::adapter_registry::Plain->new) },
    qr/adapter_factory must be an Overnet::Program::AdapterFactory instance/,
    'foreign factories are refused',
  );

  my $registry = Overnet::Program::AdapterRegistry->new({});
  like(dies { $registry->register(adapter_id => q{}, adapter => t::adapter_registry::Plain->new) },
    qr/adapter_id is required/, 'registration requires an id');
  like(dies { $registry->register(adapter_id => 'id', adapter => 'junk') },
    qr/adapter is required/, 'registration requires an adapter object');
  like(dies { $registry->register_definition(adapter_id => q{}, definition => {}) },
    qr/adapter_id is required/, 'definition registration requires an id');
  like(dies { $registry->register_definition(adapter_id => 'id', definition => 'junk') },
    qr/definition is required/, 'definition registration requires a definition object');

  my $adapter = t::adapter_registry::Plain->new;
  ok($registry->register(adapter_id => 'direct', adapter => $adapter), 'direct adapters register');
  ok(
    $registry->register_definition(
      adapter_id => 'lazy',
      definition => {kind => 'class', class => 't::adapter_registry::Plain'},
    ),
    'definitions register',
  );

  is($registry->get(undef),      undef, 'get without an id returns nothing');
  is($registry->build('absent'), undef, 'building an unknown id returns nothing');
  is($registry->build('direct'), exact_ref($adapter), 'direct adapters build to themselves');
  isa_ok($registry->build('lazy'), ['t::adapter_registry::Plain'], 'definitions build via the factory');
  ok($registry->has('direct'),  'registered ids are reported');
  ok(!$registry->has('absent'), 'unknown ids are not reported');
  is($registry->adapter_ids, ['direct', 'lazy'], 'adapter ids list sorted registrations');
};

done_testing;
