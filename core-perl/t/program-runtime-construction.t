use strictures 2;
use File::Temp qw(tempdir);
use Test2::V0;

use Overnet::Auth::Agent;
use Overnet::Auth::Client;
use Overnet::Auth::Config;
use Overnet::Auth::Daemon;
use Overnet::Auth::Server;
use Overnet::Auth::StateStore;
use Overnet::Program::AdapterRegistry;
use Overnet::Program::AdapterSession;
use Overnet::Program::Host;
use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::SecretProvider;
use Overnet::Program::Services;
use Overnet::Program::Store;
use Overnet::Program::Subscription;
use Overnet::Program::Timer;

{

  package Local::ConstructorAgent;

  use Moo;
  no Moo;

  sub dispatch { return {}; }
}

{

  package Local::ConstructorAdapter;

  use Moo;
  no Moo;
}

subtest 'Moo constructors accept hashref argument form' => sub {
  my $dir      = tempdir(CLEANUP => 1);
  my $runtime  = Overnet::Program::Runtime->new({config => {}});
  my $services = Overnet::Program::Services->new({runtime => $runtime});

  my @cases = (
    [auth_config => Overnet::Auth::Config->new({config => {}}), 'Overnet::Auth::Config'],
    [auth_agent  => Overnet::Auth::Agent->new({}),              'Overnet::Auth::Agent'],
    [
      auth_client => Overnet::Auth::Client->new({endpoint => "$dir/auth.sock"}),
      'Overnet::Auth::Client',
    ],
    [
      auth_state_store => Overnet::Auth::StateStore->new({path => "$dir/state.json"}),
      'Overnet::Auth::StateStore',
    ],
    [
      auth_server => Overnet::Auth::Server->new({agent => Local::ConstructorAgent->new}),
      'Overnet::Auth::Server',
    ],
    [
      auth_daemon => Overnet::Auth::Daemon->new({endpoint => "$dir/daemon.sock"}),
      'Overnet::Auth::Daemon',
    ],
    [adapter_registry => Overnet::Program::AdapterRegistry->new({}), 'Overnet::Program::AdapterRegistry'],
    [store            => Overnet::Program::Store->new({}),           'Overnet::Program::Store'],
    [
      protocol => Overnet::Program::Protocol->new({max_frame_size => 4096}),
      'Overnet::Program::Protocol',
    ],
    [
      timer => Overnet::Program::Timer->new({session_id => 's', timer_id => 't', due_at_ms => 1}),
      'Overnet::Program::Timer',
    ],
    [
      subscription => Overnet::Program::Subscription->new({session_id => 's', subscription_id => 'sub', query => {}}),
      'Overnet::Program::Subscription',
    ],
    [
      secret_provider => Overnet::Program::SecretProvider->new({secrets => {}, secret_policies => {}}),
      'Overnet::Program::SecretProvider',
    ],
    [runtime  => $runtime,  'Overnet::Program::Runtime'],
    [services => $services, 'Overnet::Program::Services'],
    [
      instance => Overnet::Program::Instance->new({program_id => 'constructor.program'}),
      'Overnet::Program::Instance',
    ],
    [
      adapter_session => Overnet::Program::AdapterSession->new(
        {
          session_id => 's',
          adapter_id => 'a',
          adapter    => Local::ConstructorAdapter->new,
          config     => {},
        }
      ),
      'Overnet::Program::AdapterSession',
    ],
    [
      host => Overnet::Program::Host->new({command => [$^X, '-e', '0']}),
      'Overnet::Program::Host',
    ],
  );

  for my $case (@cases) {
    my ($name, $object, $class) = @{$case};
    isa_ok $object, [$class], "$name constructor";
  }
};

subtest 'runtime constructor protects reserved internal state' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    next_session_id       => 99,
    adapter_sessions      => 'bad',
    timers                => 'bad',
    emitted_items         => 'bad',
    subscriptions         => 'bad',
    secret_handles        => 'bad',
    runtime_notifications => 'bad',
    secrets               => {'api-token' => 'top-secret'},
  );

  $runtime->register_adapter(
    adapter_id => 'constructor.adapter',
    adapter    => Local::ConstructorAdapter->new,
  );
  my $session = $runtime->open_adapter_session(adapter_id => 'constructor.adapter',);
  is $session->session_id, 'adapter-1', 'constructor does not allow next_session_id override';

  ok $runtime->schedule_timer(
    session_id => 'session-1',
    timer_id   => 'timer-1',
    delay_ms   => 0,
    ),
    'constructor does not allow timers override';
  is scalar @{$runtime->drain_runtime_notifications('session-1')}, 1,
    'runtime notifications remain usable after constructor override attempt';

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    name       => 'api-token',
  );
  like $issued->{secret_handle}{id}, qr/\Ash_[0-9a-f]{64}\z/mx,
    'constructor does not allow secret handle table override';

  my $secret_provider = Overnet::Program::SecretProvider->new(
    secrets         => {'host-token' => 'top-secret'},
    random_bytes_cb => sub {
      my ($length) = @_;
      return 'Z' x $length;
    },
  );
  my $host_runtime = Overnet::Program::Runtime->new(secret_provider => $secret_provider,);
  isa_ok $host_runtime->secret_provider, ['Overnet::Program::SecretProvider'],
    'runtime accepts an explicit secret provider';

  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          secret_provider => $secret_provider,
          secrets         => {'mixed' => 'nope'},
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/secrets\ cannot\ be\ supplied\ when\ secret_provider\ is\ provided/mx,
    'runtime rejects mixing explicit secret provider and inline secret args',
  );
};

subtest 'store constructor protects reserved storage internals' => sub {
  my $store = Overnet::Program::Store->new(
    streams   => 'bad',
    documents => 'bad',
  );

  my $appended = $store->append_event(
    stream => 'constructor.test',
    event  => {ok => 1},
  );
  is $appended->{offset}, 0, 'append works with protected store internals';
  is $store->read_events(stream => 'constructor.test')->{entries}[0]{event}{ok}, 1,
    'read works with protected store internals';
  is $store->put_document(key => 'constructor.doc', value => {ok => 1})->{key}, 'constructor.doc',
    'document put works with protected store internals';
  is $store->get_document(key => 'constructor.doc')->{value}{ok}, 1,
    'document get works with protected store internals';
};

subtest 'adapter registry constructor protects adapter table' => sub {
  my $registry = Overnet::Program::AdapterRegistry->new(adapters => 'bad',);

  ok $registry->register(
    adapter_id => 'constructor.registry',
    adapter    => Local::ConstructorAdapter->new,
    ),
    'register works with protected registry internals';
  ok $registry->has('constructor.registry'), 'registry remains usable after constructor override attempt';
};

subtest 'services bus handlers stay in lockstep with the service method vocabulary' => sub {
  my $methods = Overnet::Program::Services->service_methods;
  ok @{$methods}, 'service method vocabulary is not empty';

  my $services = Overnet::Program::Services->new(runtime => Overnet::Program::Runtime->new);
  is [sort keys %{$services->bus->handlers}], $methods,
    'every service method has a bus handler and nothing else is registered';

  is [grep { !(Overnet::Program::Services->is_service_method($_)) } @{$methods}], [],
    'service_methods agrees with is_service_method';
};

done_testing;
