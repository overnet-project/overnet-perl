use strictures 2;

use JSON ();
use Test2::V0;

use AnyEvent;
use IO::Socket::INET ();
use Net::Nostr::Relay;
use Overnet::Core::Nostr;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

my $TIMEOUT_SCALE = $INC{'Devel/Cover.pm'} ? 30 : 1;

sub _scaled_ms {
  my ($ms) = @_;
  return $ms * $TIMEOUT_SCALE;
}

sub _start_relay {
  my $sock = IO::Socket::INET->new(
    Listen    => 1,
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or die "Can't allocate free TCP port: $!";
  my $port = $sock->sockport;
  close $sock;

  my $relay = Net::Nostr::Relay->new;
  $relay->start('127.0.0.1', $port);
  return ($relay, "ws://127.0.0.1:$port");
}

{

  package t::services::ResultAdapter;

  sub new {
    my ($class, %args) = @_;
    return bless {%args}, $class;
  }

  sub map_input {
    my ($self, %args) = @_;
    return $self->{result};
  }

  sub derive {
    my ($self, %args) = @_;
    return $self->{result};
  }
}

{

  package t::services::DyingAdapter;

  sub new { my ($class, %args) = @_; return bless {%args}, $class }

  sub map_input {
    my ($self) = @_;
    die $self->{error};
  }
}

sub _services_with_adapter {
  my ($adapter) = @_;
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(adapter_id => 'mock', adapter => $adapter);
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $opened   = $services->dispatch_request(
    'adapters.open_session',
    {adapter_id => 'mock'},
    permissions => ['adapters.use'],
    session_id  => 'session-1',
  );
  return ($services, $opened->{adapter_session_id});
}

sub _map_result {
  my ($services, $session_id, %params) = @_;
  return $services->dispatch_request(
    'adapters.map_input',
    {adapter_session_id => $session_id, input => {}, %params},
    permissions => ['adapters.use'],
    session_id  => 'session-1',
  );
}

subtest 'dispatch_request validates its envelope' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  like(dies { Overnet::Program::Services->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(dies { Overnet::Program::Services->new(runtime => bless {}, 'Local::NotRuntime') },
    qr/runtime is required/, 'foreign runtimes are refused');
  like(dies { $services->dispatch_request(q{}) }, qr/method is required/, 'a method is required');
  like(dies { $services->dispatch_request('storage.get', 'junk') },
    qr/params must be an object/, 'params must be an object');
  is(dies { $services->dispatch_request('no.such', {}) }->{code},
    'protocol.unknown_method', 'unknown methods are refused');
  is(
    dies {
      $services->dispatch_request(
        'secrets.get', {name => 'a-secret'},
        permissions => ['secrets.read'],
      )
    }->{code},
    'runtime.service_unavailable',
    'session-scoped methods require a session id',
  );
  ok(
    (grep { $_ eq 'storage.get' } @{Overnet::Program::Services->service_methods}),
    'service_methods lists the dispatch surface',
  );
};

subtest 'adapter results are normalized and validated' => sub {
  my $result_for = sub {
    my ($result) = @_;
    my ($services, $session_id) = _services_with_adapter(
      t::services::ResultAdapter->new(result => $result),
    );
    return dies { _map_result($services, $session_id) } || _map_result($services, $session_id);
  };

  is($result_for->('junk')->{code}, 'runtime.service_unavailable',
    'non-object adapter results are refused');
  my $rejected = $result_for->({valid => JSON::false, reason => 'bad input'});
  is($rejected->{code},    'protocol.invalid_params', 'invalid adapter results are invalid params');
  is($rejected->{message}, 'bad input',               'the adapter reason is passed through');
  is($result_for->({valid => JSON::false})->{message}, 'Adapter rejected request',
    'a missing reason falls back to a generic message');

  is($result_for->({event => 'junk'})->{code}, 'runtime.service_unavailable',
    'non-object adapter events are refused');
  my $state_kind = $result_for->({event => {kind => 37_800}});
  is(scalar(@{$state_kind->{state}}), 1, 'state-kind events normalize into the state list');
  my $event_kind = $result_for->({event => {kind => 7_800}});
  is(scalar(@{$event_kind->{events}}), 1, 'other events normalize into the events list');

  is($result_for->({events => 'junk'})->{code}, 'runtime.service_unavailable',
    'non-array event lists are refused');
  is($result_for->({events => ['junk']})->{code}, 'runtime.service_unavailable',
    'non-object event entries are refused');
  ok($result_for->({view => [{member => 'x'}]})->{view}, 'views are passed through');
  ok($result_for->({admission => [{allowed => JSON::true}]})->{admission},
    'admissions are passed through');
  ok($result_for->({permission => [{allowed => JSON::true}]})->{permission},
    'permissions are passed through');

  is($result_for->({capabilities => 'junk'})->{code}, 'runtime.service_unavailable',
    'non-array capability lists are refused');
  is($result_for->({capabilities => ['junk']})->{code}, 'runtime.service_unavailable',
    'non-object capability entries are refused');
  is($result_for->({capabilities => [{name => q{}}]})->{code}, 'runtime.service_unavailable',
    'capabilities require a name');
  is($result_for->({capabilities => [{name => 'x', version => q{}}]})->{code},
    'runtime.service_unavailable', 'capabilities require a version');
  is($result_for->({capabilities => [{name => 'x', version => '1', details => 'junk'}]})->{code},
    'runtime.service_unavailable', 'capability details must be objects');
  ok(
    $result_for->({capabilities => [{name => 'x', version => '1', details => {}}]})->{capabilities},
    'well-formed capabilities are passed through',
  );

  my ($dying_services, $dying_session) = _services_with_adapter(
    t::services::DyingAdapter->new(error => "adapter exploded\n"),
  );
  my $string_error = dies { _map_result($dying_services, $dying_session) };
  is($string_error->{code}, 'runtime.service_unavailable',
    'string adapter errors become service_unavailable');
  like($string_error->{message}, qr/adapter exploded/, 'the adapter error text is preserved');

  my ($hash_services, $hash_session) = _services_with_adapter(
    t::services::DyingAdapter->new(error => {code => 'custom.code', message => 'structured'}),
  );
  my $hash_error = dies { _map_result($hash_services, $hash_session) };
  is($hash_error->{code}, 'custom.code', 'structured adapter errors pass through');
};

subtest 'nostr service methods round-trip through a local relay' => sub {
  my ($relay, $relay_url) = _start_relay();
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my %dispatch = (permissions => ['nostr.read', 'nostr.write'], session_id => 'session-1');

  my $key    = Overnet::Core::Nostr->generate_key;
  my $signed = $key->sign_event_hash(
    event => {kind => 1, created_at => 500, tags => [], content => 'service event'},
  );

  is(
    dies {
      $services->dispatch_request('nostr.publish_event', {relay_url => $relay_url}, %dispatch)
    }->{code},
    'protocol.invalid_params',
    'publishing requires an event',
  );
  is(
    dies {
      $services->dispatch_request(
        'nostr.publish_event',
        {relay_url => $relay_url, event => $signed, timeout_ms => 0},
        %dispatch,
      )
    }->{code},
    'protocol.invalid_params',
    'publish timeouts must be positive',
  );

  my $published = $services->dispatch_request(
    'nostr.publish_event',
    {relay_url => $relay_url, event => $signed, timeout_ms => _scaled_ms(5_000)},
    %dispatch,
  );
  ok($published->{accepted}, 'events publish through the service surface');

  is(
    dies {
      $services->dispatch_request('nostr.query_events', {relay_url => $relay_url, filters => []},
        %dispatch)
    }->{code},
    'protocol.invalid_params',
    'queries require filters',
  );
  is(
    dies {
      $services->dispatch_request(
        'nostr.open_subscription',
        {
          relay_url       => $relay_url,
          subscription_id => 'bad-filter-sub',
          filters         => ['junk'],
        },
        %dispatch,
      )
    }->{code},
    'protocol.invalid_params',
    'subscription filters must be objects',
  );
  my $queried = $services->dispatch_request(
    'nostr.query_events',
    {relay_url => $relay_url, filters => [{kinds => [1]}], timeout_ms => _scaled_ms(5_000)},
    %dispatch,
  );
  is(scalar(@{$queried->{events}}), 1, 'queries return relay events');

  my $opened = $services->dispatch_request(
    'nostr.open_subscription',
    {
      relay_url       => $relay_url,
      subscription_id => 'nostr-sub-1',
      filters         => [{kinds => [1]}],
      timeout_ms      => _scaled_ms(5_000),
    },
    %dispatch,
  );
  ok(defined $opened->{subscription_id}, 'nostr subscriptions open');

  my $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {subscription_id => $opened->{subscription_id}, timeout_ms => _scaled_ms(5_000)},
    %dispatch,
  );
  ok(ref($snapshot->{events}) eq 'ARRAY', 'subscription snapshots read');

  my $closed = $services->dispatch_request(
    'nostr.close_subscription',
    {subscription_id => $opened->{subscription_id}},
    %dispatch,
  );
  ok($closed, 'nostr subscriptions close');
  $relay->stop;
};

subtest 'parameter validators reject malformed dispatch params' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new({runtime => $runtime});
  my %dispatch = (
    permissions => [
      qw(storage.read storage.write timers.write subscriptions.read nostr.read adapters.use secrets.read)
    ],
    session_id => 'session-1',
  );
  my $error_for = sub {
    my ($method, $params) = @_;
    my $error = dies { $services->dispatch_request($method, $params, %dispatch) };
    return ref($error) eq 'HASH' ? $error : {message => "$error"};
  };

  is($error_for->('secrets.get', {name => 'x'})->{code}, 'protocol.invalid_params',
    'sanity: unknown secrets are invalid params');
  is(
    dies {
      $services->dispatch_request('secrets.get', {name => 'x'}, %dispatch, session_id => q{})
    }->{code},
    'runtime.service_unavailable',
    'empty session ids are treated as missing context',
  );

  like($error_for->('storage.get', {key => q{}})->{message}, qr/key is required/,
    'empty string params are refused');
  like($error_for->('nostr.query_events', {relay_url => 'ws://x', filters => 'junk'})->{message},
    qr/filters must be an array/, 'non-array params are refused');
  like($error_for->('nostr.open_subscription',
      {relay_url => 'ws://x', subscription_id => 's', filters => []})->{message},
    qr/filters must be a non-empty array/, 'empty subscription filters are refused');
  like(
    $error_for->('timers.schedule', {timer_id => 't', delay_ms => 'soon'})->{message},
    qr/delay_ms/,
    'non-integer timer delays are refused',
  );
  like(
    $error_for->('timers.schedule', {timer_id => 't', at => 'noon'})->{message},
    qr/at must be an integer/,
    'non-integer timer times are refused',
  );

  my $subscription_query = sub {
    my ($query) = @_;
    return $error_for->('subscriptions.open', {subscription_id => 's-1', query => $query});
  };
  like($subscription_query->('junk')->{message}, qr/query must be an object/,
    'subscription queries must be objects');
  like($subscription_query->({kind => 'many'})->{message}, qr/kind/,
    'subscription query kinds must be integers');
  like($subscription_query->({overnet_et => q{}})->{message}, qr/overnet_et/,
    'subscription query tag filters must be non-empty');

  my $open_with_handles = sub {
    my ($secret_handles) = @_;
    return $error_for->(
      'adapters.open_session',
      {adapter_id => 'mock', secret_handles => $secret_handles},
    );
  };
  like($open_with_handles->('junk')->{message}, qr/secret_handles must be an object/,
    'secret handle maps must be objects');
  like($open_with_handles->({q{} => {id => 'h'}})->{message},
    qr/slot names must be non-empty strings/, 'secret handle slots must be named');
  like($open_with_handles->({password => 'junk'})->{message},
    qr/secret_handles[.]password must be an object/, 'secret handles must be objects');
  like($open_with_handles->({password => {id => q{}}})->{message},
    qr/id must be a non-empty string/, 'secret handles require an id');
  like($open_with_handles->({password => {id => 'h', expires_at => 'soon'}})->{message},
    qr/expires_at must be an integer/, 'secret handle expirations must be integers');
};

subtest 'nostr subscription bookkeeping errors' => sub {
  my ($relay, $relay_url) = _start_relay();
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my %dispatch = (permissions => ['nostr.read', 'nostr.write'], session_id => 'session-1');

  is(
    dies {
      $services->dispatch_request(
        'nostr.read_subscription_snapshot', {subscription_id => 'ghost'},
        %dispatch,
      )
    }->{code},
    'protocol.invalid_params',
    'snapshots of unknown subscriptions are refused',
  );
  is(
    dies {
      $services->dispatch_request('nostr.close_subscription', {subscription_id => 'ghost'},
        %dispatch)
    }->{code},
    'protocol.invalid_params',
    'closing unknown subscriptions is refused',
  );

  my $opened = $services->dispatch_request(
    'nostr.open_subscription',
    {
      relay_url       => $relay_url,
      subscription_id => 'dup-sub',
      filters         => [{kinds => [1]}],
      timeout_ms      => _scaled_ms(5_000),
    },
    %dispatch,
  );
  ok(defined $opened->{subscription_id}, 'the first subscription opens');
  is(
    dies {
      $services->dispatch_request(
        'nostr.open_subscription',
        {
          relay_url       => $relay_url,
          subscription_id => 'dup-sub',
          filters         => [{kinds => [1]}],
        },
        %dispatch,
      )
    }->{code},
    'protocol.invalid_params',
    'duplicate subscription ids are refused',
  );
  my $snapshot = $services->dispatch_request(
    'nostr.read_subscription_snapshot',
    {subscription_id => 'dup-sub', refresh => '1', timeout_ms => _scaled_ms(5_000)},
    %dispatch,
  );
  ok(ref($snapshot->{events}) eq 'ARRAY', 'refreshing snapshots reads through the relay');
  $services->dispatch_request('nostr.close_subscription', {subscription_id => 'dup-sub'}, %dispatch);
  $relay->stop;
};

done_testing;
