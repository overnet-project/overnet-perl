use strictures 2;

use File::Basename qw(dirname);
use File::Spec;
use JSON ();
use Test2::V0;

use AnyEvent;
use IO::Socket::INET ();
use Net::Nostr::Relay;
use Overnet::Core::Nostr;
use Overnet::Program::AdapterRegistry;
use Overnet::Program::Runtime;
use Overnet::Program::SecretProvider;
use Overnet::Program::Store;

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

  package t::runtime_edges::Adapter;

  sub new { my ($class, %args) = @_; return bless {%args}, $class }

  sub map_input { return {events => []} }

  sub close_session {
    my ($self) = @_;
    if ($self->{die_on_close}) {
      die "close exploded\n";
    }
    return 1;
  }
}

{

  package t::runtime_edges::SlotAdapter;

  sub new { my ($class, %args) = @_; return bless {%args}, $class }

  sub supported_secret_slots {
    my ($self) = @_;
    return $self->{slots};
  }

  sub open_session {
    my ($self, %args) = @_;
    return 1;
  }
}

{

  package t::runtime_edges::SlotlessAdapter;

  sub new { my ($class) = @_; return bless {}, $class }
}

{

  package t::runtime_edges::NoOpenAdapter;

  sub new { my ($class) = @_; return bless {}, $class }

  sub supported_secret_slots { return ['password'] }
}

subtest 'constructor and accessor validation' => sub {
  like(dies { Overnet::Program::Runtime->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(
    dies { Overnet::Program::Runtime->new(adapter_registry => bless {}, 'Local::NotRegistry') },
    qr/adapter_registry must be an Overnet::Program::AdapterRegistry instance/,
    'foreign registries are refused',
  );
  like(dies { Overnet::Program::Runtime->new(store => bless {}, 'Local::NotStore') },
    qr/store must be an Overnet::Program::Store instance/, 'foreign stores are refused');
  like(dies { Overnet::Program::Runtime->new(now_cb => 'junk') },
    qr/now_cb must be a code reference/, 'now_cb must be code');
  like(dies { Overnet::Program::Runtime->new(config => 'junk') },
    qr/config must be an object/, 'config must be an object');
  like(dies { Overnet::Program::Runtime->new(config_description => 'junk') },
    qr/config_description must be an object/, 'config descriptions must be objects');
  like(dies { Overnet::Program::Runtime->new(config_description => {schema => 'junk'}) },
    qr/config_description[.]schema must be an object/, 'description schemas must be objects');
  like(dies { Overnet::Program::Runtime->new(config_description => {version => q{}}) },
    qr/config_description[.]version must be a non-empty string/, 'description versions are validated');
  like(dies { Overnet::Program::Runtime->new(host => 'nope') },
    qr/host is reserved for process supervision/, 'the host argument is reserved');
  like(
    dies { Overnet::Program::Runtime->new(secret_provider => bless {}, 'Local::NotProvider') },
    qr/secret_provider must be an Overnet::Program::SecretProvider instance/,
    'foreign secret providers are refused',
  );

  my $store   = Overnet::Program::Store->new;
  my $runtime = Overnet::Program::Runtime->new(
    {
      store           => $store,
      secret_provider => Overnet::Program::SecretProvider->new(secrets => {token => 'sekrit'}),
    },
  );
  is($runtime->store, exact_ref($store), 'the store accessor returns the store');
  ok($runtime->has_secret(name => 'token'), 'has_secret delegates to the provider');
  ok(!$runtime->revoke_secret_handle(handle_id => 'ghost'),
    'revoke_secret_handle delegates to the provider');
  is($runtime->secret_audit_events, [], 'secret_audit_events delegates to the provider');
  is($runtime->emitted_items, [], 'a fresh runtime has emitted nothing');
  like(dies { $runtime->emitted_stream_name('junk') },
    qr/item_type must be event, state, private_message, or capability/,
    'emitted stream names validate their item type');
  like(dies { $runtime->drain_runtime_notifications(q{}) },
    qr/session_id is required/, 'draining requires a session id');
};

subtest 'adapter session validation and secret slots' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secret_provider => Overnet::Program::SecretProvider->new(secrets => {password => 'hunter2'}),
  );
  $runtime->register_adapter(adapter_id => 'mock', adapter => t::runtime_edges::Adapter->new);

  like(dies { $runtime->open_adapter_session(adapter_id => q{}) },
    qr/adapter_id is required/, 'an adapter id is required');
  like(dies { $runtime->open_adapter_session(adapter_id => 'mock', config => 'junk') },
    qr/config must be an object/, 'session config must be an object');
  like(dies { $runtime->open_adapter_session(adapter_id => 'mock', secret_handles => 'junk') },
    qr/secret_handles must be an object/, 'secret handles must be an object');
  like(
    dies {
      $runtime->open_adapter_session(
        adapter_id     => 'mock',
        secret_handles => {password => {id => 'h'}},
      )
    },
    qr/session_id is required when secret_handles are supplied/,
    'secret handles require a program session',
  );
  like(dies { $runtime->open_adapter_session(adapter_id => 'mock', program_id => q{}) },
    qr/program_id must be a non-empty string/, 'program ids must be non-empty');
  like(dies { $runtime->open_adapter_session(adapter_id => 'ghost') },
    qr/Unknown adapter_id: ghost/, 'unknown adapters are refused');
  like(dies { $runtime->close_adapter_session(q{}) },
    qr/adapter_session_id is required/, 'closing requires a session id');
  like(dies { $runtime->close_adapter_session('ghost') },
    qr/Unknown adapter_session_id: ghost/, 'closing unknown sessions is refused');

  my %secret_session_args = (
    session_id => 'program-session-1',
    program_id => 'irc.bridge',
  );
  $runtime->register_adapter(
    adapter_id => 'slots',
    adapter    => t::runtime_edges::SlotAdapter->new(slots => ['password']),
  );
  my $handle = $runtime->issue_secret_handle(
    session_id => 'program-session-1',
    name       => 'password',
    program_id => 'irc.bridge',
    purpose    => 'adapters.open_session:slots:password',
  );

  is(
    dies {
      $runtime->open_adapter_session(
        adapter_id     => 'slots',
        secret_handles => {password => 'junk'},
        %secret_session_args,
      )
    }->{code},
    'protocol.invalid_params',
    'secret handle entries must be objects',
  );
  is(
    dies {
      $runtime->open_adapter_session(
        adapter_id     => 'slots',
        secret_handles => {password => {id => q{}}},
        %secret_session_args,
      )
    }->{code},
    'protocol.invalid_params',
    'secret handles require an id',
  );

  $runtime->register_adapter(
    adapter_id => 'slotless',
    adapter    => t::runtime_edges::SlotlessAdapter->new,
  );
  like(
    dies {
      $runtime->open_adapter_session(
        adapter_id     => 'slotless',
        secret_handles => {password => {id => $handle->{secret_handle}{id}}},
        %secret_session_args,
      )
    }->{message},
    qr/does not declare secure secret input slots/,
    'adapters without slot support refuse secret handles',
  );
  $runtime->register_adapter(
    adapter_id => 'no-open',
    adapter    => t::runtime_edges::NoOpenAdapter->new,
  );
  like(
    dies {
      $runtime->open_adapter_session(
        adapter_id     => 'no-open',
        secret_handles => {password => {id => $handle->{secret_handle}{id}}},
        %secret_session_args,
      )
    }->{message},
    qr/does not support secure session opening/,
    'adapters without open_session refuse secret handles',
  );
  $runtime->register_adapter(
    adapter_id => 'bad-slots',
    adapter    => t::runtime_edges::SlotAdapter->new(slots => 'junk'),
  );
  like(
    dies {
      $runtime->open_adapter_session(
        adapter_id     => 'bad-slots',
        secret_handles => {password => {id => $handle->{secret_handle}{id}}},
        %secret_session_args,
      )
    }->{message},
    qr/supported_secret_slots must return an array/,
    'slot lists must be arrays',
  );
  $runtime->register_adapter(
    adapter_id => 'empty-slots',
    adapter    => t::runtime_edges::SlotAdapter->new(slots => [q{}]),
  );
  like(
    dies {
      $runtime->open_adapter_session(
        adapter_id     => 'empty-slots',
        secret_handles => {password => {id => $handle->{secret_handle}{id}}},
        %secret_session_args,
      )
    }->{message},
    qr/supported_secret_slots must contain non-empty strings/,
    'slot names must be non-empty strings',
  );
};

subtest 'session resource release' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock',
    adapter    => t::runtime_edges::Adapter->new(die_on_close => 1),
  );

  is($runtime->get_adapter_session(undef), undef, 'getting a session without an id is a no-op');

  my $session = $runtime->open_adapter_session(
    adapter_id => 'mock',
    session_id => 'program-session-9',
  );
  my $other = $runtime->open_adapter_session(
    adapter_id => 'mock',
    session_id => 'other-session',
  );
  $runtime->schedule_timer(
    session_id => 'program-session-9',
    timer_id   => 'timer-1',
    delay_ms   => 60_000,
  );
  $runtime->open_subscription(
    session_id      => 'program-session-9',
    subscription_id => 'sub-1',
    query           => {},
  );
  $runtime->drain_runtime_notifications('other-session');

  ok($runtime->has_timer(session_id => 'program-session-9', timer_id => 'timer-1'),
    'the timer exists before release');
  my $released = $runtime->release_session_resources(session_id => 'program-session-9');
  is($released->{adapter_sessions_closed}, 1, 'the session adapter session is closed');
  ok(!$runtime->has_timer(session_id => 'program-session-9', timer_id => 'timer-1'),
    'timers are released');
  ok(
    !$runtime->has_subscription(session_id => 'program-session-9', subscription_id => 'sub-1'),
    'subscriptions are released',
  );
  ok(
    defined $runtime->get_adapter_session($other->session_id),
    'other sessions are untouched',
  );

  ok(!$runtime->has_subscription(subscription_id => 'sub-1'), 'has_subscription requires a session');
  ok(!$runtime->has_nostr_subscription(subscription_id => 'sub-1'),
    'has_nostr_subscription requires a session');
  ok(!$runtime->has_timer(timer_id => 'timer-1'), 'has_timer requires a session');
};

subtest 'timer and subscription bookkeeping croaks' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my %timer   = (session_id => 's-1', timer_id => 't-1', delay_ms => 0);

  $runtime->schedule_timer(%timer);
  like(dies { $runtime->schedule_timer(%timer) }, qr/Duplicate timer_id: t-1/,
    'duplicate timers are refused');
  like(dies { $runtime->schedule_timer(%timer, timer_id => 't-2', repeat_ms => 0) },
    qr/repeat_ms must be a positive integer/, 'repeat intervals must be positive');
  like(dies { $runtime->schedule_timer(%timer, timer_id => 't-2', payload => 'junk') },
    qr/payload must be an object/, 'payloads must be objects');
  like(
    dies { $runtime->schedule_timer(session_id => 's-1', timer_id => 't-2', at => 'noon') },
    qr/at must be an integer/,
    'absolute times must be integers',
  );
  like(dies { $runtime->schedule_timer(%timer, timer_id => 't-2', delay_ms => 'soon') },
    qr/delay_ms must be a non-negative integer/, 'delays must be non-negative integers');
  like(dies { $runtime->cancel_timer(session_id => 's-1', timer_id => 'ghost') },
    qr/Unknown timer_id: ghost/, 'cancelling unknown timers is refused');

  my $fired = $runtime->drain_runtime_notifications('s-1');
  is(scalar(@{$fired}), 1, 'the due timer fired');
  $runtime->schedule_timer(%timer, timer_id => 't-queued', repeat_ms => 60_000);
  $runtime->_queue_due_timer_notifications;
  $runtime->cancel_timer(session_id => 's-1', timer_id => 't-queued');
  is($runtime->drain_runtime_notifications('s-1'), [],
    'cancelling a timer drops its queued notifications');

  like(
    dies {
      $runtime->open_subscription(session_id => 's-1', subscription_id => 'q-1', query => 'junk')
    },
    qr/query must be an object/,
    'subscription queries must be objects',
  );
  $runtime->open_subscription(session_id => 's-1', subscription_id => 'q-1', query => {});
  like(
    dies {
      $runtime->open_subscription(session_id => 's-1', subscription_id => 'q-1', query => {})
    },
    qr/Duplicate subscription_id: q-1/,
    'duplicate subscriptions are refused',
  );
  like(
    dies { $runtime->close_subscription(session_id => 's-1', subscription_id => 'ghost') },
    qr/Unknown subscription_id: ghost/,
    'closing unknown subscriptions is refused',
  );
  $runtime->close_subscription(session_id => 's-1', subscription_id => 'q-1');
  ok(!$runtime->has_subscription(session_id => 's-1', subscription_id => 'q-1'),
    'closed subscriptions are gone');
};

subtest 'emission surface validation' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $key     = Overnet::Core::Nostr->generate_key;
  my $event   = sub {
    my (%spec) = @_;
    return {kind => 7_800, created_at => 1, tags => [], content => '{}', %spec};
  };

  like(dies { $runtime->accept_emitted_item(method => q{}) },
    qr/method is required/, 'emitted items require a method');
  like(
    dies { $runtime->accept_emitted_item(method => 'overnet.emit_event', item_type => 'junk') },
    qr/item_type must be event or state/,
    'emitted item types are validated',
  );
  like(
    dies {
      $runtime->accept_emitted_item(
        method    => 'overnet.emit_event',
        item_type => 'event',
        candidate => 'junk',
      )
    },
    qr/candidate must be an object/,
    'emitted candidates must be objects',
  );

  my $wrong_state = dies {
    $runtime->accept_emitted_item(
      method    => 'overnet.emit_state',
      item_type => 'state',
      candidate => $event->(),
    )
  };
  is($wrong_state->{code}, 'runtime.validation_failed', 'emit_state refuses non-state kinds');

  my $wrong_event = dies {
    $runtime->accept_emitted_item(
      method    => 'overnet.emit_event',
      item_type => 'event',
      candidate => $event->(kind => 37_800),
    )
  };
  is($wrong_event->{code}, 'runtime.validation_failed', 'emit_event refuses state kinds');
  ok(
    (grep { /kind 37800/ } @{$wrong_event->{details}{errors} || []}),
    'the state-kind rejection is explained',
  );

  like(dies { $runtime->accept_emitted_capabilities(method => q{}) },
    qr/method is required/, 'capability emission requires a method');
  like(
    dies {
      $runtime->accept_emitted_capabilities(
        method       => 'overnet.emit_capabilities',
        capabilities => 'junk',
      )
    },
    qr/capabilities must be an array/,
    'capability lists must be arrays',
  );
  my $bad_entries = dies {
    $runtime->accept_emitted_capabilities(
      method       => 'overnet.emit_capabilities',
      capabilities => ['junk', {name => q{}}, {name => 'x', version => q{}}],
    )
  };
  is($bad_entries->{code}, 'runtime.validation_failed', 'malformed capability entries are refused');
  is(scalar(@{$bad_entries->{details}{errors} || []}), 4, 'every malformed capability field is reported');

  like(dies { $runtime->accept_emitted_private_message(method => q{}) },
    qr/method is required/, 'private message emission requires a method');
  like(
    dies {
      $runtime->accept_emitted_private_message(
        method    => 'overnet.emit_private_message',
        candidate => 'junk',
      )
    },
    qr/candidate must be an object/,
    'private message candidates must be objects',
  );
  my $invalid_private = dies {
    $runtime->accept_emitted_private_message(
      method    => 'overnet.emit_private_message',
      candidate => {},
    )
  };
  is($invalid_private->{code}, 'runtime.validation_failed', 'invalid private messages are refused');

  my $bad_clock = Overnet::Program::Runtime->new(now_cb => sub { return 'noon' });
  like(
    dies { $bad_clock->schedule_timer(session_id => 's', timer_id => 't', delay_ms => 0) },
    qr/now_cb must return an integer millisecond timestamp/,
    'non-integer clocks croak',
  );
};

subtest 'nostr runtime methods validate and refresh' => sub {
  my ($relay, $relay_url) = _start_relay();
  my $runtime = Overnet::Program::Runtime->new;
  my $key     = Overnet::Core::Nostr->generate_key;
  my $signed  = sub {
    my (%spec) = @_;
    return $key->sign_event_hash(
      event => {kind => 1, created_at => 700, tags => [], content => 'edge', %spec},
    );
  };

  like(dies { $runtime->publish_nostr_event(relay_url => $relay_url, event => 'junk') },
    qr/event must be an object/, 'published events must be objects');
  like(
    dies {
      $runtime->publish_nostr_event(relay_url => $relay_url, event => $signed->(), timeout_ms => 0)
    },
    qr/timeout_ms must be a positive integer/,
    'publish timeouts must be positive',
  );
  like(dies { $runtime->query_nostr_events(relay_url => $relay_url, filters => 'junk') },
    qr/filters must be a non-empty array/, 'query filters must be arrays');
  like(
    dies {
      $runtime->query_nostr_events(relay_url => $relay_url, filters => [{}], timeout_ms => 0)
    },
    qr/timeout_ms must be a positive integer/,
    'query timeouts must be positive',
  );

  my %subscription = (
    session_id      => 's-1',
    subscription_id => 'n-1',
    relay_url       => $relay_url,
    filters         => [{kinds => [1]}],
    timeout_ms      => _scaled_ms(5_000),
  );
  like(dies { $runtime->open_nostr_subscription(%subscription, filters => []) },
    qr/filters must be a non-empty array/, 'subscription filters must be non-empty');
  like(dies { $runtime->open_nostr_subscription(%subscription, timeout_ms => 0) },
    qr/timeout_ms must be a positive integer/, 'subscription timeouts must be positive');

  my $first = $signed->();
  $runtime->publish_nostr_event(
    relay_url  => $relay_url,
    event      => $first,
    timeout_ms => _scaled_ms(5_000),
  );
  my $opened = $runtime->open_nostr_subscription(%subscription);
  is(scalar(@{$opened->{events}}), 1, 'opening a subscription snapshots existing events');
  like(dies { $runtime->open_nostr_subscription(%subscription) },
    qr/Duplicate subscription_id: n-1/, 'duplicate nostr subscriptions are refused');
  like(
    dies {
      $runtime->read_nostr_subscription_snapshot(session_id => 's-1', subscription_id => 'ghost')
    },
    qr/Unknown subscription_id: ghost/,
    'snapshots of unknown subscriptions are refused',
  );
  like(
    dies {
      $runtime->close_nostr_subscription(session_id => 's-1', subscription_id => 'ghost')
    },
    qr/Unknown subscription_id: ghost/,
    'closing unknown nostr subscriptions is refused',
  );

  my $second = $signed->(created_at => 701);
  $runtime->publish_nostr_event(
    relay_url  => $relay_url,
    event      => $second,
    timeout_ms => _scaled_ms(5_000),
  );
  my $notifications = $runtime->drain_runtime_notifications('s-1');
  is(scalar(@{$notifications}), 1, 'refreshing subscriptions queues new event notifications');
  is($notifications->[0]{params}{data}{id}, $second->{id}, 'the new event is delivered');

  my $snapshot = $runtime->read_nostr_subscription_snapshot(
    session_id      => 's-1',
    subscription_id => 'n-1',
    refresh         => 1,
  );
  is(scalar(@{$snapshot->{events}}), 2, 'refreshed snapshots merge and deduplicate events');

  ok($runtime->close_nostr_subscription(session_id => 's-1', subscription_id => 'n-1'),
    'nostr subscriptions close');
  ok(!$runtime->has_nostr_subscription(session_id => 's-1', subscription_id => 'n-1'),
    'closed nostr subscriptions are gone');
  $relay->stop;
};

subtest 'bookkeeping internals and stale entries' => sub {
  my ($relay, $relay_url) = _start_relay();
  my $runtime = Overnet::Program::Runtime->new;
  my $key     = Overnet::Core::Nostr->generate_key;
  my $fixture_path = File::Spec->catfile(dirname(__FILE__), 'fixtures', 'valid-native-event.json');
  open my $fixture_fh, '<', $fixture_path or die "Can't read $fixture_path: $!";
  my $fixture_json = do { local $/ = undef; <$fixture_fh> };
  close $fixture_fh or die "close $fixture_path failed: $!";
  my $candidate = JSON::decode_json($fixture_json)->{input};
  my $accepted  = $runtime->accept_emitted_item(
    method    => 'overnet.emit_event',
    item_type => 'event',
    candidate => $candidate,
  );
  ok($accepted->{accepted}, 'a well-formed event emission is accepted');
  is(scalar(@{$runtime->emitted_items}), 1, 'accepted emissions are recorded');

  $runtime->schedule_timer(session_id => 's-1', timer_id => 'keep',   delay_ms => 60_000);
  $runtime->schedule_timer(session_id => 's-1', timer_id => 'cancel', delay_ms => 60_000);
  $runtime->cancel_timer(session_id => 's-1', timer_id => 'cancel');
  ok($runtime->has_timer(session_id => 's-1', timer_id => 'keep'),
    'cancelling one timer keeps its siblings');

  $runtime->open_subscription(session_id => 's-1', subscription_id => 'keep', query => {});
  $runtime->open_subscription(session_id => 's-1', subscription_id => 'close', query => {});
  $runtime->close_subscription(session_id => 's-1', subscription_id => 'close');
  ok($runtime->has_subscription(session_id => 's-1', subscription_id => 'keep'),
    'closing one subscription keeps its siblings');

  my $signed = $key->sign_event_hash(
    event => {kind => 1, created_at => 800, tags => [], content => 'stale'},
  );
  $runtime->publish_nostr_event(relay_url => $relay_url, event => $signed);
  $runtime->open_nostr_subscription(
    session_id      => 's-1',
    subscription_id => 'n-keep',
    relay_url       => $relay_url,
    filters         => [{kinds => [1]}],
    timeout_ms      => 500,
  );
  $runtime->open_nostr_subscription(
    session_id      => 's-1',
    subscription_id => 'n-close',
    relay_url       => $relay_url,
    filters         => [{kinds => [1]}],
  );
  $runtime->close_nostr_subscription(session_id => 's-1', subscription_id => 'n-close');
  ok(
    $runtime->has_nostr_subscription(session_id => 's-1', subscription_id => 'n-keep'),
    'closing one nostr subscription keeps its siblings',
  );
  ok(
    $runtime->read_nostr_subscription_snapshot(
      session_id      => 's-1',
      subscription_id => 'n-keep',
      refresh         => 1,
    ),
    'sub-second subscription timeouts refresh with a floor',
  );

  my $released = $runtime->release_session_resources(session_id => 's-1');
  ok($released->{nostr_subscriptions_closed} >= 1, 'release closes nostr subscriptions');
  ok($released->{timers_canceled} >= 1,            'release cancels timers');

  is(
    Overnet::Program::Runtime::_merge_nostr_snapshot_events('junk', [{id => 'a'}]),
    [{id => 'a'}],
    'non-array snapshot halves are skipped while merging',
  );
  is(
    Overnet::Program::Runtime::_merge_nostr_snapshot_events(
      [{id => 'a'}, 'junk', {note => 'no id'}],
      [{id => 'a'}, {id => 'b'}],
    ),
    [{id => 'a'}, {note => 'no id'}, {id => 'b'}],
    'merged snapshots deduplicate by event id and skip malformed entries',
  );
  $relay->stop;
};

done_testing;
