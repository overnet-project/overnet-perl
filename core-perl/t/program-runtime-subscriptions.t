use strictures 2;
use Test2::V0;
use JSON           ();
use File::Basename qw(dirname);
use File::Spec;

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;
use Overnet::Core::Nostr;
use Overnet::Program::Subscription;

sub _load_fixture_input {
  my ($name) = @_;

  my $path = File::Spec->catfile(dirname(__FILE__), 'fixtures', $name);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;

  return JSON::decode_json($json)->{input};
}

sub _ready_instance {
  my (%args) = @_;

  my $instance = Overnet::Program::Instance->new(%args);
  my $hello    = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'subscriptions.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  return $instance;
}

subtest 'services open subscriptions and queue matching existing emitted outputs' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $event = _load_fixture_input('valid-native-event.json');
  my $state = _load_fixture_input('valid-state-event.json');

  $services->dispatch_request('overnet.emit_event', {event => $event}, permissions => ['overnet.emit_event'],);
  $services->dispatch_request('overnet.emit_state', {state => $state}, permissions => ['overnet.emit_state'],);

  my $opened = $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-1',
      query           => {overnet_et => 'chat.message'},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-1',
  );
  is $opened->{subscription_id}, 'sub-1', 'subscription id returned';

  my $notifications = $runtime->drain_runtime_notifications('session-1');
  is scalar @{$notifications},    1,                             'matching existing item is queued';
  is $notifications->[0]{method}, 'runtime.subscription_event',  'runtime subscription notification is queued';
  is $notifications->[0]{params}{subscription_id}, 'sub-1',      'queued notification records subscription id';
  is $notifications->[0]{params}{item_type},       'event',      'queued notification records item type';
  is $notifications->[0]{params}{data}{id},        $event->{id}, 'queued notification includes matched event payload';
};

subtest 'services reject invalid subscription params and duplicates' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'subscriptions.open',
      {
        subscription_id => 'sub-1',
        query           => {unsupported => 'field'},
      },
      permissions => ['subscriptions.read'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'unsupported query field error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unsupported query field is invalid params';

  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-1',
      query           => {},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-1',
  );

  $error = undef;
  eval {
    $services->dispatch_request(
      'subscriptions.open',
      {
        subscription_id => 'sub-1',
        query           => {},
      },
      permissions => ['subscriptions.read'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'duplicate subscription id error is structured';
  is $error->{code}, 'protocol.invalid_params', 'duplicate subscription id is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'subscriptions.close',
      {subscription_id => 'missing'},
      permissions => ['subscriptions.read'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'unknown close error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown subscription close is invalid params';
};

subtest 'nostr subscription snapshot rejects invalid refresh values as invalid params' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  {
    no warnings qw(redefine);
    local *Overnet::Core::Nostr::query_events = sub { return [] };

    $services->dispatch_request(
      'nostr.open_subscription',
      {
        subscription_id => 'nostr-sub-1',
        relay_url       => 'wss://relay.example.test',
        filters         => [{kinds => [1],},],
      },
      permissions => ['nostr.read'],
      session_id  => 'session-1',
    );

    my $error;
    eval {
      $services->dispatch_request(
        'nostr.read_subscription_snapshot',
        {
          subscription_id => 'nostr-sub-1',
          refresh         => 'definitely',
        },
        permissions => ['nostr.read'],
        session_id  => 'session-1',
      );
      1;
    } or $error = $@;

    is ref($error),              'HASH',                    'invalid refresh error is structured';
    is $error->{code},           'protocol.invalid_params', 'invalid refresh is invalid params';
    is $error->{details}{param}, 'refresh',                 'invalid refresh identifies the refresh parameter';
  }
};

subtest 'closing subscription stops future delivery and clears pending notifications' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $event    = _load_fixture_input('valid-native-event.json');

  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-close',
      query           => {},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-close',
  );

  $services->dispatch_request('overnet.emit_event', {event => $event}, permissions => ['overnet.emit_event'],);

  is scalar @{$runtime->drain_runtime_notifications('other-session')}, 0, 'unrelated session has no notifications';

  $services->dispatch_request(
    'subscriptions.close',
    {subscription_id => 'sub-close'},
    permissions => ['subscriptions.read'],
    session_id  => 'session-close',
  );

  is scalar @{$runtime->drain_runtime_notifications('session-close')}, 0,
    'closing clears pending notifications for that subscription';

  $services->dispatch_request('overnet.emit_event', {event => $event}, permissions => ['overnet.emit_event'],);

  is scalar @{$runtime->drain_runtime_notifications('session-close')}, 0,
    'closed subscription receives no future notifications';
};

subtest 'empty-query subscriptions receive capability notifications' => sub {
  my $runtime    = Overnet::Program::Runtime->new;
  my $services   = Overnet::Program::Services->new(runtime => $runtime);
  my $capability = {
    name    => 'adapter.irc.presence',
    version => '1.0',
    details => {scope => 'channel'},
  };

  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-all',
      query           => {},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-all',
  );
  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-filtered',
      query           => {overnet_et => 'chat.message'},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-filtered',
  );

  $services->dispatch_request(
    'overnet.emit_capabilities',
    {capabilities => [$capability]},
    permissions => ['overnet.emit_capabilities'],
  );

  my $all_notifications = $runtime->drain_runtime_notifications('session-all');
  is(scalar @{$all_notifications},                1, 'empty-query subscription receives capability notification');
  is($all_notifications->[0]{params}{item_type},  'capability',        'notification records capability item type');
  is($all_notifications->[0]{params}{data}{name}, $capability->{name}, 'notification includes capability payload');

  is scalar @{$runtime->drain_runtime_notifications('session-filtered')}, 0,
    'field-filtered subscription does not receive capability notifications';
};

subtest 'instance drains runtime.subscription_event notifications' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    instance_id                 => 'instance-subscriptions',
    supported_protocol_versions => ['0.1'],
    permissions                 => ['subscriptions.read', 'overnet.emit_event', 'overnet.emit_capabilities'],
    service_handler             => $services,
  );

  my $opened = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-open-1',
      method => 'subscriptions.open',
      params => {
        subscription_id => 'sub-1',
        query           => {overnet_et => 'chat.message'},
      },
    )
  );
  ok $opened->{send}{ok}, 'subscriptions.open succeeds through instance';

  my $event   = _load_fixture_input('valid-native-event.json');
  my $emitted = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-emit-1',
      method => 'overnet.emit_event',
      params => {event => $event},
    )
  );
  ok $emitted->{send}{ok}, 'emit_event succeeds through instance';

  my $notifications = $instance->drain_runtime_notifications;
  is scalar @{$notifications},    1,                             'instance drains one runtime notification';
  is $notifications->[0]{type},   'notification',                'drained message is a notification';
  is $notifications->[0]{method}, 'runtime.subscription_event',  'drained method is runtime.subscription_event';
  is $notifications->[0]{params}{subscription_id}, 'sub-1',      'notification records subscription id';
  is $notifications->[0]{params}{item_type},       'event',      'notification records item type';
  is $notifications->[0]{params}{data}{id},        $event->{id}, 'notification includes emitted event payload';

  my $closed = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-close-1',
      method => 'subscriptions.close',
      params => {subscription_id => 'sub-1'},
    )
  );
  ok $closed->{send}{ok}, 'subscriptions.close succeeds through instance';

  $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-emit-2',
      method => 'overnet.emit_event',
      params => {event => $event},
    )
  );
  is scalar @{$instance->drain_runtime_notifications}, 0, 'closed subscription produces no further notifications';

  my $reopened = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-open-2',
      method => 'subscriptions.open',
      params => {
        subscription_id => 'sub-2',
        query           => {},
      },
    )
  );
  ok $reopened->{send}{ok}, 'empty-query subscription opens through instance';
  my $reopened_backlog = $instance->drain_runtime_notifications;
  is scalar @{$reopened_backlog}, 2, 'empty-query subscription replays existing accepted emitted items';

  my $capabilities = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-emit-3',
      method => 'overnet.emit_capabilities',
      params => {
        capabilities => [
          {
            name    => 'adapter.irc.presence',
            version => '1.0',
          },
        ],
      },
    )
  );
  ok $capabilities->{send}{ok}, 'emit_capabilities succeeds through instance';

  my $capability_notifications = $instance->drain_runtime_notifications;
  is scalar @{$capability_notifications}, 1, 'instance drains one capability notification';
  is $capability_notifications->[0]{method}, 'runtime.subscription_event',
    'capability notification method is runtime.subscription_event';
  is $capability_notifications->[0]{params}{subscription_id}, 'sub-2',
    'capability notification records subscription id';
  is $capability_notifications->[0]{params}{item_type}, 'capability', 'capability notification records item type';
  is $capability_notifications->[0]{params}{data}{name},
    'adapter.irc.presence',
    'capability notification includes payload';
};

subtest 'subscription construction and matching edge paths' => sub {
  my %valid = (
    session_id      => 'session-1',
    subscription_id => 'sub-1',
  );

  like(dies { Overnet::Program::Subscription->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(dies { Overnet::Program::Subscription->new(%valid, session_id => q{}) },
    qr/session_id is required/, 'a session id is required');
  like(dies { Overnet::Program::Subscription->new(%valid, subscription_id => q{}) },
    qr/subscription_id is required/, 'a subscription id is required');
  like(dies { Overnet::Program::Subscription->new(%valid, query => 'junk') },
    qr/query must be an object/, 'queries must be objects');

  my $open = Overnet::Program::Subscription->new({%valid});
  is($open->query, {}, 'the query accessor clones the query');
  ok(!$open->matches(item_type => ['ref']), 'reference item types never match');
  ok($open->matches(item_type => 'anything'), 'an empty query matches every item type');

  my $keyed = Overnet::Program::Subscription->new(%valid, query => {overnet_et => 'note'});
  ok(!$keyed->matches(item_type => 'timer'), 'non-content item types never match keyed queries');

  my $kind_query = Overnet::Program::Subscription->new(
    %valid,
    query => {kind => 1_059, overnet_et => 'note'},
  );
  ok(!$kind_query->matches(item_type => 'private_message', data => 'junk'),
    'private messages need object data');
  ok(
    !$kind_query->matches(item_type => 'private_message', data => {transport => 'junk'}),
    'private message kinds need a transport object',
  );
  ok(
    !$kind_query->matches(
      item_type => 'private_message',
      data      => {transport => {kind => 1}, private_type => 'note'},
    ),
    'mismatched private message kinds never match',
  );
  ok(
    !$kind_query->matches(
      item_type => 'private_message',
      data      => {transport => {kind => 1_059}, private_type => 'other'},
    ),
    'mismatched private type fields never match',
  );
  ok(
    $kind_query->matches(
      item_type => 'private_message',
      data      => {transport => {kind => 1_059}, private_type => 'note'},
    ),
    'matching private messages match',
  );

  ok(!$kind_query->matches(item_type => 'event', event => 'junk'),
    'events must be Net::Nostr::Event objects');

  my $key   = Overnet::Core::Nostr->generate_key;
  my $event = Overnet::Core::Nostr->event_from_wire(
    $key->sign_event_hash(
      event => {
        kind       => 1_059,
        created_at => 1,
        content    => q{},
        tags       => [['overnet_et', 'note'], ['overnet_ot', 'channel']],
      },
    ),
  );
  ok(
    $kind_query->matches(item_type => 'event', event => $event->{event}),
    'matching events match',
  );
  my $wrong_kind = Overnet::Program::Subscription->new(%valid, query => {kind => 1});
  ok(!$wrong_kind->matches(item_type => 'event', event => $event->{event}),
    'mismatched event kinds never match');
  my $wrong_tag = Overnet::Program::Subscription->new(%valid, query => {overnet_et => 'other'});
  ok(!$wrong_tag->matches(item_type => 'event', event => $event->{event}),
    'mismatched overnet tags never match');
};

done_testing;
