package Overnet::Test::SpecConformance;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);

use Exporter       qw(import);
use File::Basename qw(dirname);
use File::Spec;
use JSON ();
use Overnet::Core::Nostr;
use Overnet::Test::SpecConformance::IRCServerHarness ();
use Scalar::Util                                     qw(reftype);
use Test2::V0;
use Test2::Tools::ClassicCompare qw(is is_deeply);

our $VERSION = '0.001';

our @EXPORT_OK = qw(
  run_auth_agent_conformance
  run_core_validator_conformance
  run_core_provenance_conformance
  run_private_messaging_conformance
  run_irc_adapter_map_conformance
  run_irc_adapter_derived_presence_conformance
  run_irc_adapter_authoritative_conformance
  run_irc_server_conformance
);

sub run_core_validator_conformance {
  require Overnet::Core::Validator;
  my $fixtures_dir = File::Spec->catdir(dirname(__FILE__), q{..}, q{..}, q{..}, q{t}, q{fixtures});
  opendir my $dh, $fixtures_dir
    or croak "Can't open $fixtures_dir: $OS_ERROR";
  my @files = sort grep {/\.json\z/mxs} readdir $dh;
  closedir $dh;

  for my $file (@files) {
    my $fixture  = _load_fixture(File::Spec->catfile($fixtures_dir, $file));
    my $expected = $fixture->{expected} || {};

    subtest "$file - " . ($fixture->{description} || $file) => sub {
      my $result = Overnet::Core::Validator::validate($fixture->{input}, $fixture->{context},);

      is($result->{valid}, $expected->{overnet_valid}, "valid = $expected->{overnet_valid}",);

      if (!$expected->{overnet_valid} && $expected->{reason}) {
        my $found = grep {/\Q$expected->{reason}\E/imxs} @{$result->{errors} || []};
        ok($found, "errors contain: $expected->{reason}");
      }
    };
  }
  return;
}

sub run_core_provenance_conformance {
  require Overnet::Core::Provenance;

  _run_fixture_family(
    family => 'provenance',
    runner => sub {
      my ($fixture) = @_;
      my $expected  = $fixture->{expected} || {};
      my $input     = $fixture->{input}    || {};
      my $result =
        Overnet::Core::Provenance::verify_event($input->{event}, $input->{trusted_authority_records},);

      is($result->{outcome}, $expected->{outcome}, "outcome = $expected->{outcome}",);
    },
  );
  return;
}

sub run_private_messaging_conformance {
  require Overnet::Core::PrivateMessaging;

  _run_fixture_family(
    family => 'private-messaging',
    runner => sub {
      my ($fixture) = @_;
      my $expected  = $fixture->{expected} || {};
      my $result    = Overnet::Core::PrivateMessaging::validate_transport($fixture->{input});

      is($result->{valid}, $expected->{private_transport_valid}, "valid = $expected->{private_transport_valid}",);

      if (!$expected->{private_transport_valid} && $expected->{reason}) {
        my $found = grep {/\Q$expected->{reason}\E/imxs} @{$result->{errors} || []};
        ok($found, "errors contain: $expected->{reason}");
      }

      _assertions($result, $expected->{assertions});
    },
  );
  return;
}

sub run_auth_agent_conformance {
  _run_fixture_family(
    family => 'auth',
    runner => sub {
      my ($fixture) = @_;
      my $input     = $fixture->{input}    || {};
      my $expected  = $fixture->{expected} || {};

      if (ref($input->{request}) eq 'HASH') {
        require Overnet::Auth::Agent;

        my $agent =
          Overnet::Auth::Agent->new(%{$input->{agent} || {}});
        my $response = $agent->dispatch($input->{request});

        if (ref($expected->{response}) eq 'HASH') {
          ok(_subset_match($response, $expected->{response}), 'response contains expected fields',);
        }

        _assertions($response, $expected->{assertions});
        return;
      }

      if ( ref($input->{artifact}) eq 'HASH'
        && ref($input->{bridge}) eq 'HASH') {
        require Overnet::Auth::Bridge::IRC;

        my $wire_output = Overnet::Auth::Bridge::IRC->encode_artifact(
          artifact => $input->{artifact},
          %{$input->{bridge}},
        );
        my $decoded_artifact = Overnet::Auth::Bridge::IRC->decode_artifact(%{$wire_output},);

        if (ref($expected->{wire_output}) eq 'HASH') {
          ok(_subset_match($wire_output, $expected->{wire_output}), 'wire output contains expected fields',);
        }

        if (ref($expected->{decoded_artifact}) eq 'HASH') {
          ok(
            _subset_match($decoded_artifact, $expected->{decoded_artifact}),
            'decoded artifact contains expected fields',
          );
        }

        return;
      }

      croak "Unsupported auth fixture shape\n";
    },
  );
  return;
}

sub run_irc_adapter_map_conformance {
  require Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  _run_fixture_family(
    family => 'irc',
    runner => sub {
      my ($fixture) = @_;
      my $expected  = $fixture->{expected} || {};
      my $result    = $adapter->map_input(%{$fixture->{input} || {}});

      is($result->{valid}, $expected->{overnet_valid}, "valid = $expected->{overnet_valid}",);

      if ($expected->{overnet_valid}) {
        my $got_event        = {%{$result->{event}   || {}}};
        my $expected_event   = {%{$expected->{event} || {}}};
        my $got_content      = delete $got_event->{content};
        my $expected_content = delete $expected_event->{content};

        is_deeply($got_event, $expected_event, 'mapped event envelope matches fixture');
        is_deeply(
          JSON::decode_json($got_content),
          JSON::decode_json($expected_content),
          'mapped event content matches fixture semantically',
        );
      } else {
        is($result->{reason}, $expected->{reason}, 'reason matches fixture');
      }
    },
  );
  return;
}

sub run_irc_adapter_derived_presence_conformance {
  require Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  _run_fixture_family(
    family => 'irc-derived',
    runner => sub {
      my ($fixture) = @_;
      my $expected = $fixture->{expected} || {};
      my $result =
        $adapter->derive_channel_presence(%{$fixture->{input} || {}});

      is($result->{valid}, $expected->{overnet_valid}, "valid = $expected->{overnet_valid}",);

      if ($expected->{overnet_valid}) {
        my $got_event        = {%{$result->{event}   || {}}};
        my $expected_event   = {%{$expected->{event} || {}}};
        my $got_content      = delete $got_event->{content};
        my $expected_content = delete $expected_event->{content};

        is_deeply($got_event, $expected_event, 'derived event envelope matches fixture');
        is_deeply(
          JSON::decode_json($got_content),
          JSON::decode_json($expected_content),
          'derived event content matches fixture semantically',
        );
      } else {
        is($result->{reason}, $expected->{reason}, 'reason matches fixture');
      }
    },
  );
  return;
}

sub run_irc_adapter_authoritative_conformance {
  require Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  _run_fixture_family(
    family => 'irc-authoritative',
    runner => sub {
      my ($fixture) = @_;
      my $input     = $fixture->{input}    || {};
      my $expected  = $fixture->{expected} || {};
      my $result;

      if (defined($input->{command}) && length($input->{command})) {
        $result = $adapter->map_input(%{$input});
      } else {
        my %derive_input   = %{_expanded_authoritative_input($input)};
        my $operation      = delete $derive_input{operation};
        my $session_config = delete $derive_input{session_config};
        $result = $adapter->derive(
          operation      => $operation,
          session_config => $session_config,
          input          => \%derive_input,
        );
      }

      is($result->{valid}, exists($expected->{valid}) ? $expected->{valid} : 1, 'result validity matches fixture',);
      _assertions($result, $expected->{assertions});
    },
  );
  return;
}

sub run_irc_server_conformance {
  _run_fixture_family(
    family => 'irc-server',
    runner => \&_run_irc_server_fixture,
  );
  _run_fixture_family(
    family => 'irc-server-authoritative',
    runner => \&_run_irc_server_fixture,
  );
  _run_fixture_family(
    family => 'irc-server-recovery',
    runner => \&_run_irc_server_fixture,
  );
  return;
}

sub _run_fixture_family {
  my (%args) = @_;
  my $family = $args{family};
  my $runner = $args{runner};

  my @paths = _fixture_files($family);

  if (!@paths) {
    subtest "$family fixtures" => sub {
      skip_all "no $family fixtures available (spec checkout absent)";
    };
    return;
  }

  for my $path (@paths) {
    my $fixture     = _load_fixture($path);
    my $name        = (File::Spec->splitpath($path))[2];
    my $description = $fixture->{description} || $name;

    subtest "$name - $description" => sub {
      $runner->($fixture, $path);
    };
  }
  return;
}

sub _run_irc_server_fixture {
  my ($fixture) = @_;
  my $state = _irc_fixture_state($fixture);

  _apply_irc_account_update($state);
  _apply_irc_fixture_received_lines($state);
  my @operation_results = _run_irc_fixture_operations($state);
  _apply_irc_fixture_commands($state);
  my $render_result = _render_irc_fixture_item($state);
  _add_irc_registration_prelude($state);

  my $lines = _irc_fixture_output_lines($state, $render_result);
  _assert_irc_server_fixture($state, $lines, $render_result, \@operation_results);
  return;
}

sub _irc_fixture_state {
  my ($fixture) = @_;
  my $input     = $fixture->{input}    || {};
  my $expected  = $fixture->{expected} || {};
  my ($server, $client_id) = _build_irc_server_harness($input);
  return {
    input     => $input,
    expected  => $expected,
    server    => $server,
    client_id => $client_id,
    client    => $server->{clients}{$client_id},
  };
}

sub _apply_irc_account_update {
  my ($state) = @_;
  my $input = $state->{input};
  if (!(ref($input->{account_update}) eq 'HASH')) {
    return;
  }

  require Overnet::Program::IRC::Command::Auth;

  my $target_nick   = _account_update_target_nick($input->{account_update}, $state->{client});
  my $target_client = $state->{server}->_client_for_current_nick($target_nick);
  if (!(ref($target_client) eq 'HASH')) {
    croak "No fixture client found for account_update nick $target_nick\n";
  }

  Overnet::Program::IRC::Command::Auth::set_authoritative_account(
    $state->{server},
    $target_client,
    (
      exists($input->{account_update}{account})
      ? (account => $input->{account_update}{account})
      : ()
    ),
  );
  return;
}

sub _account_update_target_nick {
  my ($account_update, $client) = @_;
  my $target_nick = $account_update->{nick};
  if (defined($target_nick) && !ref($target_nick) && length($target_nick)) {
    return $target_nick;
  }
  return $client->{nick};
}

sub _apply_irc_fixture_received_lines {
  my ($state) = @_;
  my $client_spec = _fixture_client_spec($state->{input});
  _apply_irc_fixture_client_lines($state, $client_spec->{received_lines});
  return;
}

sub _run_irc_fixture_operations {
  my ($state) = @_;
  my $operations = $state->{input}{operations};
  if (!(ref($operations) eq 'ARRAY')) {
    return;
  }

  my @results;
  for my $operation (@{$operations}) {
    push @results, _plain_data(_run_irc_server_operation($state->{server}, $state->{client_id}, $operation,));
  }
  return @results;
}

sub _apply_irc_fixture_commands {
  my ($state) = @_;
  _apply_irc_fixture_client_lines($state, $state->{input}{commands});
  if (defined($state->{input}{line}) && !ref($state->{input}{line})) {
    $state->{server}->_handle_client_line($state->{client_id}, $state->{input}{line});
  }
  return;
}

sub _apply_irc_fixture_client_lines {
  my ($state, $lines) = @_;
  if (!(ref($lines) eq 'ARRAY')) {
    return;
  }
  for my $line (@{$lines}) {
    $state->{server}->_handle_client_line($state->{client_id}, $line);
  }
  return;
}

sub _render_irc_fixture_item {
  my ($state) = @_;
  my $item = $state->{input}{item};
  if (!(ref($item) eq 'HASH')) {
    return;
  }

  my %item = %{$item};
  if (($item{item_type} || q{}) ne 'private_message'
    && ref($item{data}) eq 'HASH') {
    $item{data} = _coerce_fixture_wire_event($item{data});
  }
  return $state->{server}->_render_subscription_item(%item);
}

sub _add_irc_registration_prelude {
  my ($state) = @_;
  if (!(_needs_irc_registration_prelude($state))) {
    return;
  }

  my $client_spec = _fixture_client_spec($state->{input});
  my $lines       = Overnet::Program::IRC::Renderer::registration_prelude_lines(
    server_name     => $state->{server}{config}{server_name},
    nick            => $client_spec->{nick},
    isupport_tokens => $state->{server}->_isupport_tokens,
  );
  push @{$state->{server}{_spec_lines}{$state->{client_id}}}, @{$lines};
  return;
}

sub _needs_irc_registration_prelude {
  my ($state)     = @_;
  my $input       = $state->{input};
  my $expected    = $state->{expected};
  my $client_spec = _fixture_client_spec($input);
  return 0 if defined($input->{line});
  return 0 if ref($input->{item});
  return 0 if ref($client_spec->{received_lines});
  return 0 if ref($input->{commands});
  return 0 if !($client_spec->{registered});
  return 0 if !(defined($client_spec->{nick}));
  return 0 if !(ref($expected->{lines}) eq 'ARRAY' && @{$expected->{lines}});
  return 1;
}

sub _irc_fixture_output_lines {
  my ($state, $render_result) = @_;
  my $lines = $state->{server}{_spec_lines}{$state->{client_id}} || [];
  if (ref($render_result) eq 'HASH' && defined($render_result->{line})) {
    return [@{$lines}, $render_result->{line}];
  }
  return $lines;
}

sub _assert_irc_server_fixture {
  my ($state, $lines, $render_result, $operation_results) = @_;
  _assert_irc_fixture_lines($state, $lines);
  _assert_irc_fixture_decorated_lines($state, $render_result);
  _assert_irc_fixture_client($state);
  _assert_irc_fixture_mapped_event($state);
  _assert_irc_fixture_rendered($state, $render_result);
  _assert_irc_fixture_data($state, $render_result, $operation_results);
  return;
}

sub _assert_irc_fixture_lines {
  my ($state, $lines) = @_;
  my $expected = $state->{expected};
  if (ref($expected->{lines}) eq 'ARRAY') {
    ok(_contains_lines_in_order($lines, $expected->{lines}), 'rendered lines contain the expected sequence',);
  }
  return;
}

sub _assert_irc_fixture_decorated_lines {
  my ($state, $render_result) = @_;
  my $expected = $state->{expected};
  if (!(ref($expected->{decorated_lines}) eq 'ARRAY')) {
    return;
  }

  my @decorated;
  if (ref($render_result) eq 'HASH' && defined($render_result->{line})) {
    push @decorated, $state->{server}->_decorate_outbound_line_for_client($state->{client}, $render_result->{line});
  }
  ok(
    _contains_lines_in_order(\@decorated, $expected->{decorated_lines}),
    'decorated rendered lines contain the expected sequence',
  );
  return;
}

sub _assert_irc_fixture_client {
  my ($state)  = @_;
  my $expected = $state->{expected};
  my $client   = $state->{client};

  if (exists $expected->{registered}) {
    is($client->{registered} ? 1 : 0, $expected->{registered} ? 1 : 0, 'registered state matches fixture');
  }
  if (exists $expected->{nick}) {
    is($client->{nick}, $expected->{nick}, 'client nick matches fixture');
  }
  if (ref($expected->{joined_channels}) eq 'ARRAY') {
    is_deeply(
      [sort values %{$client->{joined_channels} || {}}],
      $expected->{joined_channels},
      'joined channels match fixture',
    );
  }
  return;
}

sub _assert_irc_fixture_mapped_event {
  my ($state) = @_;
  my $expected = $state->{expected};

  if (exists $expected->{channel_object_id}) {
    my $tags = _first_tag_values(_last_mapped_event($state->{server})->{tags});
    is($tags->{overnet_oid}, $expected->{channel_object_id}, 'mapped channel object id matches fixture');
  }
  if (exists $expected->{mapped_overnet_et}) {
    my $tags = _first_tag_values(_last_mapped_event($state->{server})->{tags});
    is($tags->{overnet_et},  $expected->{mapped_overnet_et},  'mapped overnet_et matches fixture');
    is($tags->{overnet_ot},  $expected->{mapped_overnet_ot},  'mapped overnet_ot matches fixture');
    is($tags->{overnet_oid}, $expected->{mapped_overnet_oid}, 'mapped overnet_oid matches fixture');
  }
  return;
}

sub _last_mapped_event {
  my ($server) = @_;
  return $server->{_spec_last_emitted_event}
    || (
    ref($server->{_spec_last_map_result}{events}) eq 'ARRAY'
    ? $server->{_spec_last_map_result}{events}[0]
    : undef
    )
    || {};
}

sub _assert_irc_fixture_rendered {
  my ($state, $render_result) = @_;
  my $expected = $state->{expected};
  if (exists $expected->{rendered}) {
    is((ref($render_result) eq 'HASH') ? 1 : 0, $expected->{rendered} ? 1 : 0, 'rendered flag matches fixture');
  }
  return;
}

sub _assert_irc_fixture_data {
  my ($state, $render_result, $operation_results) = @_;
  my $server = $state->{server};
  _assertions(
    {
      server => _plain_data(
        {
          authoritative_discovered_channels   => $server->{authoritative_discovered_channels},
          authoritative_channel_cache         => $server->{authoritative_channel_cache},
          authoritative_subscription_channels => $server->{authoritative_subscription_channels},
        }
      ),
      results => $operation_results,
      client  => _plain_data($state->{client}),
      render  => _plain_data($render_result),
    },
    $state->{expected}{assertions},
  );
  return;
}

sub _run_irc_server_operation {
  my ($server, $client_id, $operation) = @_;
  if (!(ref($operation) eq 'HASH')) {
    croak "fixture operation must be an object\n";
  }

  my $type     = $operation->{type} || q{};
  my %dispatch = (
    refresh_authoritative_discovery_cache => sub { return _op_refresh_discovery($server, $operation); },
    refresh_authoritative_channel_cache   => sub { return _op_refresh_channel_cache($server, $operation); },
    set_authoritative_channel_events      => sub { return _op_set_authoritative_channel_events($server, $operation); },
    ensure_authoritative_discovery_subscription =>
      sub { return {subscription_id => $server->_ensure_authoritative_discovery_subscription,}; },
    ensure_authoritative_channel_subscription =>
      sub { return {subscription_ids => $server->_ensure_authoritative_channel_subscription($operation->{channel}),}; },
    handle_subscription_event           => sub { return _op_handle_subscription_event($server, $operation); },
    simulate_restart                    => sub { return _op_simulate_restart($server); },
    derive_authoritative_channel_view   => sub { return _op_derive_channel_view($server, $operation); },
    derive_authoritative_join_admission => sub { return _op_derive_join_admission($server, $operation); },
    line                                => sub { return _op_line($server, $client_id, $operation); },
  );
  if (!($dispatch{$type})) {
    croak "Unsupported IRC server fixture operation: $type\n";
  }
  return $dispatch{$type}->();
}

sub _op_refresh_discovery {
  my ($server, $operation) = @_;
  return {count => $server->_refresh_authoritative_discovery_cache(($operation->{refresh} ? (refresh => 1) : ()),),};
}

sub _op_refresh_channel_cache {
  my ($server, $operation) = @_;
  return {
    events => $server->_refresh_authoritative_nip29_channel_cache(
      $operation->{channel}, ($operation->{refresh} ? (refresh => 1) : ()),
    ),
  };
}

sub _op_set_authoritative_channel_events {
  my ($server, $operation) = @_;
  my $channel   = $operation->{channel};
  my $canonical = $server->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    croak "operation channel is required\n";
  }
  my $events = _build_authoritative_events(
    session_config => $server->{config}{adapter_config},
    network        => $server->{config}{network},
    target         => $canonical,
    scenario       => $operation->{scenario} || {},
  );
  $server->{_spec_authoritative_channels}{$canonical} ||= {};
  $server->{_spec_authoritative_channels}{$canonical}{events} = $events;
  _set_discovered_channel($server, $canonical, $operation);
  return {channel => $canonical, events => $events};
}

sub _set_discovered_channel {
  my ($server, $canonical, $operation) = @_;
  if (!(exists $operation->{discovered})) {
    return;
  }
  if ($operation->{discovered}) {
    $server->{authoritative_discovered_channels}{$canonical} ||= {channel_name => $canonical,};
    return;
  }
  delete $server->{authoritative_discovered_channels}{$canonical};
  return;
}

sub _op_handle_subscription_event {
  my ($server, $operation) = @_;
  my $event           = _operation_subscription_event($server, $operation);
  my $subscription_id = _subscription_id_for_fixture_operation($server, $operation);
  my $count           = $server->_handle_subscription_event(
    {
      subscription_id => $subscription_id,
      item_type       => 'nostr.event',
      data            => $event,
    }
  );
  return {subscription_id => $subscription_id, count => $count, event => $event};
}

sub _operation_subscription_event {
  my ($server, $operation) = @_;
  return ref($operation->{event}) eq 'HASH'
    ? _build_authoritative_event_hash(
    group_id => scalar(($server->_authoritative_group_binding($operation->{channel}))[1]),
    spec     => $operation->{event},
    )
    : $operation->{event};
}

sub _op_simulate_restart {
  my ($server) = @_;
  delete $server->{authoritative_grant_subscription_id};
  delete $server->{authoritative_discovery_subscription_id};
  delete $server->{authoritative_grant_cache};
  delete $server->{authoritative_discovered_channels};
  delete $server->{authoritative_channel_cache};
  $server->{authoritative_subscription_channels} = {};
  $server->{suppress_subscription_event_ids}     = {};
  _clear_client_authority_seen($server);
  return {restarted => 1};
}

sub _clear_client_authority_seen {
  my ($server) = @_;
  for my $client (values %{$server->{clients} || {}}) {
    if (!(ref($client) eq 'HASH')) {
      next;
    }
    delete $client->{authority_seen_invites};
    delete $client->{authority_seen_requests};
  }
  return;
}

sub _op_derive_channel_view {
  my ($server, $operation) = @_;
  return $server->_derive_authoritative_channel_view(
    $operation->{channel},
    _operation_actor_args($operation),
    ($operation->{force} ? (force => 1) : ()),
  );
}

sub _op_derive_join_admission {
  my ($server, $operation) = @_;
  return $server->_derive_authoritative_join_admission(
    $operation->{channel},
    _operation_actor_args($operation),
    ($operation->{force}             ? (force       => 1)                                    : ()),
    (defined($operation->{join_key}) ? (extra_input => {join_key => $operation->{join_key}}) : ()),
  );
}

sub _operation_actor_args {
  my ($operation) = @_;
  return (
    (defined($operation->{actor_pubkey}) ? (actor_pubkey => $operation->{actor_pubkey}) : ()),
    (defined($operation->{actor_mask})   ? (actor_mask   => $operation->{actor_mask})   : ()),
  );
}

sub _op_line {
  my ($server, $client_id, $operation) = @_;
  $server->_handle_client_line($client_id, $operation->{line});
  return {line => $operation->{line}};
}

sub _subscription_id_for_fixture_operation {
  my ($server, $operation) = @_;
  my $subscription = $operation->{subscription} || q{};

  if ($subscription eq 'discovery') {
    return $server->_authoritative_discovery_subscription_id;
  }

  if ($subscription eq 'grant') {
    return $server->_authoritative_grant_subscription_id;
  }

  if ($subscription eq 'channel_meta' || $subscription eq 'channel_control') {
    my @subscription_ids = $server->_authoritative_channel_subscription_ids($operation->{channel});
    return $subscription eq 'channel_meta'
      ? $subscription_ids[0]
      : $subscription_ids[1];
  }

  return $operation->{subscription_id};
}

sub _build_irc_server_harness {
  my ($input) = @_;
  require Overnet::Program::IRC::Server;
  require Overnet::Program::IRC::Renderer;
  require Overnet::Adapter::IRC;

  my ($server, $adapter_config) = _new_irc_server_harness($input);
  my $server_view    = _fixture_server_view($input);
  my $client_spec    = _fixture_client_spec($input);
  my $next_client_id = 2;

  _populate_current_nicks($server, \$next_client_id, $server_view);
  _populate_known_nicks($server, \$next_client_id, $input);
  _populate_fixture_channels($server, \$next_client_id, $input);
  _populate_server_view_channel_members($server, \$next_client_id, $server_view);
  _populate_visible_channel_members($server, \$next_client_id, $input);
  _populate_fixture_channel_topics($server, $input);
  _populate_server_view_channel_topics($server, $server_view);
  _populate_joined_channels($server, $client_spec);
  _pad_registered_users($server, \$next_client_id, $server_view);
  _pad_connected_clients($server, \$next_client_id, $server_view);
  _pad_channels($server, $server_view);
  _populate_authoritative_channels($server, $adapter_config, $input);

  return ($server, 1);
}

sub _new_irc_server_harness {
  my ($input) = @_;
  my $server = Overnet::Test::SpecConformance::IRCServerHarness->new;

  my $server_view    = _fixture_server_view($input);
  my $adapter_config = _fixture_adapter_config($server_view);
  $server->{config}                       = _fixture_server_config($server_view, $adapter_config);
  $server->{adapter_session_id}           = 'spec-fixture';
  $server->{_spec_adapter}                = Overnet::Adapter::IRC->new;
  $server->{_spec_lines}                  = {};
  $server->{_spec_emits}                  = [];
  $server->{_spec_authoritative_channels} = {};
  $server->{_spec_nostr_subscriptions}    = {};

  _install_primary_fixture_client($server, _fixture_client_spec($input), 1);
  return ($server, $adapter_config);
}

sub _fixture_server_view {
  my ($input) = @_;
  return ref($input->{server_view}) eq 'HASH' ? $input->{server_view} : {};
}

sub _fixture_client_spec {
  my ($input) = @_;
  return ref($input->{client}) eq 'HASH' ? $input->{client} : {};
}

sub _fixture_adapter_config {
  my ($server_view) = @_;
  return ref($server_view->{adapter_config}) eq 'HASH'
    ? {%{$server_view->{adapter_config}}}
    : {};
}

sub _fixture_authority_relay_config {
  my ($server_view, $adapter_config) = @_;
  if (ref($server_view->{authority_relay}) eq 'HASH') {
    return {%{$server_view->{authority_relay}}};
  }
  if (ref($adapter_config->{authority_relay}) eq 'HASH') {
    return {%{$adapter_config->{authority_relay}}};
  }
  return;
}

sub _fixture_server_config {
  my ($server_view, $adapter_config) = @_;
  my $authority_relay = _fixture_authority_relay_config($server_view, $adapter_config);
  return {
    network        => $server_view->{network}     || 'local',
    server_name    => $server_view->{server_name} || 'overnet.irc.local',
    adapter_config => $adapter_config,
    (
      ref($authority_relay) eq 'HASH' ? (authority_relay => $authority_relay)
      : ()
    ),
    use_server_capabilities => $server_view->{use_server_capabilities} ? 1 : 0,
    supported_capabilities  => ref($server_view->{supported_capabilities}) eq 'ARRAY'
    ? [@{$server_view->{supported_capabilities}}]
    : [],
  };
}

sub _install_primary_fixture_client {
  my ($server, $client_spec, $client_id) = @_;
  my $client = {
    id         => $client_id,
    registered => $client_spec->{registered} ? 1 : 0,
    nick       => defined($client_spec->{nick})
    ? $client_spec->{nick}
    : ($client_spec->{registered} ? 'fixture-user' : undef),
    username        => $client_spec->{username},
    realname        => $client_spec->{realname},
    joined_channels => {},
    capabilities    => {},
    socket          => undef,
    peerhost        => $client_spec->{peerhost} || '127.0.0.1',
    peerport        => $client_spec->{peerport} || 6667,

    # A fixture states the presentational host it expects directly, so the
    # server presents it verbatim rather than deriving a transport-address
    # cloak (which is exercised by the implementation's own tests).
    presentational_host => $client_spec->{peerhost} || '127.0.0.1',
  };

  if (defined($client_spec->{authority_pubkey}) && !ref($client_spec->{authority_pubkey})) {
    $client->{authority_pubkey} = $client_spec->{authority_pubkey};
  }
  if (ref($client_spec->{capabilities}) eq 'ARRAY') {
    for my $capability (@{$client_spec->{capabilities}}) {
      $client->{capabilities}{$capability} = 1;
    }
  }
  if ($client->{capabilities}{'overnet-e2ee'}) {
    $client->{e2ee_pubkey} = ('b' x 64);
  }
  $server->{clients}{$client_id} = $client;
  _register_fixture_client_nick($server, $client_id, $client->{nick});
  return;
}

sub _register_fixture_client_nick {
  my ($server, $client_id, $nick) = @_;
  if (!(defined($nick) && length($nick))) {
    return;
  }
  $server->{nick_to_client_id}{$server->_nick_key($nick)} = $client_id;
  return;
}

sub _populate_current_nicks {
  my ($server, $next_client_id_ref, $server_view) = @_;
  for my $nick (@{$server_view->{current_nicks} || []}) {
    _ensure_stub_client_for_nick($server, $next_client_id_ref, $nick);
  }
  return;
}

sub _populate_known_nicks {
  my ($server, $next_client_id_ref, $input) = @_;
  for my $known (@{$input->{known_nicks} || []}) {
    _ensure_known_fixture_client($server, $next_client_id_ref, $known);
  }
  return;
}

sub _ensure_known_fixture_client {
  my ($server, $next_client_id_ref, $known) = @_;
  if (ref($known) eq 'HASH') {
    _ensure_stub_client_for_nick(
      $server,
      $next_client_id_ref,
      $known->{nick},
      username         => $known->{username},
      realname         => $known->{realname},
      host             => $known->{host},
      authority_pubkey => $known->{authority_pubkey},
    );
    return;
  }
  _ensure_stub_client_for_nick($server, $next_client_id_ref, $known);
  return;
}

sub _populate_fixture_channels {
  my ($server, $next_client_id_ref, $input) = @_;
  for my $entry (@{$input->{channels} || []}) {
    if (!(_valid_fixture_channel_entry($entry))) {
      next;
    }
    _apply_fixture_channel_topic($server, $entry);
    for my $nick (@{$entry->{visible_nicks} || []}) {
      _ensure_stub_client_for_nick($server, $next_client_id_ref, $nick);
      $server->_add_visible_nick($entry->{channel}, $nick);
    }
  }
  return;
}

sub _valid_fixture_channel_entry {
  my ($entry) = @_;
  return
       ref($entry) eq 'HASH'
    && defined($entry->{channel})
    && !ref($entry->{channel})
    && length($entry->{channel});
}

sub _apply_fixture_channel_topic {
  my ($server, $entry) = @_;
  if (defined($entry->{topic}) && !ref($entry->{topic})) {
    my $state = $server->_channel_state($entry->{channel});
    $state->{topic_text} = $entry->{topic};
  }
  return;
}

sub _populate_server_view_channel_members {
  my ($server, $next_client_id_ref, $server_view) = @_;
  for my $channel (sort keys %{$server_view->{channel_members} || {}}) {
    for my $nick (@{$server_view->{channel_members}{$channel} || []}) {
      _join_visible_fixture_channel_member($server, $next_client_id_ref, $channel, $nick);
    }
  }
  return;
}

sub _populate_visible_channel_members {
  my ($server, $next_client_id_ref, $input) = @_;
  for my $entry (@{$input->{visible_channel_members} || []}) {
    if (!(_valid_visible_member_entry($entry))) {
      next;
    }
    _join_visible_fixture_channel_member(
      $server,
      $next_client_id_ref,
      $entry->{channel},
      $entry->{nick},
      username         => $entry->{username},
      realname         => $entry->{realname},
      host             => $entry->{host},
      authority_pubkey => $entry->{authority_pubkey},
    );
  }
  return;
}

sub _valid_visible_member_entry {
  my ($entry) = @_;
  return
       ref($entry) eq 'HASH'
    && defined($entry->{channel})
    && !ref($entry->{channel})
    && length($entry->{channel})
    && defined($entry->{nick})
    && !ref($entry->{nick})
    && length($entry->{nick});
}

sub _join_visible_fixture_channel_member {
  my ($server, $next_client_id_ref, $channel, $nick, %opts) = @_;
  my $state = $server->_channel_state($channel);
  _ensure_stub_client_for_nick($server, $next_client_id_ref, $nick, %opts);
  $server->_add_visible_nick($channel, $nick);
  _mark_fixture_channel_membership($server, $state, $channel, $nick);
  return;
}

sub _mark_fixture_channel_membership {
  my ($server, $state, $channel, $nick) = @_;
  my $nick_key = $server->_nick_key($nick);
  if (!(defined $nick_key)) {
    return;
  }
  my $member_id = $server->{nick_to_client_id}{$nick_key};
  if (!(defined $member_id)) {
    return;
  }
  $state->{members}{$member_id} = 1;
  $server->{clients}{$member_id}{joined_channels}{$server->_channel_key($channel)} = $channel;
  return;
}

sub _populate_fixture_channel_topics {
  my ($server, $input) = @_;
  for my $entry (@{$input->{channel_topics} || []}) {
    if (!(_valid_fixture_channel_entry($entry))) {
      next;
    }
    my $state = $server->_channel_state($entry->{channel});
    $state->{topic_text} = $entry->{topic};
    $state->{topic_line} =
      sprintf(':%s TOPIC %s :%s', ($entry->{actor_nick} || 'server'), $entry->{channel}, ($entry->{topic} || q{}),);
  }
  return;
}

sub _populate_server_view_channel_topics {
  my ($server, $server_view) = @_;
  for my $channel (sort keys %{$server_view->{channel_topic} || {}}) {
    my $topic = _topic_from_fixture_item($server_view->{channel_topic}{$channel});
    if (!(ref($topic) eq 'HASH')) {
      next;
    }
    my $state = $server->_channel_state($channel);
    $state->{topic_text} = $topic->{text};
    $state->{topic_line} = sprintf(':%s TOPIC %s :%s', $topic->{nick}, $channel, $topic->{text},);
  }
  return;
}

sub _topic_from_fixture_item {
  my ($item) = @_;
  if (!(ref($item) eq 'HASH' && ($item->{item_type} || q{}) eq 'state' && ref($item->{data}) eq 'HASH')) {
    return;
  }

  my $event_hash = _coerce_fixture_wire_event($item->{data});
  my $content    = eval { JSON::decode_json($event_hash->{content}) };
  if (!(ref($content) eq 'HASH' && ref($content->{body}) eq 'HASH')) {
    return;
  }
  if (!(defined($content->{body}{topic}) && !ref($content->{body}{topic}))) {
    return;
  }

  return {
    nick => _topic_nick_from_content($content),
    text => $content->{body}{topic},
  };
}

sub _topic_nick_from_content {
  my ($content) = @_;
  my $nick =
    ref($content->{provenance}) eq 'HASH'
    ? $content->{provenance}{external_identity}
    : undef;
  if (defined($nick) && !ref($nick) && length($nick)) {
    return $nick;
  }
  return 'server';
}

sub _populate_joined_channels {
  my ($server, $client_spec) = @_;
  for my $channel (@{$client_spec->{joined_channels} || []}) {
    $server->_add_client_to_channel(1, $channel);
  }
  return;
}

sub _pad_registered_users {
  my ($server, $next_client_id_ref, $server_view) = @_;
  while (_registered_client_count($server) < ($server_view->{registered_users} || 0)) {
    _ensure_stub_client_for_nick($server, $next_client_id_ref, 'fixture-reg-' . ${$next_client_id_ref});
  }
  return;
}

sub _registered_client_count {
  my ($server) = @_;
  my $count = 0;
  for my $client (values %{$server->{clients} || {}}) {
    if (ref($client) eq 'HASH' && $client->{registered}) {
      $count++;
    }
  }
  return $count;
}

sub _pad_connected_clients {
  my ($server, $next_client_id_ref, $server_view) = @_;
  while (scalar(keys %{$server->{clients}}) < ($server_view->{connected_clients} || 0)) {
    _add_unregistered_fixture_client($server, $next_client_id_ref);
  }
  return;
}

sub _add_unregistered_fixture_client {
  my ($server, $next_client_id_ref) = @_;
  my $id = ${$next_client_id_ref};
  ${$next_client_id_ref}++;
  $server->{clients}{$id} = {
    id                  => $id,
    registered          => 0,
    joined_channels     => {},
    capabilities        => {},
    socket              => undef,
    peerhost            => '127.0.0.1',
    peerport            => 6667 + $id,
    presentational_host => '127.0.0.1',
  };
  return;
}

sub _pad_channels {
  my ($server, $server_view) = @_;
  while (scalar(keys %{$server->{channels}}) < ($server_view->{channels} || 0)) {
    my $channel = '#fixture' . scalar(keys %{$server->{channels}});
    $server->_channel_state($channel);
  }
  return;
}

sub _populate_authoritative_channels {
  my ($server, $adapter_config, $input) = @_;
  for my $channel (sort keys %{$input->{authoritative_channels} || {}}) {
    _populate_authoritative_channel($server, $adapter_config, $channel, $input->{authoritative_channels}{$channel});
  }
  return;
}

sub _populate_authoritative_channel {
  my ($server, $adapter_config, $channel, $scenario) = @_;
  if (!(ref($scenario) eq 'HASH')) {
    return;
  }
  my $canonical = $server->_canonical_channel_name($channel);
  my $events    = _build_authoritative_events(
    session_config => $adapter_config,
    network        => $server->{config}{network},
    target         => $channel,
    scenario       => $scenario->{scenario} || {},
  );
  $server->{_spec_authoritative_channels}{$canonical} = {events => $events};
  if (!exists($scenario->{discovered}) || $scenario->{discovered}) {
    $server->{authoritative_discovered_channels}{$canonical} = {channel_name => $canonical};
  }
  return;
}

sub _ensure_stub_client_for_nick {
  my ($server, $next_client_id_ref, $nick, %opts) = @_;
  if (!(defined $nick && !ref($nick) && length($nick))) {
    return;
  }
  my $nick_key = $server->_nick_key($nick);
  if (!(defined $nick_key)) {
    return;
  }
  if (exists $server->{nick_to_client_id}{$nick_key}) {
    my $client_id = $server->{nick_to_client_id}{$nick_key};
    my $client    = $server->{clients}{$client_id};
    if (ref($client) eq 'HASH') {
      if (defined $opts{username}) {
        $client->{username} = $opts{username};
      }
      if (defined $opts{realname}) {
        $client->{realname} = $opts{realname};
      }
      if (defined $opts{host}) {
        $client->{peerhost}            = $opts{host};
        $client->{presentational_host} = $opts{host};
      }
      if (defined $opts{authority_pubkey}) {
        $client->{authority_pubkey} = $opts{authority_pubkey};
      }
    }
    return;
  }

  my $id = ${$next_client_id_ref};
  ${$next_client_id_ref}++;
  $server->{clients}{$id} = {
    id                  => $id,
    registered          => 1,
    nick                => $nick,
    username            => defined($opts{username}) ? $opts{username} : lc($nick),
    realname            => defined($opts{realname}) ? $opts{realname} : $nick,
    joined_channels     => {},
    capabilities        => {},
    socket              => undef,
    peerhost            => defined($opts{host}) ? $opts{host} : '127.0.0.1',
    peerport            => 6667 + $id,
    presentational_host => defined($opts{host}) ? $opts{host} : '127.0.0.1',
    (
      defined($opts{authority_pubkey})
      ? (authority_pubkey => $opts{authority_pubkey})
      : ()
    ),
  };
  $server->{nick_to_client_id}{$nick_key} = $id;
  return;
}

sub _expanded_authoritative_input {
  my ($input)      = @_;
  my %expanded     = %{$input || {}};
  my $nested_input = delete $expanded{input};
  if (ref($nested_input) eq 'HASH') {
    my %inner = %{$nested_input};
    if (ref($inner{authoritative_scenario}) eq 'HASH') {
      $inner{authoritative_events} = _build_authoritative_events(
        session_config => $expanded{session_config},
        network        => $inner{network},
        target         => $inner{target},
        scenario       => $inner{authoritative_scenario},
      );
      delete $inner{authoritative_scenario};
    }
    $expanded{input} = \%inner;
  }
  if (ref($expanded{input}) eq 'HASH') {
    return \%expanded;
  }

  if (ref($expanded{authoritative_scenario}) eq 'HASH') {
    $expanded{authoritative_events} = _build_authoritative_events(
      session_config => $expanded{session_config},
      network        => $expanded{network},
      target         => $expanded{target},
      scenario       => $expanded{authoritative_scenario},
    );
    delete $expanded{authoritative_scenario};
  }

  return \%expanded;
}

sub _build_authoritative_events {
  my (%args) = @_;
  require Overnet::Authority::HostedChannel;
  require Net::Nostr::Event;
  require Net::Nostr::Group;

  my $scenario = $args{scenario} || {};
  if (!(ref($scenario) eq 'HASH')) {
    return [];
  }
  my $events = $scenario->{events} || [];
  if (!(ref($events) eq 'ARRAY')) {
    croak "authoritative_scenario.events must be an array\n";
  }

  my (undef, $group_id, $error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => $args{network},
    session_config => $args{session_config},
    target         => $args{target},
  );
  if (defined $error) {
    croak "$error\n";
  }

  my @built;
  for my $spec (@{$events}) {
    if (!(ref($spec) eq 'HASH')) {
      croak "authoritative_scenario event must be an object\n";
    }
    push @built,
      _build_authoritative_event_hash(
      group_id => $group_id,
      spec     => $spec,
      );
  }

  return \@built;
}

sub _build_authoritative_event_hash {
  my (%args) = @_;
  require Net::Nostr::Event;
  require Net::Nostr::Group;

  my $spec       = $args{spec};
  my $event_hash = _authoritative_event_hash_for_type(
    group_id => $args{group_id},
    spec     => $spec,
  );

  if (defined($spec->{actor_pubkey})) {
    push @{$event_hash->{tags}},
      ['overnet_actor',     $spec->{actor_pubkey}],
      ['overnet_authority', $spec->{authority_event_id}],
      ['overnet_sequence',  0 + $spec->{authority_sequence}];
  }

  return $event_hash;
}

sub _authoritative_event_hash_for_type {
  my (%args)   = @_;
  my $spec     = $args{spec};
  my $type     = $spec->{type} || q{};
  my %dispatch = (
    metadata      => sub { return _group_metadata_event(%args, edit => 0); },
    metadata_edit => sub { return _group_metadata_event(%args, edit => 1); },
    admins        => sub { return _group_membership_event(admins  => %args); },
    members       => sub { return _group_membership_event(members => %args); },
    roles         => sub { return _group_roles_event(%args); },
    put_user      => sub { return _group_put_user_event(%args); },
    remove_user   => sub { return _group_remove_user_event(%args); },
    invite        => sub { return _group_invite_event(%args); },
    join          => sub { return _group_join_event(%args); },
    part          => sub { return _group_part_event(%args); },
  );
  if (!($dispatch{$type})) {
    croak "Unsupported authoritative_scenario event type: $type\n";
  }
  return $dispatch{$type}->();
}

sub _group_event_args {
  my (%args) = @_;
  my $spec = $args{spec};
  return (
    pubkey     => $spec->{pubkey} || ('f' x 64),
    group_id   => $args{group_id},
    created_at => $spec->{created_at} || 0,
  );
}

sub _group_metadata_event {
  my (%args) = @_;
  my $spec = $args{spec};
  my $event =
    $args{edit}
    ? Net::Nostr::Group->edit_metadata(_group_event_args(%args), _metadata_args($spec),)
    : Net::Nostr::Group->metadata(_group_event_args(%args), _metadata_args($spec),);
  my $event_hash = $event->to_hash;
  _apply_metadata_tags($event_hash, $spec);
  return $event_hash;
}

sub _metadata_args {
  my ($spec) = @_;
  return (
    (defined($spec->{name}) ? (name       => $spec->{name}) : ()),
    ($spec->{closed}        ? (closed     => 1)             : ()),
    ($spec->{private}       ? (private    => 1)             : ()),
    ($spec->{restricted}    ? (restricted => 1)             : ()),
    ($spec->{hidden}        ? (hidden     => 1)             : ()),
  );
}

sub _group_membership_event {
  my ($kind, %args) = @_;
  my $event =
    $kind eq 'admins'
    ? Net::Nostr::Group->admins(_group_event_args(%args), members => $args{spec}{members} || [],)
    : Net::Nostr::Group->members(_group_event_args(%args), members => $args{spec}{members} || [],);
  return $event->to_hash;
}

sub _group_roles_event {
  my (%args) = @_;
  my @roles  = map { ref eq 'HASH' ? $_ : {name => $_} } @{$args{spec}{roles} || []};
  my $event  = Net::Nostr::Group->roles(_group_event_args(%args), roles => \@roles,);
  return $event->to_hash;
}

sub _group_put_user_event {
  my (%args) = @_;
  my $event = Net::Nostr::Group->put_user(
    _group_event_args(%args),
    target => $args{spec}{target_pubkey},
    roles  => $args{spec}{roles} || [],
  );
  return $event->to_hash;
}

sub _group_remove_user_event {
  my (%args) = @_;
  my $event = Net::Nostr::Group->remove_user(
    _group_event_args(%args),
    target => $args{spec}{target_pubkey},
    reason => $args{spec}{reason} || q{},
  );
  return $event->to_hash;
}

sub _group_invite_event {
  my (%args)     = @_;
  my $spec       = $args{spec};
  my $event_hash = Net::Nostr::Group->create_invite(
    _group_event_args(%args),
    code   => $spec->{code},
    reason => $spec->{reason} || q{},
  )->to_hash;
  if (defined $spec->{target_pubkey}) {
    push @{$event_hash->{tags}}, ['p', $spec->{target_pubkey}];
  }
  return $event_hash;
}

sub _group_join_event {
  my (%args)     = @_;
  my $spec       = $args{spec};
  my $event_hash = Net::Nostr::Group->join_request(
    _group_event_args(%args),
    (defined($spec->{code}) ? (code => $spec->{code}) : ()),
    reason => $spec->{reason} || q{},
  )->to_hash;
  if (defined $spec->{actor_mask}) {
    push @{$event_hash->{tags}}, ['overnet_irc_mask', $spec->{actor_mask}];
  }
  return $event_hash;
}

sub _group_part_event {
  my (%args) = @_;
  my $event = Net::Nostr::Group->leave_request(_group_event_args(%args), reason => $args{spec}{reason} || q{},);
  return $event->to_hash;
}

sub _apply_metadata_tags {
  my ($event_hash, $spec) = @_;
  if ($spec->{moderated}) {
    push @{$event_hash->{tags}}, ['mode', 'moderated'];
  }
  if ($spec->{topic_restricted}) {
    push @{$event_hash->{tags}}, ['mode', 'topic-restricted'];
  }
  push @{$event_hash->{tags}}, map { ['ban',           $_] } @{$spec->{ban_masks}              || []};
  push @{$event_hash->{tags}}, map { ['except',        $_] } @{$spec->{except_masks}           || []};
  push @{$event_hash->{tags}}, map { ['invite-except', $_] } @{$spec->{invite_exception_masks} || []};
  if (exists $spec->{key}) {
    push @{$event_hash->{tags}}, ['key', $spec->{key}];
  }
  if (exists $spec->{user_limit}) {
    push @{$event_hash->{tags}}, ['limit', 0 + $spec->{user_limit}];
  }
  if (exists $spec->{topic}) {
    push @{$event_hash->{tags}}, ['topic', $spec->{topic}];
  }
  if ($spec->{tombstoned}) {
    push @{$event_hash->{tags}}, ['status', 'tombstoned'];
  }
  return;
}

sub _coerce_fixture_wire_event {
  my ($event_hash) = @_;
  my $missing;

  if (!(ref($event_hash) eq 'HASH')) {
    return $missing;
  }

  my $parsed = Overnet::Core::Nostr->event_from_wire($event_hash);
  if ($parsed) {
    return {%{$event_hash}};
  }

  my %unsigned = %{$event_hash};
  delete @unsigned{qw(id pubkey sig)};
  my $key = Overnet::Core::Nostr->generate_key;
  return $key->sign_event_hash(event => \%unsigned);
}

sub _fixture_files {
  my ($family) = @_;
  my $dir = _fixture_dir($family);
  if (!(-d $dir)) {
    return ();
  }

  opendir my $dh, $dir or croak "Can't open $dir: $OS_ERROR";
  my @files = sort grep {/\.json\z/mxs} readdir $dh;
  closedir $dh;
  return map { File::Spec->catfile($dir, $_) } @files;
}

sub _fixture_dir {
  my ($family) = @_;
  return File::Spec->catdir(_spec_root(), 'fixtures', $family);
}

sub _spec_root {
  for my $dir (
    File::Spec->catdir(dirname(__FILE__), q{..}, q{..}, q{..}, q{..}, q{spec}),
    File::Spec->catdir(dirname(__FILE__), q{..}, q{..}, q{..}, q{..}, q{..}, q{spec}),
  ) {
    my $abs = File::Spec->rel2abs($dir);
    if (-d $abs) {
      return $abs;
    }
  }

  return File::Spec->rel2abs(File::Spec->catdir(dirname(__FILE__), q{..}, q{..}, q{..}, q{..}, q{spec}),);
}

sub _load_fixture {
  my ($path) = @_;
  open my $fh, '<', $path or croak "Can't read $path: $OS_ERROR";
  my $json = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  close $fh
    or croak "close $path failed: $OS_ERROR";
  return JSON::decode_json($json);
}

sub _assertions {
  my ($root, $assertions) = @_;
  if (!(ref($assertions) eq 'ARRAY')) {
    return;
  }

  for my $assertion (@{$assertions}) {
    my $path  = $assertion->{path};
    my $value = _path_get($root, $path);

    if (exists $assertion->{equals}) {
      is_deeply($value, $assertion->{equals}, "$path equals expected value");
      next;
    }

    if ($assertion->{missing}) {
      ok(!defined($value), "$path is missing");
      next;
    }

    fail("Unsupported assertion shape for path $path");
  }
  return;
}

sub _subset_match {
  my ($got, $expected) = @_;

  if (!defined($expected)) {
    return !defined($got);
  }

  if (ref($expected) eq 'HASH') {
    if (!(ref($got) eq 'HASH')) {
      return 0;
    }
    for my $key (keys %{$expected}) {
      if (!(exists $got->{$key})) {
        return 0;
      }
      if (!(_subset_match($got->{$key}, $expected->{$key}))) {
        return 0;
      }
    }
    return 1;
  }

  if (ref($expected) eq 'ARRAY') {
    if (!(ref($got) eq 'ARRAY')) {
      return 0;
    }
    if (!(@{$got} == @{$expected})) {
      return 0;
    }
    for my $idx (0 .. $#{$expected}) {
      if (!(_subset_match($got->[$idx], $expected->[$idx]))) {
        return 0;
      }
    }
    return 1;
  }

  return defined($got) && $got eq $expected;
}

sub _plain_data {
  my ($value) = @_;
  my $missing;

  if (!(defined $value)) {
    return $missing;
  }
  if (!(ref($value))) {
    return $value;
  }

  my $type = reftype($value) || q{};
  if ($type eq 'HASH') {
    return {
      map { $_ => _plain_data($value->{$_}) }
      sort keys %{$value}
    };
  }
  if ($type eq 'ARRAY') {
    return [map { _plain_data($_) } @{$value}];
  }

  return "$value";
}

sub _path_get {
  my ($root, $path) = @_;
  my $missing;

  if (!(defined $path && length $path)) {
    return $root;
  }

  my @parts = split /\./mxs, $path;
  my $value = $root;
  for my $part (@parts) {
    if (!(defined $value)) {
      return $missing;
    }

    if (ref($value) eq 'HASH') {
      $value = $value->{$part};
      next;
    }

    if (ref($value) eq 'ARRAY' && $part =~ /\A\d+\z/mxs) {
      $value = $value->[$part];
      next;
    }

    return $missing;
  }

  return $value;
}

sub plain_data_for_harness {
  my ($value) = @_;
  return _plain_data($value);
}

sub _contains_lines_in_order {
  my ($got, $expected) = @_;
  if (!(ref($got) eq 'ARRAY' && ref($expected) eq 'ARRAY')) {
    return 0;
  }
  if (!(@{$expected})) {
    return 1;
  }

  my $cursor = 0;
  for my $line (@{$got}) {
    if (!(defined $line && defined $expected->[$cursor])) {
      next;
    }
    if (_line_matches($line, $expected->[$cursor])) {
      $cursor++;
      if ($cursor >= @{$expected}) {
        return 1;
      }
    }
  }

  return 0;
}

sub _line_matches {
  my ($got, $expected) = @_;
  if (!(defined $got && defined $expected)) {
    return 0;
  }
  if ($got eq $expected) {
    return 1;
  }

  if (index($expected, '<base64_json_transport>') >= 0) {
    my $pattern = quotemeta($expected);
    $pattern =~ s/\\<base64_json_transport\\>/\\S+/gmxs;
    return $got =~ /\A$pattern\z/mxs ? 1 : 0;
  }

  return 0;
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    if (exists $values{$tag->[0]}) {
      next;
    }
    $values{$tag->[0]} = $tag->[1];
  }

  return \%values;
}

1;

=head1 NAME

Overnet::Test::SpecConformance - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Test::SpecConformance;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 run_core_validator_conformance

Public API entry point.

=head2 run_core_provenance_conformance

Public API entry point.

=head2 run_private_messaging_conformance

Public API entry point.

=head2 run_auth_agent_conformance

Public API entry point.

=head2 run_irc_adapter_map_conformance

Public API entry point.

=head2 run_irc_adapter_derived_presence_conformance

Public API entry point.

=head2 run_irc_adapter_authoritative_conformance

Public API entry point.

=head2 run_irc_server_conformance

Public API entry point.

=head2 plain_data_for_harness

Returns a plain data copy for the IRC server conformance harness.

=head1 DIAGNOSTICS

This module reports errors through normal Perl exceptions or structured return values.

=head1 CONFIGURATION AND ENVIRONMENT

No module-specific environment configuration is required.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

No known bugs are documented.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
