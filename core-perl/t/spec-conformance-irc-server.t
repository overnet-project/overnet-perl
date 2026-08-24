use strictures 2;

use FindBin;
use File::Spec;
use JSON ();
use Test2::V0;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server',       'lib');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'relay-perl',       'lib');
use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'adapter-irc-perl', 'lib');

my $IRC_SERVER_LIB = File::Spec->rel2abs(File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server', 'lib'));

if (!-d $IRC_SERVER_LIB) {
  skip_all("irc-server checkout not found at $IRC_SERVER_LIB");
}

use Overnet::Test::SpecConformance qw(
  run_irc_server_conformance
);

run_irc_server_conformance();

my $SC = 'Overnet::Test::SpecConformance';

sub _harness {
  my (%input) = @_;
  my ($server, $client_id) = Overnet::Test::SpecConformance::_build_irc_server_harness(\%input);
  return ($server, $client_id);
}

subtest 'harness populates padded and detailed fixture state' => sub {
  my ($server, $client_id) = _harness(
    server_view => {
      connected_clients => 10,
      authority_relay   => {url => 'wss://relay.invalid'},
      channel_topic     => {
        '#topical' => {
          item_type => 'state',
          data      => {
            kind       => 37_800,
            created_at => 1,
            tags       => [],
            content    => JSON::encode_json({body => {topic => 'from view'}}),
          },
        },
        '#untopical' => {item_type => 'event'},
      },
    },
    client      => {registered => 1, nick => 'alice'},
    channels    => [{channel => '#plain', topic => 'plain topic', visible_nicks => ['bob']}, 'junk', {}],
    known_nicks => [
      {nick => 'kn'},
      {nick => 'kn', username => 'ku', realname => 'K N', host => 'kn.example', authority_pubkey => ('c' x 64)},
    ],
    visible_channel_members => ['junk', {channel => '#plain'}, {channel => '#plain', nick => 'carol'}],
    channel_topics          => [{channel => '#told', topic => 'told topic', actor_nick => 'teller'}, 'junk'],
    authoritative_channels  => {'#auth' => 'junk'},
  );

  ok(scalar(keys %{$server->{clients}}) >= 4, 'connected clients were padded');
  my ($unregistered) = grep { ref($_) eq 'HASH' && !$_->{registered} && !defined $_->{nick} }
    values %{$server->{clients}};
  ok($unregistered, 'padding added unregistered stub clients');

  my $kn_id = $server->{nick_to_client_id}{$server->_nick_key('kn')};
  is($server->{clients}{$kn_id}{username},         'ku',         'repeated known nick updates username');
  is($server->{clients}{$kn_id}{realname},         'K N',        'repeated known nick updates realname');
  is($server->{clients}{$kn_id}{peerhost},         'kn.example', 'repeated known nick updates host');
  is($server->{clients}{$kn_id}{authority_pubkey}, ('c' x 64),   'repeated known nick updates authority pubkey');

  is($server->_channel_state('#plain')->{topic_text}, 'plain topic', 'channel entries record topics');
  is($server->_channel_state('#told')->{topic_text},  'told topic',  'channel_topics entries record topics');
  like($server->_channel_state('#told')->{topic_line}, qr/:teller TOPIC \#told :told topic/,
    'channel_topics entries record the topic line');
  is($server->_channel_state('#topical')->{topic_text}, 'from view', 'server_view channel_topic state applies');
  ok(!defined $server->_channel_state('#untopical')->{topic_text}, 'invalid channel_topic items are skipped');
  ok(!$server->{_spec_authoritative_channels}{'#auth'}, 'non-hash authoritative scenarios are skipped');

  ok($server->_authority_relay_enabled, 'server_view authority_relay enables the relay');

  # Stub client helpers reject unusable nicks directly.
  my $next_id = 1000;
  Overnet::Test::SpecConformance::_ensure_stub_client_for_nick($server, \$next_id, undef);
  Overnet::Test::SpecConformance::_ensure_stub_client_for_nick($server, \$next_id, {ref => 1});
  is($next_id, 1000, 'invalid nicks never allocate stub clients');
};

subtest 'harness request dispatch and adapter delegation' => sub {
  my ($server, $client_id) = _harness(client => {registered => 1, nick => 'alice'});

  is($server->_request(method => 'overnet.emit_state',        params => {a => 1}), {}, 'emit_state records');
  is($server->_request(method => 'overnet.emit_capabilities', params => {}),      {}, 'emit_capabilities records');
  is($server->_request(method => 'subscriptions.open',        params => {}),      {}, 'subscriptions.open is a stub');
  is($server->_request(method => 'subscriptions.close',       params => {}),      {}, 'subscriptions.close is a stub');
  is($server->_request(method => 'no.such.method',            params => {}),      {}, 'unknown methods return empty');
  is(scalar(@{$server->{_spec_emits}}), 2, 'emits were recorded');

  my $opened = $server->_request(
    method => 'nostr.open_subscription',
    params => {subscription_id => 'sub-1', filters => [{kinds => [39_000]}]},
  );
  is($opened->{subscription_id}, 'sub-1', 'open_subscription echoes the id');
  my $closed = $server->_request(method => 'nostr.close_subscription', params => {subscription_id => 'sub-1'});
  ok($closed->{closed}, 'close_subscription reports closed');

  my $mapped = $server->_request(method => 'adapters.map_input', params => {});
  ok(ref($mapped) eq 'HASH', 'map_input without input still returns a result');

  my $derived = $server->_request(
    method => 'adapters.derive',
    params => {operation => 'unknown-op', input => {}},
  );
  ok(ref($derived) eq 'HASH', 'derive dispatches to the adapter');

  is($server->_send_message,                  1, 'send_message is stubbed');
  is($server->_log,                           1, 'log is stubbed');
  is($server->_health,                        1, 'health is stubbed');
  is($server->_close_channel_subscription,    1, 'close_channel_subscription is stubbed');
  is($server->_close_client_dm_subscription,  1, 'close_client_dm_subscription is stubbed');

  ok($server->_send_client_line('no-such-client', 'PING'), 'lines for unknown clients are still recorded');
  is($server->{_spec_lines}{'no-such-client'}[0], 'PING', 'undecorated line was recorded verbatim');

  delete $server->{config}{supported_capabilities};
  is([$server->_supported_capabilities], [], 'missing capability config yields no capabilities');
};

subtest 'harness stores published events per channel' => sub {
  my ($server) = _harness(
    server_view => {adapter_config => {authority_profile => 'nip29', group_host => 'groups.example'}},
    client      => {registered => 1, nick => 'alice'},
  );

  Overnet::Test::SpecConformance::IRCServerHarness::_store_published_event($server, 'junk');
  ok(!keys %{$server->{_spec_authoritative_channels}}, 'nothing was stored for a non-hash event');

  my $junk_publish;
  ok(
    lives {
      $junk_publish = $server->_request(method => 'nostr.publish_event', params => {event => 'junk'});
    },
    'publishing a non-hash event does not die',
  );
  ok($junk_publish->{accepted}, 'non-hash events are still accepted');
  ok(!exists $junk_publish->{event_id}, 'non-hash events carry no event id');

  my $missing_publish = $server->_request(method => 'nostr.publish_event', params => {});
  ok($missing_publish->{accepted},         'publishing without an event is accepted');
  ok(!exists $missing_publish->{event_id}, 'publishing without an event carries no event id');

  my $unresolvable = {kind => 1, created_at => 1, content => q{}, tags => []};
  ok($server->_request(method => 'nostr.publish_event', params => {event => $unresolvable})->{accepted},
    'events without a channel binding are accepted');
  ok(!keys %{$server->{_spec_authoritative_channels}}, 'nothing was stored without a channel binding');

  require Overnet::Authority::HostedChannel;
  my (undef, $group_id) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => $server->{config}{network},
    session_config => {group_host => 'groups.example'},
    target         => '#ops',
  );
  my $event = {kind => 39_000, tags => [['d', $group_id]], content => q{}, created_at => 1, id => ('a' x 64)};
  my $published = $server->_request(method => 'nostr.publish_event', params => {event => $event});
  is($published->{event_id}, ('a' x 64), 'published events echo their id');
  $server->_request(method => 'nostr.publish_event', params => {event => $event});
  $server->_request(
    method => 'nostr.publish_event',
    params => {event => {%{$event}, id => undef}},
  );
  $server->_request(
    method => 'nostr.publish_event',
    params => {event => {%{$event}, id => ('b' x 64)}},
  );

  my ($channel_entry) = values %{$server->{_spec_authoritative_channels}};
  is(scalar(@{$channel_entry->{events}}), 3, 'duplicate event ids are stored once');

  ok(
    !Overnet::Test::SpecConformance::IRCServerHarness::_event_id_seen(
      $event, [undef, 'junk', {id => ('c' x 64)}],
    ),
    'unseen ids and malformed stored events do not match',
  );
};

subtest 'harness nostr filter matching' => sub {
  my ($server) = _harness(client => {registered => 1, nick => 'alice'});
  my $h = 'Overnet::Test::SpecConformance::IRCServerHarness';

  is($server->_spec_nostr_events_for_filters(undef), [], 'missing filters match nothing');
  is($server->_spec_nostr_events_for_filters([]),    [], 'empty filters match nothing');

  my $match  = {kind => 39_000, id => ('1' x 64), tags => [['h', 'ops']]};
  my $other  = {kind => 39_001, id => ('2' x 64), tags => [['h', 'ops']]};
  $server->{_spec_authoritative_channels} = {
    '#ops'   => {events => [$match, $match, 'junk', $other]},
    '#empty' => 'junk',
  };

  my $found = $server->_spec_nostr_events_for_filters([{kinds => [39_000]}]);
  is(scalar(@{$found}), 1, 'kind filters deduplicate and select events');

  is($server->_spec_nostr_events_for_filters([{kinds => [40_000]}]), [], 'unmatched kinds select nothing');
  is(scalar(@{$server->_spec_nostr_events_for_filters([{'#h' => ['ops']}])}), 2, 'tag filters select events');
  is($server->_spec_nostr_events_for_filters([{'#h' => ['other']}]), [], 'unmatched tag values select nothing');
  is($server->_spec_nostr_events_for_filters([{'#missing' => ['x']}]), [], 'missing tag names select nothing');

  ok(!$h->can('nope'), 'sanity: harness class is loaded');
  ok(!Overnet::Test::SpecConformance::IRCServerHarness::_spec_event_matches_any_filter($match, ['junk']),
    'non-hash filters never match');
  ok(!Overnet::Test::SpecConformance::IRCServerHarness::_spec_event_matches_filter('junk', {}),
    'non-hash events never match');
  ok(!Overnet::Test::SpecConformance::IRCServerHarness::_spec_event_matches_filter($match, 'junk'),
    'non-hash filter shapes never match');
  ok(
    Overnet::Test::SpecConformance::IRCServerHarness::_spec_event_matches_filter(
      {kind => 1, tags => [['h', 'ops'], 'junk', ['x', 'y']]},
      {'#h' => ['ops']},
    ),
    'malformed tags are skipped while matching',
  );

  is(
    Overnet::Test::SpecConformance::IRCServerHarness::_normalize_adapter_result_for_harness('junk'),
    {},
    'non-hash adapter results normalize to an empty hash',
  );
  is(
    Overnet::Test::SpecConformance::IRCServerHarness::_normalize_adapter_result_for_harness(
      {event => {kind => 37_800}},
    ),
    {event => {kind => 37_800}, state => [{kind => 37_800}]},
    'state-kind events normalize into the state list',
  );
  is(
    Overnet::Test::SpecConformance::IRCServerHarness::_normalize_adapter_result_for_harness(
      {events => [{kind => 9}], extra => 1},
    ),
    {events => [{kind => 9}], extra => 1},
    'results that already carry an events list are returned verbatim',
  );
};

subtest 'channel cache refresh tolerates an empty authoritative event set' => sub {
  my ($server) = _harness(
    server_view => {adapter_config => {authority_profile => 'nip29', group_host => 'groups.example'}},
    client      => {registered => 1, nick => 'alice'},
  );

  ok(!$server->_authority_relay_enabled, 'sanity: the authority relay is disabled');

  my $events;
  ok(
    lives { $events = $server->_refresh_authoritative_nip29_channel_cache('#ops') },
    'refreshing a channel with no stored events does not die',
  );
  is($events, [], 'the refresh reports an empty event set');

  my $canonical = $server->_canonical_channel_name('#ops');
  my $cache     = $server->{authoritative_channel_cache}{$canonical};
  is($cache->{events}, [], 'the cache stores the empty event set');
  ok(exists $cache->{view} && !defined $cache->{view}, 'the cached view is undef when nothing can be derived');
};

subtest 'harness delegates to the real server when the relay is enabled' => sub {
  my ($server) = _harness(
    server_view => {
      adapter_config  => {authority_profile => 'nip29', group_host => 'groups.example'},
      authority_relay => {url => 'wss://relay.invalid'},
    },
    client => {registered => 1, nick => 'alice'},
  );

  ok($server->_authority_relay_enabled, 'relay is enabled');
  ok(defined $server->_ensure_authoritative_discovery_subscription, 'discovery subscription reaches the server');
  ok($server->_refresh_authoritative_discovery_cache(refresh => 1) >= 0, 'discovery refresh reaches the server');
  ok($server->_ensure_authoritative_channel_subscription('#ops'), 'channel subscription reaches the server');
  is($server->_read_authoritative_nip29_events('#ops'), [], 'reading channel events reaches the server');
  ok($server->_refresh_authoritative_nip29_channel_cache('#ops'), 'channel cache refresh reaches the server');
};

subtest 'fixture operations dispatch' => sub {
  my ($server, $client_id) = _harness(
    server_view => {adapter_config => {authority_profile => 'nip29', group_host => 'groups.example'}},
    client      => {registered => 1, nick => 'alice', joined_channels => ['#ops']},
  );

  like(
    dies { Overnet::Test::SpecConformance::_run_irc_server_operation($server, $client_id, 'junk') },
    qr/operation must be an object/,
    'non-hash operations croak',
  );
  like(
    dies { Overnet::Test::SpecConformance::_run_irc_server_operation($server, $client_id, {type => 'bogus'}) },
    qr/Unsupported IRC server fixture operation: bogus/,
    'unknown operation types croak',
  );
  like(
    dies {
      Overnet::Test::SpecConformance::_run_irc_server_operation(
        $server, $client_id, {type => 'set_authoritative_channel_events'},
      )
    },
    qr/operation channel is required/,
    'set_authoritative_channel_events requires a channel',
  );

  my $run = sub {
    my (%operation) = @_;
    return Overnet::Test::SpecConformance::_run_irc_server_operation($server, $client_id, \%operation);
  };

  my $set = $run->(
    type       => 'set_authoritative_channel_events',
    channel    => '#OPS',
    discovered => 1,
    refresh    => 1,
    scenario   => {events => [{type => 'metadata', name => 'ops'}]},
  );
  ok(scalar(@{$set->{events}}), 'set_authoritative_channel_events builds events');
  ok(
    exists $server->{authoritative_discovered_channels}{$set->{channel}},
    'discovered channels are recorded',
  );
  $run->(
    type       => 'set_authoritative_channel_events',
    channel    => '#ops',
    discovered => 0,
    scenario   => {events => [{type => 'metadata', name => 'ops'}]},
  );
  ok(
    !exists $server->{authoritative_discovered_channels}{$set->{channel}},
    'undiscovered channels are removed',
  );

  ok(defined $run->(type => 'refresh_authoritative_discovery_cache', refresh => 1)->{count},
    'discovery refresh operation runs');
  ok($run->(type => 'refresh_authoritative_channel_cache', channel => '#ops', refresh => 1)->{events},
    'channel cache refresh operation runs');
  ok(exists $run->(type => 'ensure_authoritative_discovery_subscription')->{subscription_id},
    'ensure discovery subscription operation runs');
  ok(exists $run->(type => 'ensure_authoritative_channel_subscription', channel => '#ops')->{subscription_ids},
    'ensure channel subscription operation runs');

  my $handled = $run->(
    type            => 'handle_subscription_event',
    subscription_id => 'sub-x',
    event           => 'not-a-hash',
  );
  is($handled->{event}, 'not-a-hash', 'non-hash operation events pass through unchanged');

  my $line = $run->(type => 'line', line => 'PING :token');
  is($line->{line}, 'PING :token', 'line operations echo the line');

  my $view = $run->(type => 'derive_authoritative_channel_view', channel => '#ops', force => 1);
  ok(ref($view) eq 'HASH', 'channel view derivation runs');
  my $admission = $run->(
    type         => 'derive_authoritative_join_admission',
    channel      => '#ops',
    force        => 1,
    join_key     => 'sekrit',
    actor_pubkey => ('a' x 64),
    actor_mask   => 'alice!a@host',
  );
  ok(ref($admission) eq 'HASH', 'join admission derivation runs');

  my $restart = $run->(type => 'simulate_restart');
  is($restart, {restarted => 1}, 'simulated restarts report success');
  $server->{clients}{junk} = 'not-a-hash';
  is($run->(type => 'simulate_restart'), {restarted => 1}, 'restart tolerates malformed clients');
  delete $server->{clients}{junk};

  is(
    Overnet::Test::SpecConformance::_subscription_id_for_fixture_operation(
      $server, {subscription => 'grant'},
    ),
    $server->_authoritative_grant_subscription_id,
    'grant subscription ids resolve',
  );
  my @channel_ids = $server->_authoritative_channel_subscription_ids('#ops');
  is(
    Overnet::Test::SpecConformance::_subscription_id_for_fixture_operation(
      $server, {subscription => 'channel_meta', channel => '#ops'},
    ),
    $channel_ids[0],
    'channel_meta subscription ids resolve',
  );
  is(
    Overnet::Test::SpecConformance::_subscription_id_for_fixture_operation(
      $server, {subscription_id => 'explicit'},
    ),
    'explicit',
    'explicit subscription ids pass through',
  );
};

subtest 'account updates target the right fixture client' => sub {
  my ($server, $client_id) = _harness(client => {registered => 1, nick => 'alice'});
  my $state = {
    input  => {account_update => {nick => 'ghost', account => 'x' x 64}},
    server => $server,
    client => $server->{clients}{$client_id},
  };
  like(
    dies { Overnet::Test::SpecConformance::_apply_irc_account_update($state) },
    qr/No fixture client found for account_update nick ghost/,
    'account updates for unknown nicks croak',
  );

  my $fallback = {
    input  => {account_update => {}},
    server => $server,
    client => $server->{clients}{$client_id},
  };
  ok(lives { Overnet::Test::SpecConformance::_apply_irc_account_update($fallback) },
    'account updates without a nick fall back to the fixture client');
  is(
    Overnet::Test::SpecConformance::_account_update_target_nick({}, {nick => 'alice'}),
    'alice',
    'target nick falls back to the client nick',
  );
};

done_testing;
