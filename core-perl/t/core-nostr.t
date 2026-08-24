use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use IO::Socket::INET ();
use JSON             ();
use Test2::V0;

use AnyEvent;
use AnyEvent::Socket            qw(tcp_server);
use AnyEvent::WebSocket::Server ();
use Net::Nostr::Filter;
use Net::Nostr::Key;
use Net::Nostr::Relay;
use Overnet::Core::Nostr;

my $TIMEOUT_SCALE = $INC{'Devel/Cover.pm'} ? 30 : 1;

sub _scaled_ms {
  my ($ms) = @_;
  return $ms * $TIMEOUT_SCALE;
}

sub _free_port {
  my $sock = IO::Socket::INET->new(
    Listen    => 1,
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or die "Can't allocate free TCP port: $!";

  my $port = $sock->sockport;
  close $sock;
  return $port;
}

sub _start_relay {
  my $port  = _free_port();
  my $relay = Net::Nostr::Relay->new;
  $relay->start('127.0.0.1', $port);
  return ($relay, "ws://127.0.0.1:$port");
}

# A websocket endpoint that completes the handshake and then answers each
# inbound message through the supplied script (or stays mute without one), so
# tests can drive the client-side timeout and dispatch edge paths.
sub _start_scripted_relay {
  my ($script) = @_;
  my $port     = _free_port();
  my $server   = AnyEvent::WebSocket::Server->new;
  my $state    = {conns => []};
  $state->{guard} = tcp_server '127.0.0.1', $port, sub {
    my ($fh) = @_;
    $server->establish($fh)->cb(
      sub {
        my $conn = eval { shift->recv };
        if (!$conn) {
          return;
        }
        push @{$state->{conns}}, $conn;
        $conn->on(
          each_message => sub {
            my ($c, $message) = @_;
            if ($script) {
              $script->($c, JSON::decode_json($message->body));
            }
          },
        );
      },
    );
  };
  return ($state, "ws://127.0.0.1:$port");
}

subtest 'load_key accepts every supported private key encoding' => sub {
  like(dies { Overnet::Core::Nostr->load_key }, qr/privkey is required/, 'a missing privkey croaks');
  like(
    dies { Overnet::Core::Nostr->load_key(privkey => q{}) },
    qr/privkey is required/,
    'an empty privkey croaks',
  );

  my $source = Net::Nostr::Key->new;
  my $hex    = $source->privkey_hex;

  my $from_hex = Overnet::Core::Nostr->load_key(privkey => $hex);
  is($from_hex->pubkey_hex, $source->pubkey_hex, 'hex secrets load');

  my $from_nsec = Overnet::Core::Nostr->load_key(privkey => uc $source->privkey_nsec);
  is($from_nsec->pubkey_hex, $source->pubkey_hex, 'nsec secrets load case-insensitively');

  my $pem_path = File::Spec->catfile(tempdir(CLEANUP => 1), 'key.pem');
  $source->save_privkey($pem_path);
  my $from_path = Overnet::Core::Nostr->load_key(privkey => $pem_path);
  is($from_path->pubkey_hex, $source->pubkey_hex, 'PEM file paths load');

  my $pem = do {
    open my $fh, '<', $pem_path or die "Can't read $pem_path: $!";
    local $/ = undef;
    <$fh>;
  };
  my $from_pem = Overnet::Core::Nostr->load_key(privkey => $pem);
  is($from_pem->pubkey_hex, $source->pubkey_hex, 'inline PEM text loads');
};

subtest 'generate_key and the key wrapper helpers' => sub {
  my $key = Overnet::Core::Nostr->generate_key;
  isa_ok($key, ['Overnet::Core::Nostr::Key'], 'generated keys are wrapped');
  like($key->pubkey_hex, qr/\A[0-9a-f]{64}\z/, 'pubkey_hex returns hex');

  my $event_hash = $key->create_event_hash(
    kind       => 1,
    created_at => 10,
    tags       => [['t', 'x']],
    content    => 'hello',
  );
  is($event_hash->{kind},   1,               'create_event_hash sets the kind');
  is($event_hash->{pubkey}, $key->pubkey_hex, 'create_event_hash signs with the key');

  my $signed = $key->sign_event_hash(event => {kind => 1, created_at => 11, tags => [], content => 'x'});
  is($signed->{created_at}, 11, 'sign_event_hash returns a plain hash');

  my $path = File::Spec->catfile(tempdir(CLEANUP => 1), 'saved.pem');
  $key->save_privkey($path);
  ok(-s $path, 'save_privkey writes the key');
};

subtest 'event_from_wire parses only valid signed events' => sub {
  my $key    = Overnet::Core::Nostr->generate_key;
  my $signed = $key->sign_event_hash(event => {kind => 1, created_at => 12, tags => [['a', 'b']], content => 'hi'});

  my $event = Overnet::Core::Nostr->event_from_wire($signed);
  isa_ok($event, ['Overnet::Core::Nostr::Event'], 'valid wire events parse');
  is($event->id,         $signed->{id},         'id accessor');
  is($event->kind,       1,                     'kind accessor');
  is($event->pubkey,     $signed->{pubkey},     'pubkey accessor');
  is($event->created_at, 12,                    'created_at accessor');
  is($event->content,    'hi',                  'content accessor');
  is($event->tags,       [['a', 'b']],          'tags accessor');
  is($event->to_hash,    $signed,               'to_hash round-trips');
  ok($event->validate,   'validate delegates to the wrapped event');

  is(Overnet::Core::Nostr->event_from_wire({kind => 1}), undef, 'unsigned events do not parse');
};

subtest 'wrap_private_message validates and wraps payloads' => sub {
  my $sender    = Overnet::Core::Nostr->generate_key;
  my $recipient = Overnet::Core::Nostr->generate_key;

  like(
    dies { Overnet::Core::Nostr->wrap_private_message(sender_key => 'nope') },
    qr/key must be an Overnet::Core::Nostr::Key instance/,
    'unwrapped sender keys croak',
  );
  like(
    dies { Overnet::Core::Nostr->wrap_private_message(sender_key => $sender, payload => 'nope') },
    qr/payload must be an object/,
    'non-hash payloads croak',
  );
  like(
    dies {
      Overnet::Core::Nostr->wrap_private_message(sender_key => $sender, payload => {}, recipient_pubkeys => [])
    },
    qr/recipient_pubkeys must be a non-empty array/,
    'empty recipient lists croak',
  );
  like(
    dies {
      Overnet::Core::Nostr->wrap_private_message(
        sender_key        => $sender,
        payload           => {},
        recipient_pubkeys => [q{}],
      )
    },
    qr/recipient_pubkeys must contain non-empty strings/,
    'empty recipient entries croak',
  );
  like(
    dies {
      Overnet::Core::Nostr->wrap_private_message(
        sender_key        => $sender,
        payload           => {},
        recipient_pubkeys => [$recipient->pubkey_hex, []],
      )
    },
    qr/recipient_pubkeys must contain non-empty strings/,
    'reference recipient entries croak',
  );

  my $to_both = Overnet::Core::Nostr->wrap_private_message(
    sender_key        => $sender,
    payload           => {type => 'note'},
    recipient_pubkeys => [$recipient->pubkey_hex],
  );
  isa_ok($to_both->{transport}, ['Overnet::Core::Nostr::Event'], 'wrapping without skip_sender works');

  my $wrapped = Overnet::Core::Nostr->wrap_private_message(
    sender_key        => $sender,
    payload           => {type => 'note', body => 'psst'},
    recipient_pubkeys => [$recipient->pubkey_hex],
    skip_sender       => 1,
  );
  isa_ok($wrapped->{transport},       ['Overnet::Core::Nostr::Event'], 'transport event is wrapped');
  isa_ok($wrapped->{decrypted_rumor}, ['Overnet::Core::Nostr::Event'], 'rumor event is wrapped');
  is(JSON::decode_json($wrapped->{decrypted_rumor}->content), {type => 'note', body => 'psst'},
    'the rumor carries the payload');
};

subtest 'sign_event_hash validates the unsigned event shape' => sub {
  my $key = Overnet::Core::Nostr->generate_key;

  like(
    dies { Overnet::Core::Nostr->sign_event_hash(key => $key, event => 'nope') },
    qr/event must be an object/, 'non-hash events croak',
  );
  like(
    dies { Overnet::Core::Nostr->sign_event_hash(key => $key, event => {}) },
    qr/event kind is required/, 'missing kinds croak',
  );
  like(
    dies { Overnet::Core::Nostr->sign_event_hash(key => $key, event => {kind => 1}) },
    qr/event created_at is required/, 'missing created_at croaks',
  );
  like(
    dies { Overnet::Core::Nostr->sign_event_hash(key => $key, event => {kind => 1, created_at => 1}) },
    qr/event tags must be an array/, 'missing tags croak',
  );
  like(
    dies {
      Overnet::Core::Nostr->sign_event_hash(
        key   => $key,
        event => {kind => 1, created_at => 1, tags => [], content => {}},
      )
    },
    qr/event content must be a string/, 'reference content croaks',
  );
  like(
    dies {
      Overnet::Core::Nostr->sign_event_hash(
        key   => $key,
        event => {kind => 1, created_at => 1, tags => [], pubkey => 'f' x 64},
      )
    },
    qr/event pubkey does not match the signing key/, 'foreign pubkeys croak',
  );

  my $signed = Overnet::Core::Nostr->sign_event_hash(
    key   => $key,
    event => {kind => 1, created_at => 1, tags => [], pubkey => $key->pubkey_hex},
  );
  is($signed->content, q{}, 'missing content defaults to the empty string');
  ok($signed->validate, 'matching pubkeys sign successfully');
};

subtest 'publish_event argument validation' => sub {
  my $key    = Overnet::Core::Nostr->generate_key;
  my $signed = $key->sign_event_hash(event => {kind => 1, created_at => 1, tags => [], content => 'x'});

  like(
    dies { Overnet::Core::Nostr->publish_event(event => $signed) },
    qr/relay_url is required/, 'missing relay urls croak',
  );
  like(
    dies { Overnet::Core::Nostr->publish_event(event => $signed, relay_url => 'ws://x', timeout_ms => 'soon') },
    qr/timeout_ms must be a positive integer/, 'non-numeric timeouts croak',
  );
  like(
    dies { Overnet::Core::Nostr->publish_event(event => 'nope', relay_url => 'ws://x') },
    qr/event must be an object/, 'non-hash events croak',
  );
};

subtest 'publish_event delivers to a local relay and times out without one' => sub {
  my ($relay, $relay_url) = _start_relay();

  my $key    = Overnet::Core::Nostr->generate_key;
  my $signed = $key->sign_event_hash(event => {kind => 1, created_at => 100, tags => [], content => 'live'});

  my $published = Overnet::Core::Nostr->publish_event(
    relay_url  => $relay_url,
    event      => $signed,
    timeout_ms => _scaled_ms(5_000),
  );
  ok($published->{accepted}, 'the relay accepted the wire-hash event');
  is($published->{event_id}, $signed->{id}, 'the event id is echoed');

  my $wrapper = Overnet::Core::Nostr->event_from_wire(
    $key->sign_event_hash(event => {kind => 1, created_at => 101, tags => [], content => 'again'}),
  );
  my $republished = Overnet::Core::Nostr->publish_event(
    relay_url  => $relay_url,
    event      => $wrapper,
    timeout_ms => _scaled_ms(5_000),
  );
  ok($republished->{accepted}, 'wrapped event objects publish too');
  $relay->stop;

  my ($mute, $mute_url) = _start_scripted_relay(undef);
  my $timed_out = Overnet::Core::Nostr->publish_event(
    relay_url  => $mute_url,
    event      => $signed,
    timeout_ms => 500,
  );
  is($timed_out->{accepted}, 0,                   'a mute relay does not accept');
  is($timed_out->{message},  'publish timed out', 'the timeout is reported');

  my ($rejecting, $rejecting_url) = _start_scripted_relay(
    sub {
      my ($conn, $message) = @_;
      if (($message->[0] || q{}) ne 'EVENT') {
        return;
      }
      my $event_id = $message->[1]{id};
      $conn->send(JSON::encode_json(['OK', 'not-the-published-event', JSON::true,  q{}]));
      $conn->send(JSON::encode_json(['OK', $event_id,                JSON::false, 'blocked: rejected']));
    },
  );
  my $rejected = Overnet::Core::Nostr->publish_event(
    relay_url  => $rejecting_url,
    event      => $signed,
    timeout_ms => _scaled_ms(5_000),
  );
  is($rejected->{accepted}, 0, 'a rejecting relay reports the event as not accepted');
  like($rejected->{message}, qr/rejected/, 'the rejection reason is passed through');
};

subtest 'query_events argument validation' => sub {
  like(
    dies { Overnet::Core::Nostr->query_events(filters => [{}]) },
    qr/relay_url is required/, 'missing relay urls croak',
  );
  like(
    dies { Overnet::Core::Nostr->query_events(relay_url => 'ws://x', filters => []) },
    qr/filters must be a non-empty array/, 'empty filter lists croak',
  );
  like(
    dies { Overnet::Core::Nostr->query_events(relay_url => 'ws://x', filters => [{}], timeout_ms => 0) },
    qr/timeout_ms must be a positive integer/, 'zero timeouts croak',
  );
};

subtest 'query_events returns matching relay events' => sub {
  my ($relay, $relay_url) = _start_relay();

  my $key    = Overnet::Core::Nostr->generate_key;
  my $signed = $key->sign_event_hash(event => {kind => 1, created_at => 200, tags => [], content => 'query me'});
  my $published = Overnet::Core::Nostr->publish_event(
    relay_url  => $relay_url,
    event      => $signed,
    timeout_ms => _scaled_ms(5_000),
  );
  ok($published->{accepted}, 'the fixture event was published');

  my $from_hash_filter = Overnet::Core::Nostr->query_events(
    relay_url  => $relay_url,
    filters    => [{kinds => [1]}],
    timeout_ms => _scaled_ms(5_000),
  );
  is(scalar(@{$from_hash_filter}), 1,             'hash filters query events');
  is($from_hash_filter->[0]{id},   $signed->{id}, 'the stored event is returned');

  my $from_filter_object = Overnet::Core::Nostr->query_events(
    relay_url  => $relay_url,
    filters    => [Net::Nostr::Filter->new(kinds => [1])],
    timeout_ms => _scaled_ms(5_000),
  );
  is(scalar(@{$from_filter_object}), 1, 'filter objects query events');

  my $no_match = Overnet::Core::Nostr->query_events(
    relay_url  => $relay_url,
    filters    => [{kinds => [42_424]}],
    timeout_ms => _scaled_ms(5_000),
  );
  is($no_match, [], 'unmatched filters return an empty list');
  $relay->stop;

  my ($mute, $mute_url) = _start_scripted_relay(undef);
  my $timed_out = Overnet::Core::Nostr->query_events(
    relay_url  => $mute_url,
    filters    => [{kinds => [1]}],
    timeout_ms => 500,
  );
  is($timed_out, [], 'a mute relay yields no events after the timeout');
};

subtest 'query_events dispatch edge paths' => sub {
  my $key    = Overnet::Core::Nostr->generate_key;
  my $signed = $key->sign_event_hash(event => {kind => 1, created_at => 300, tags => [], content => 'twice'});

  my ($scripted, $scripted_url) = _start_scripted_relay(
    sub {
      my ($conn, $message) = @_;
      if (($message->[0] || q{}) ne 'REQ') {
        return;
      }
      my $sub_id = $message->[1];
      $conn->send(JSON::encode_json(['EVENT', 'other-subscription', $signed]));
      $conn->send(JSON::encode_json(['EVENT', $sub_id, $signed]));
      $conn->send(JSON::encode_json(['EVENT', $sub_id, $signed]));
      $conn->send(JSON::encode_json(['EOSE',  'other-subscription']));
      $conn->send(JSON::encode_json(['EOSE',  $sub_id]));
    },
  );

  my $events = Overnet::Core::Nostr->query_events(
    relay_url  => $scripted_url,
    filters    => [{kinds => [1]}],
    timeout_ms => _scaled_ms(5_000),
  );
  is(scalar(@{$events}), 1, 'duplicate deliveries and foreign subscriptions are ignored');
  is($events->[0]{id}, $signed->{id}, 'the deduplicated event is returned');

  my ($closing, $closing_url) = _start_scripted_relay(
    sub {
      my ($conn, $message) = @_;
      if (($message->[0] || q{}) ne 'REQ') {
        return;
      }
      $conn->send(JSON::encode_json(['CLOSED', $message->[1], 'gone']));
    },
  );

  my $closed = Overnet::Core::Nostr->query_events(
    relay_url  => $closing_url,
    filters    => [{kinds => [1]}],
    timeout_ms => _scaled_ms(5_000),
  );
  is($closed, [], 'a CLOSED subscription finishes the query empty');
};

done_testing;
