use strictures 2;

use File::Spec;
use Socket qw(AF_UNIX PF_UNSPEC SOCK_STREAM);
use Test::More;

use JSON ();
use Overnet::Auth::Agent;
use Overnet::Auth::SocketIO;
use Overnet::Program::Protocol;
use Overnet::Auth::Client;
use Overnet::Auth::Server;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

subtest 'agent_info discovers the endpoint from OVERNET_AUTH_SOCK' => sub {
  _with_auth_server(
    agent       => Overnet::Auth::Agent->new,
    connections => 1,
    run         => sub {
      my (%args) = @_;
      local $ENV{OVERNET_AUTH_SOCK} = $args{endpoint};

      my $client   = Overnet::Auth::Client->new(socket_factory => $args{socket_factory},);
      my $response = $client->agent_info;

      is $response->{ok},                       1,       'agent.info succeeds';
      is $response->{result}{protocol_version}, '0.2.0', 'protocol version is returned';
      ok scalar grep { $_ eq 'sessions.authorize' }
        @{$response->{result}{capabilities} || []},
        'capabilities include sessions.authorize';
      ok scalar grep { $_ eq 'policies.grant' }
        @{$response->{result}{capabilities} || []},
        'capabilities include policies.grant';
      ok scalar grep { $_ eq 'service_pins.set' }
        @{$response->{result}{capabilities} || []},
        'capabilities include service_pins.set';
      ok scalar grep { $_ eq 'sessions.list' }
        @{$response->{result}{capabilities} || []},
        'capabilities include sessions.list';
    },
  );
};

subtest 'sessions_authorize returns a signed auth artifact through the socket client' => sub {
  _with_auth_server(
    agent => Overnet::Auth::Agent->new(
      allow_unattended_autoapprove => 1,
      identities                   => [
        {
          identity_id    => 'default',
          backend_type   => 'direct_secret',
          backend_config => {
            secret => $fixture_secret,
          },
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => $fixture_pubkey,
          },
        },
      ],
    ),
    connections => 1,
    run         => sub {
      my (%args) = @_;

      my $client = Overnet::Auth::Client->new(
        endpoint       => $args{endpoint},
        socket_factory => $args{socket_factory},
      );
      my $response = $client->sessions_authorize(
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      );

      is $response->{ok},                  1,         'sessions.authorize succeeds';
      is $response->{result}{identity_id}, 'default', 'response identifies the selected identity';
      is $response->{result}{artifacts}[0]{value}{pubkey},
        $fixture_pubkey,
        'the returned auth artifact is signed by the configured identity';
    },
  );
};

subtest 'sessions_authorize preserves structured error responses' => sub {
  _with_auth_server(
    agent => Overnet::Auth::Agent->new(
      identities => [
        {
          identity_id    => 'default',
          backend_type   => 'direct_secret',
          backend_config => {
            secret => $fixture_secret,
          },
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => $fixture_pubkey,
          },
        },
      ],
    ),
    connections => 1,
    run         => sub {
      my (%args) = @_;

      my $client = Overnet::Auth::Client->new(
        endpoint       => $args{endpoint},
        socket_factory => $args{socket_factory},
      );
      my $response = $client->sessions_authorize(
        program_id  => 'irc.bridge',
        identity_id => 'default',
        interactive => 0,
        service     => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      );

      is $response->{ok},          0,                      'sessions.authorize fails';
      is $response->{error}{code}, 'auth.headless_unavailable', 'the auth-agent error response is preserved';
    },
  );
};

subtest 'policies.list, service_pins.set, and sessions.list work through the socket client' => sub {
  _with_auth_server(
    agent => Overnet::Auth::Agent->new(
      service_pins => {
        'wss://relay.example.test/auth' => {
          scheme => 'nostr.pubkey',
          value  => ('1' x 64),
        },
      },
      sessions => [
        {
          session_handle => {id => 'sess-1'},
          identity_id    => 'default',
          program_id     => 'irc.bridge',
          service        => {
            locators => ['wss://relay.example.test/auth'],
          },
          scope     => 'irc://irc.example.test/overnet',
          action    => 'session.authenticate',
          renewable => 1,
          artifacts => [],
        },
      ],
      policies => [
        {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => ['wss://relay.example.test/auth'],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
    ),
    connections => 3,
    run         => sub {
      my (%args) = @_;

      my $client = Overnet::Auth::Client->new(
        endpoint       => $args{endpoint},
        socket_factory => $args{socket_factory},
      );

      my $policies = $client->policies_list;
      my $set_pin  = $client->service_pins_set(
        locator          => 'wss://relay2.example.test/auth',
        service_identity => {
          scheme => 'nostr.pubkey',
          value  => ('2' x 64),
        },
      );
      my $sessions = $client->sessions_list;

      is $policies->{ok},                             1,                 'policies.list succeeds';
      is $policies->{result}{policies}[0]{policy_id}, 'policy-1',        'policy ids are returned over the client';
      is $set_pin->{ok},                              1,                 'service_pins.set succeeds';
      is $set_pin->{result}{locator}, 'wss://relay2.example.test/auth',  'service_pins.set returns the locator';
      is $sessions->{ok},             1,                                 'sessions.list succeeds';
      is $sessions->{result}{sessions}[0]{session_handle}{id}, 'sess-1', 'sessions.list returns stored sessions';
    },
  );
};

subtest 'policies.grant, policies.revoke, service_pins.list, and service_pins.forget work through the socket client' =>
  sub {
  _with_auth_server(
    agent => Overnet::Auth::Agent->new(
      service_pins => {
        'wss://relay.example.test/auth' => {
          scheme => 'nostr.pubkey',
          value  => ('1' x 64),
        },
      },
    ),
    connections => 4,
    run         => sub {
      my (%args) = @_;

      my $client = Overnet::Auth::Client->new(
        endpoint       => $args{endpoint},
        socket_factory => $args{socket_factory},
      );

      my $grant = $client->policies_grant(
        policy => {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          service     => {
            locators         => ['wss://relay.example.test/auth'],
            service_identity => {
              scheme => 'nostr.pubkey',
              value  => ('1' x 64),
            },
          },
          scope  => 'irc://irc.example.test/overnet',
          action => 'session.delegate',
        },
      );
      my $pins   = $client->service_pins_list;
      my $forget = $client->service_pins_forget(locator => 'wss://relay.example.test/auth',);
      my $revoke = $client->policies_revoke(policy_id => 'policy-1',);

      is $grant->{ok},                        1,          'policies.grant succeeds';
      is $grant->{result}{policy}{policy_id}, 'policy-1', 'policies.grant returns a stable policy id';
      is $pins->{ok},                         1,          'service_pins.list succeeds';
      is $pins->{result}{service_pins}[0]{locator},
        'wss://relay.example.test/auth',
        'service_pins.list returns the stored locator';
      is $forget->{ok},                1,                               'service_pins.forget succeeds';
      is $forget->{result}{locator},   'wss://relay.example.test/auth', 'service_pins.forget echoes the locator';
      is $revoke->{ok},                1,                               'policies.revoke succeeds';
      is $revoke->{result}{policy_id}, 'policy-1',                      'policies.revoke echoes the policy id';
    },
  );
  };

subtest 'client reports a missing auth-agent endpoint clearly' => sub {
  local $ENV{OVERNET_AUTH_SOCK}     = undef;
  local $ENV{OVERNET_AUTH_ENDPOINT} = undef;

  my $error = eval {
    my $client = Overnet::Auth::Client->new;
    $client->agent_info;
    1;
  } ? undef : $@;

  like $error, qr/auth-agent\ endpoint\ is\ not\ configured/mx, 'client refuses to run without a configured endpoint';
};

subtest 'endpoint falls back to OVERNET_AUTH_ENDPOINT when OVERNET_AUTH_SOCK is unset' => sub {
  local $ENV{OVERNET_AUTH_SOCK}     = undef;
  local $ENV{OVERNET_AUTH_ENDPOINT} = '/tmp/overnet-auth.endpoint';

  my $client = Overnet::Auth::Client->new;
  is $client->endpoint, '/tmp/overnet-auth.endpoint', 'endpoint discovery falls back to OVERNET_AUTH_ENDPOINT';
};

subtest 'endpoint resolution precedence and request validation' => sub {
  local %ENV = %ENV;
  delete @ENV{qw(OVERNET_AUTH_SOCK OVERNET_AUTH_ENDPOINT)};

  is(Overnet::Auth::Client->new(endpoint => '/tmp/configured.sock')->endpoint,
    '/tmp/configured.sock', 'a configured endpoint wins');
  is(Overnet::Auth::Client->new->endpoint, undef, 'no endpoint resolves to undef');
  {
    local $ENV{OVERNET_AUTH_ENDPOINT} = '/tmp/legacy.sock';
    is(Overnet::Auth::Client->new->endpoint, '/tmp/legacy.sock', 'the legacy endpoint variable is honored');
    local $ENV{OVERNET_AUTH_SOCK} = '/tmp/preferred.sock';
    is(Overnet::Auth::Client->new->endpoint, '/tmp/preferred.sock', 'OVERNET_AUTH_SOCK wins over the legacy variable');
  }

  my $constructor_error = eval { Overnet::Auth::Client->new('odd'); 1 } ? undef : $@;
  like $constructor_error, qr/constructor\ arguments\ must\ be\ a\ hash/mx, 'odd constructor arguments die';

  my $client = Overnet::Auth::Client->new;
  my $error = eval { $client->request(params => {}); 1 } ? undef : $@;
  like $error, qr/method\ is\ required/mx, 'requests require a method';
  $error = eval { $client->request(method => 'agent.info', params => 'junk'); 1 } ? undef : $@;
  like $error, qr/params\ must\ be\ an\ object/mx, 'request params must be an object';
  $error = eval { $client->request(method => 'agent.info'); 1 } ? undef : $@;
  like $error, qr/auth-agent\ endpoint\ is\ not\ configured/mx,
    'requests without a resolvable endpoint croak';
  $error = eval {
    Overnet::Auth::Client->new(socket_factory => sub { return })->request(method => 'agent.info');
    1;
  } ? undef : $@;
  like $error, qr/socket_factory\ did\ not\ return\ a\ socket/mx,
    'socket factories must return a socket';
};

subtest 'real unix socket connections connect and fail visibly' => sub {
  require File::Temp;
  require IO::Socket::UNIX;
  my $dir      = File::Temp::tempdir(CLEANUP => 1);
  my $endpoint = File::Spec->catfile($dir, 'agent.sock');

  my $error = eval {
    Overnet::Auth::Client->new(endpoint => $endpoint)->request(method => 'agent.info');
    1;
  } ? undef : $@;
  like $error, qr/connect\ to\ auth-agent\ endpoint\ .*\ failed/mx,
    'connecting to a missing endpoint croaks';

  my $listener = IO::Socket::UNIX->new(
    Type   => SOCK_STREAM,
    Local  => $endpoint,
    Listen => 1,
  ) or die "listen on $endpoint failed: $!";
  my $socket = Overnet::Auth::Client->new(endpoint => $endpoint)->_connect_socket;
  ok $socket, 'connecting to a listening endpoint returns a socket';
  close $socket   or die "close failed: $!";
  close $listener or die "close failed: $!";
};

subtest 'wrapper methods issue their protocol requests' => sub {
  _with_auth_server(
    agent       => Overnet::Auth::Agent->new,
    connections => 3,
    run         => sub {
      my (%args) = @_;
      my $client = Overnet::Auth::Client->new(
        endpoint       => $args{endpoint},
        socket_factory => $args{socket_factory},
      );
      ok defined $client->identities_list->{ok},                       'identities_list round-trips';
      ok defined $client->sessions_renew(session_handle => {})->{ok},  'sessions_renew round-trips';
      ok defined $client->sessions_revoke(session_handle => {})->{ok}, 'sessions_revoke round-trips';
    },
  );
};

subtest 'response validation rejects malformed and mismatched replies' => sub {
  my $respond_with = sub {
    my ($bytes_builder) = @_;
    socketpair(my $server_socket, my $client_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
      or die "socketpair failed: $!";
    my $child = fork();
    die "fork failed: $!" unless defined $child;
    if (!$child) {
      close $client_socket or die "close failed: $!";
      sysread $server_socket, my $request, 65_536;
      my $bytes = $bytes_builder->($request);
      if (defined $bytes && length $bytes) {
        Overnet::Auth::SocketIO->write_all(socket => $server_socket, bytes => $bytes);
      }
      close $server_socket or die "close failed: $!";
      exit 0;
    }
    close $server_socket or die "close failed: $!";
    return ($client_socket, $child);
  };

  my $protocol = Overnet::Program::Protocol->new;
  my $run_case = sub {
    my ($bytes_builder, %request_args) = @_;
    my ($socket, $child) = $respond_with->($bytes_builder);
    my $client = Overnet::Auth::Client->new(socket_factory => sub { return $socket });
    my $result = eval { $client->request(method => 'agent.info', %request_args) };
    my $error  = $@;
    waitpid $child, 0;
    return ($result, $error);
  };

  my (undef, $closed_error) = $run_case->(sub { return q{} });
  like $closed_error, qr/auth-agent\ closed\ the\ connection/mx,
    'a connection closed before responding croaks';

  my (undef, $invalid_error) = $run_case->(
    sub { return $protocol->encode_message({type => 'response'}) },
  );
  like $invalid_error, qr/:\ /mx, 'invalid protocol responses croak with code and message';

  my (undef, $mismatch_error) = $run_case->(
    sub {
      return $protocol->encode_message(
        {type => 'response', id => 'other-id', ok => JSON::true, result => {}},
      );
    },
  );
  like $mismatch_error, qr/response\ id\ does\ not\ match/mx, 'mismatched response ids croak';

  my ($chunked, $chunk_error) = $run_case->(
    sub {
      return $protocol->encode_message(
        {type => 'response', id => 'pinned', ok => JSON::true, result => {blob => ('x' x 10_000)}},
      );
    },
    id => 'pinned',
  );
  is $chunk_error, '', 'responses larger than one read chunk parse';
  is length($chunked->{result}{blob}), 10_000, 'the full oversized payload arrives';
};

subtest 'server constructor and socket read edge paths' => sub {
  my $error = eval { Overnet::Auth::Server->new; 1 } ? undef : $@;
  like $error, qr/agent\ is\ required/mx, 'servers require an agent';
  $error = eval { Overnet::Auth::Server->new('odd'); 1 } ? undef : $@;
  like $error, qr/constructor\ arguments\ must\ be\ a\ hash/mx, 'odd constructor arguments die';
  $error = eval { Overnet::Auth::Server->new(agent => {}); 1 } ? undef : $@;
  like $error, qr/agent\ is\ required/mx,
    'unblessed agent references are rejected with the intended croak';

  my $server = Overnet::Auth::Server->new(agent => Overnet::Auth::Agent->new);
  $error = eval { $server->serve_socket(undef); 1 } ? undef : $@;
  like $error, qr/socket\ is\ required/mx, 'serving requires a socket';

  socketpair(my $server_socket, my $client_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  close $client_socket or die "close failed: $!";
  ok $server->serve_socket($server_socket), 'a peer that closes without writing ends the loop';
  close $server_socket or die "close failed: $!";

  socketpair(my $blocking_server, my $blocking_client, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  $blocking_server->blocking(0);
  $error = eval { $server->serve_socket($blocking_server); 1 } ? undef : $@;
  like $error, qr/read\ from\ auth-agent\ socket\ failed/mx,
    'failed reads croak with the socket error';
  close $blocking_server or die "close failed: $!";
  close $blocking_client or die "close failed: $!";
};

subtest 'empty-string endpoints and methods are treated as unset' => sub {
  local %ENV = %ENV;
  delete @ENV{qw(OVERNET_AUTH_SOCK OVERNET_AUTH_ENDPOINT)};

  is(Overnet::Auth::Client->new({endpoint => '/tmp/by-hashref.sock'})->endpoint,
    '/tmp/by-hashref.sock', 'a hashref constructor argument is accepted');

  my $empty = Overnet::Auth::Client->new(endpoint => q{});
  is $empty->endpoint, undef, 'an empty configured endpoint is ignored';
  {
    local $ENV{OVERNET_AUTH_SOCK}     = q{};
    local $ENV{OVERNET_AUTH_ENDPOINT} = q{};
    is $empty->endpoint, undef, 'empty environment endpoints are ignored';
  }

  my $error = eval { $empty->request(method => q{}); 1 } ? undef : $@;
  like $error, qr/method\ is\ required/mx, 'empty methods are treated as missing';

  socketpair(my $stalled_server, my $stalled_client, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed: $!";
  $stalled_client->blocking(0);
  my $stalled = Overnet::Auth::Client->new(socket_factory => sub { return $stalled_client });
  $error = eval { $stalled->request(method => 'agent.info'); 1 } ? undef : $@;
  like $error, qr/read\ from\ auth-agent\ endpoint\ failed/mx, 'failed response reads croak';
  close $stalled_server or die "close failed: $!";
};

done_testing;

sub _with_auth_server {
  my (%args) = @_;
  my $endpoint = File::Spec->catfile('/virtual', 'auth.sock');
  my @children;

  my $result = eval {
    $args{run}->(
      endpoint       => $endpoint,
      socket_factory => sub {
        my ($requested_endpoint) = @_;
        is $requested_endpoint, $endpoint, 'client requested the expected endpoint';
        socketpair(my $server_socket, my $client_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
          or die "socketpair failed: $!";
        my $server = Overnet::Auth::Server->new(agent => $args{agent},);
        my $child  = fork();
        die "fork failed: $!" unless defined $child;
        if (!$child) {
          close $client_socket
            or die "close client socket failed: $!";
          $server->serve_socket($server_socket);
          close $server_socket
            or die "close server socket failed: $!";
          exit 0;
        }
        close $server_socket or die "close server socket failed: $!";
        push @children, $child;
        return $client_socket;
      },
    );
    1;
  };
  my $error = $@;

  is scalar(@children), ($args{connections} || 1), 'expected auth-agent connections were opened';
  for my $child (@children) {
    waitpid($child, 0);
    is $? >> 8, 0, 'auth-agent server exits cleanly';
  }

  die $error unless $result;
  return;
}
