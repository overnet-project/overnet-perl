use strictures 2;

use FindBin;
use File::Spec;
use File::Temp qw(tempdir);
use JSON       ();
use Socket     qw(AF_UNIX PF_UNSPEC SOCK_STREAM);
use Test2::V0;

use IO::Socket::UNIX;
use Overnet::Auth::Client;
use Overnet::Auth::SocketIO;
use Overnet::Auth::StateStore;
use Overnet::Program::Protocol;
use Overnet::Auth::Daemon;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';
my $challenge      = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';

{

  package t::auth_daemon::FakeListener;

  use Moo;

  has queue  => (is => 'ro', default => sub { [] });
  has closed => (is => 'rw', default => sub {0});

  no Moo;

  sub accept {
    my ($self) = @_;
    return shift @{$self->{queue}};
  }

  sub close {
    my ($self) = @_;
    $self->{closed} = 1;
    return 1;
  }
}

subtest 'daemon serves multiple requests from the configured endpoint' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config($config_file, $socket_path);
  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    max_connections => 2,
    endpoint        => $socket_path,
  );

  my $info = $client->agent_info;
  is $info->{ok}, 1, 'agent.info succeeds through the daemon';

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
      value => $challenge,
    },
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => 22242,
          tags => [[relay => 'irc://irc.example.test/overnet'], [challenge => $challenge],],
        },
      },
    ],
  );

  is $response->{ok}, 1, 'sessions.authorize succeeds through the daemon';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey,
    'daemon-loaded identity signs the returned artifact';

  _wait_for_child($pid, 'daemon exits cleanly after serving the expected request count');
};

subtest 'endpoint argument overrides the configured daemon endpoint' => sub {
  my $dir               = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file       = File::Spec->catfile($dir, 'auth-agent.json');
  my $configured_socket = File::Spec->catfile($dir, 'configured.sock');
  my $override_socket   = File::Spec->catfile($dir, 'override.sock');

  _write_config($config_file, $configured_socket);
  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    endpoint        => $override_socket,
    max_connections => 1,
  );

  my $response = $client->agent_info;

  is $response->{ok},   1,                'agent.info succeeds through the override socket';
  is $client->endpoint, $override_socket, 'client was pointed at the override endpoint';

  _wait_for_child($pid, 'daemon exits cleanly after serving the override socket');
};

subtest 'daemon rejects invalid max_connections values at construction' => sub {
  my $error = eval {
    Overnet::Auth::Daemon->new(
      endpoint        => '/virtual/auth.sock',
      max_connections => 'not-a-number',
    );
    1;
  } ? undef : $@;

  like $error, qr/max_connections\ must\ be\ a\ positive\ integer/mx, 'non-numeric max_connections is rejected';

  $error = eval {
    Overnet::Auth::Daemon->new(
      endpoint        => '/virtual/auth.sock',
      max_connections => 0,
    );
    1;
  } ? undef : $@;

  like $error, qr/max_connections\ must\ be\ a\ positive\ integer/mx, 'zero max_connections is rejected';
};

subtest 'daemon rejects a pre-existing non-socket file at the endpoint path' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config($config_file, $socket_path);
  open my $fh, '>', $socket_path or die "open $socket_path failed: $!";
  print {$fh} "not a socket\n" or die "write $socket_path failed: $!";
  close $fh                    or die "close $socket_path failed: $!";

  my $error = eval {
    my $daemon = Overnet::Auth::Daemon->new(config_file => $config_file,);
    $daemon->run;
    1;
  } ? undef : $@;

  like $error,
    qr/auth-agent\ endpoint\ path\ already\ exists\ and\ is\ not\ a\ socket/mx,
    'daemon refuses to unlink non-socket endpoint paths';
};

subtest 'daemon loads mutable state from the configured state file' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $state_file  = File::Spec->catfile($dir, 'auth-state.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config(
    $config_file, $socket_path,
    state_file    => $state_file,
    with_policies => 0
  );
  _write_state(
    $state_file,
    {
      policies => [
        {
          policy_id   => 'policy-1',
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => ['irc://irc.example.test/overnet'],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
      service_pins => {},
      sessions     => [],
    }
  );

  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    max_connections => 1,
    endpoint        => $socket_path,
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
      value => $challenge,
    },
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => 22242,
          tags => [[relay => 'irc://irc.example.test/overnet'], [challenge => $challenge],],
        },
      },
    ],
  );

  is $response->{ok}, 1, 'headless authorization succeeds from persisted policy state';
  _wait_for_child($pid, 'daemon exits cleanly after loading persisted mutable state');
};

subtest 'daemon persists mutable session and service-pin state to the configured state file' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $state_file  = File::Spec->catfile($dir, 'auth-state.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config(
    $config_file, $socket_path,
    state_file    => $state_file,
    with_policies => 0,
    unattended    => 1,
  );
  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    max_connections => 1,
    endpoint        => $socket_path,
  );

  my $response = $client->sessions_authorize(
    program_id  => 'irc.bridge',
    identity_id => 'default',
    service     => {
      locators         => ['wss://relay.example.test/auth'],
      service_identity => {
        scheme => 'nostr.pubkey',
        value  => ('1' x 64),
      },
    },
    scope     => 'irc://irc.example.test/overnet',
    action    => 'session.authenticate',
    challenge => {
      type  => 'opaque',
      value => $challenge,
    },
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => 22242,
          tags => [[relay => 'irc://irc.example.test/overnet'], [challenge => $challenge],],
        },
      },
    ],
  );

  is $response->{ok}, 1, 'authorization succeeds';
  _wait_for_child($pid, 'daemon exits cleanly after persisting mutable state');

  my $state = _read_json($state_file);
  is scalar(@{$state->{sessions} || []}), 1, 'persisted state includes the new session';
  is $state->{service_pins}{'wss://relay.example.test/auth'}{value},
    ('1' x 64),
    'persisted state includes the first-contact service pin';
};

subtest 'constructor validation and defaults' => sub {
  like(
    dies { Overnet::Auth::Daemon->new('odd') },
    qr/constructor arguments must be a hash/,
    'odd constructor arguments die',
  );
  like(
    dies { Overnet::Auth::Daemon->new(config => bless({}, 't::auth_daemon::NotConfig'), endpoint => '/tmp/x.sock') },
    qr/config must be an Overnet::Auth::Config/,
    'non-config objects are rejected',
  );
  like(
    dies { Overnet::Auth::Daemon->new(config => {}, endpoint => '/tmp/x.sock') },
    qr/config must be an Overnet::Auth::Config/,
    'unblessed config references are rejected with the intended croak',
  );
  like(
    dies { Overnet::Auth::Daemon->new() },
    qr/auth-agent endpoint is required/,
    'an endpoint is required',
  );
  like(
    dies { Overnet::Auth::Daemon->new(endpoint => '/tmp/x.sock', max_connections => 'many') },
    qr/max_connections must be a positive integer/,
    'non-numeric connection limits are rejected',
  );
  like(
    dies { Overnet::Auth::Daemon->new(endpoint => '/tmp/x.sock', agent => bless({}, 't::auth_daemon::NoDispatch')) },
    qr/agent must support dispatch/,
    'agents must support dispatch',
  );
  like(
    dies { Overnet::Auth::Daemon->new(endpoint => '/tmp/x.sock', agent => {}) },
    qr/agent must support dispatch/,
    'unblessed agent references are rejected with the intended croak',
  );

  my $daemon = Overnet::Auth::Daemon->new(
    {
      endpoint    => '/tmp/x.sock',
      socket_mode => oct('0644'),
      state_file  => '/tmp/state.json',
    },
  );
  is $daemon->_socket_mode, oct('0644'), 'an explicit socket mode is honored';
  isa_ok $daemon->_state_store, ['Overnet::Auth::StateStore'], 'a state_file arg builds a state store';

  my $default_mode = Overnet::Auth::Daemon->new(endpoint => '/tmp/x.sock');
  is $default_mode->_socket_mode, oct('0600'), 'the socket mode defaults to 0600';
  is $default_mode->_state_store, undef, 'no state store is built without a state file';

  my $store  = Overnet::Auth::StateStore->new(path => '/tmp/injected-state.json');
  my $reused = Overnet::Auth::Daemon->new(endpoint => '/tmp/x.sock', state_store => $store);
  is $reused->_state_store, exact_ref($store), 'an injected state store is reused';
};

subtest 'listen socket lifecycle on a real endpoint' => sub {
  my $dir      = tempdir(CLEANUP => 1);
  my $endpoint = File::Spec->catfile($dir, 'nested', 'auth.sock');

  my $daemon = Overnet::Auth::Daemon->new(endpoint => $endpoint, max_connections => 1);
  my $listener = $daemon->_listen_socket;
  ok $listener, 'a unix listener is created below a new directory';
  is $daemon->_listen_socket, exact_ref($listener), 'the listener is cached';

  my $client = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $endpoint)
    or die "connect to $endpoint failed: $!";
  my $protocol = Overnet::Program::Protocol->new;
  my $request  = Overnet::Program::Protocol::build_request(
    id     => 'daemon-run-1',
    method => 'agent.info',
    params => {},
  );
  Overnet::Auth::SocketIO->write_all(socket => $client, bytes => $protocol->encode_message($request));

  ok $daemon->run, 'the daemon serves the pending connection and stops at the limit';
  ok !-S $endpoint, 'the endpoint socket is removed on teardown';

  sysread $client, my $raw, 65_536;
  like $raw, qr/daemon-run-1/, 'the pending client received a response';
  close $client or die "close failed: $!";
};

subtest 'listen socket edge and failure paths' => sub {
  my $dir = tempdir(CLEANUP => 1);

  my $occupied = File::Spec->catfile($dir, 'occupied.sock');
  open my $plain, '>', $occupied or die "open $occupied failed: $!";
  close $plain or die "close $occupied failed: $!";
  like(
    dies { Overnet::Auth::Daemon->new(endpoint => $occupied)->_listen_socket },
    qr/already exists and is not a socket/,
    'a non-socket file at the endpoint is refused',
  );

  my $stale_path = File::Spec->catfile($dir, 'stale.sock');
  my $stale = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $stale_path, Listen => 1)
    or die "listen on $stale_path failed: $!";
  $stale->close or die "close failed: $!";
  my $reclaimed = Overnet::Auth::Daemon->new(endpoint => $stale_path);
  ok $reclaimed->_listen_socket, 'a stale socket file is unlinked and reclaimed';
  $reclaimed->_teardown_socket;

  like(
    dies {
      Overnet::Auth::Daemon->new(
        endpoint       => File::Spec->catfile($dir, 'factory.sock'),
        listen_factory => sub { return },
      )->_listen_socket
    },
    qr/listen on auth-agent endpoint .* failed/,
    'a listen factory returning nothing croaks',
  );

  my $failing_listener = Overnet::Auth::Daemon->new(
    endpoint       => File::Spec->catfile($dir, 'accept-fail.sock'),
    listen_factory => sub {
      return t::auth_daemon::FakeListener->new(queue => []);
    },
  );
  like(
    dies { $failing_listener->run },
    qr/accept on auth-agent endpoint failed/,
    'accept failures croak',
  );

  my $closed = IO::Socket::UNIX->new(
    Type   => SOCK_STREAM,
    Local  => File::Spec->catfile($dir, 'closing.sock'),
    Listen => 1,
  ) or die "listen failed: $!";
  $closed->close or die "close failed: $!";
  my $torn = Overnet::Auth::Daemon->new(endpoint => File::Spec->catfile($dir, 'closing.sock'));
  $torn->_current_listen_socket($closed);
  like(
    dies { $torn->_teardown_socket },
    qr/close auth-agent listener socket failed/,
    'closing an already-closed listener croaks',
  );
};

subtest 'a dispatch failure tears the daemon down cleanly' => sub {
  my $dir      = tempdir(CLEANUP => 1);
  my $endpoint = File::Spec->catfile($dir, 'crash.sock');

  {

    package t::auth_daemon::CrashingAgent;

    sub new      { my ($class) = @_; return bless {}, $class }
    sub dispatch { die "agent exploded\n" }
  }

  my $daemon = Overnet::Auth::Daemon->new(
    endpoint => $endpoint,
    agent    => t::auth_daemon::CrashingAgent->new,
  );
  my $listener = $daemon->_listen_socket;
  my $client = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $endpoint)
    or die "connect failed: $!";
  my $protocol = Overnet::Program::Protocol->new;
  Overnet::Auth::SocketIO->write_all(
    socket => $client,
    bytes  => $protocol->encode_message(
      Overnet::Program::Protocol::build_request(id => 'x-1', method => 'agent.info', params => {}),
    ),
  );

  like(dies { $daemon->run }, qr/agent exploded/, 'dispatch failures propagate from run');
  ok !-S $endpoint, 'the endpoint socket is removed after the failure';
  close $client or die "close failed: $!";
};

subtest 'empty endpoint and state_file values are treated as unset' => sub {
  like(
    dies { Overnet::Auth::Daemon->new(endpoint => q{}) },
    qr/auth-agent endpoint is required/,
    'an empty endpoint is treated as missing',
  );
  is(
    Overnet::Auth::Daemon->new(endpoint => '/tmp/x.sock', state_file => q{})->_state_store,
    undef,
    'an empty state_file builds no state store',
  );
  ok(
    Overnet::Auth::Daemon->new(endpoint => '/tmp/x.sock')->_teardown_socket,
    'tearing down without a listener or socket file succeeds',
  );
};

done_testing;

sub _start_daemon {
  my (%args) = @_;
  my @client_sockets;
  my @server_sockets;
  my $endpoint =
    defined($args{endpoint})
    ? $args{endpoint}
    : _config_endpoint($args{config_file});

  for (1 .. ($args{max_connections} || 1)) {
    socketpair(my $server_socket, my $client_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair failed: $!";
    push @server_sockets, $server_socket;
    push @client_sockets, $client_socket;
  }

  my $pid = fork();
  die "fork failed: $!" unless defined $pid;
  if (!$pid) {
    my $listener = t::auth_daemon::FakeListener->new(queue => \@server_sockets);
    my $daemon   = Overnet::Auth::Daemon->new(%args);
    $daemon->{listen_factory} = sub { return $listener };
    $daemon->run;
    exit 0;
  }

  my $client = Overnet::Auth::Client->new(
    endpoint       => $endpoint,
    socket_factory => sub {
      my ($requested_endpoint) = @_;
      is $requested_endpoint, $endpoint, 'client requested the expected endpoint';
      return shift @client_sockets;
    },
  );

  return ($pid, $client);
}

sub _wait_for_child {
  my ($pid, $name) = @_;
  waitpid($pid, 0);
  is $? >> 8, 0, $name;
  return;
}

sub _config_endpoint {
  my ($path) = @_;
  open my $fh, '<', $path or die "open $path failed: $!";
  my $decoded =
    do { local $/ = undef; JSON::encode_json(JSON::decode_json(<$fh>)) };
  close $fh or die "close $path failed: $!";
  my $config = JSON::decode_json($decoded);
  return $config->{daemon}{endpoint};
}

sub _write_config {
  my ($path, $socket_path, %args) = @_;
  my @policies =
    $args{with_policies} || !exists($args{with_policies})
    ? (
    {
      identity_id => 'default',
      program_id  => 'irc.bridge',
      locators    => ['irc://irc.example.test/overnet'],
      scope       => 'irc://irc.example.test/overnet',
      action      => 'session.authenticate',
    },
    )
    : ();

  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} JSON::encode_json(
    {
      daemon => {
        endpoint => $socket_path,
        (
          defined($args{state_file})
          ? (state_file => $args{state_file})
          : ()
        ),
      },
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
      policies => \@policies,
      (
        $args{unattended}
        ? (allow_unattended_autoapprove => JSON::true)
        : ()
      ),
    }
  ) or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
  return;
}

sub _write_state {
  my ($path, $value) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} JSON::encode_json($value)
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
  return;
}

sub _read_json {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "open $path failed: $!";
  my $value = JSON::decode_json(do { local $/ = undef; <$fh> });
  close $fh
    or die "close $path failed: $!";
  return $value;
}
