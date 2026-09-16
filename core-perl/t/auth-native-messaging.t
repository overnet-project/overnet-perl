use strictures 2;
use Cwd        qw(abs_path);
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Spec;
use File::Temp qw(tempdir tempfile);
use FindBin;
use IO::Socket::UNIX;
use IPC::Open3 qw(open3);
use JSON       ();
use Socket     qw(SOCK_STREAM);
use Symbol     qw(gensym);
use Test2::V0;
use Time::HiRes qw(sleep time);

use Overnet::Auth::Client;
use Overnet::Auth::Agent;
use Overnet::Authority::Delegation;
use Overnet::Auth::NativeMessaging;
use Overnet::Auth::SocketIO;

my $json     = JSON->new->utf8->canonical;
my $root     = abs_path(File::Spec->catdir($FindBin::Bin, '..'));
my $host     = File::Spec->catfile($root, 'bin', 'overnet-auth-native.pl');
my $dir      = tempdir(CLEANUP => 1);
my $endpoint = File::Spec->catfile($dir, 'agent.sock');
my %children;

END {
  local $?;
  for my $pid (keys %children) {
    kill 'TERM', $pid;
    waitpid($pid, 0);
  }
}


# Test the trusted, embedded host separately from the unauthenticated public
# socket. The latter must fail closed; program assertions cannot authenticate it.
{ package t::auth_native::TrustedClient;
  use parent 'Overnet::Auth::Client';
  sub request {
    my ($self, %args) = @_;
    return $self->{test_agent}->dispatch({type => 'request', id => $args{id} || 'test',
      method => $args{method}, params => $args{params} || {}},
      caller => {admin => 1, program_id => 'browser:https://chat.example.test#test-approval'});
  }
}
my $trusted_client = t::auth_native::TrustedClient->new;
$trusted_client->{test_agent} = Overnet::Auth::Agent->new(identities => [{
  identity_id => 'test', backend_type => 'direct_secret', backend_config => {secret => '1' x 64},
  public_identity => {scheme => 'nostr.pubkey', value => '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'},
}]);

my $config = File::Spec->catfile($dir, 'agent.json');
_write(
  $config,
  $json->encode(
    {
      daemon     => {endpoint => $endpoint},
      identities => [{identity_id => 'test', backend_type => 'direct_secret', backend_config => {secret => '1' x 64}}]
    }
  )
);
my $daemon = fork();
die "fork: $!" if !defined $daemon;
if (!$daemon) {
  exec $^X, '-I' . File::Spec->catdir($root, 'lib'),
    File::Spec->catfile($root, 'bin', 'overnet-auth-agent.pl'), '--config-file', $config;
  die "exec daemon: $!";
}
$children{$daemon} = 1;
my $deadline = time() + 5;
sleep 0.01 while !-S $endpoint && time() < $deadline;
ok -S $endpoint, 'real auth daemon is listening' or bail_out('auth daemon did not start');

subtest 'native framing reaches the real agent and preserves request IDs' => sub {
  my @requests =
    map { {type => 'request', id => $_, method => 'agent.info', params => {}} } ('first', "second-\x{2603}");
  my ($out, $err, $exit) = _native(join(q{}, map { _frame($_) } @requests), $endpoint);
  is $exit, 0,   'host exits cleanly on EOF';
  is $err,  q{}, 'stdout framing is not accompanied by errors';
  my $responses = _decode_frames($out);
  is scalar @{$responses}, 2, 'both native requests receive responses';
  for my $index (0 .. 1) {
    is $responses->[$index]{id}, $requests[$index]{id}, 'the caller ID survives both transports';
    ok $responses->[$index]{ok}, 'the real agent answered';
    is $responses->[$index]{result}{protocol_version}, '0.2.0', 'agent protocol version';
  }
};

subtest 'the executable handles fragmented stdin and browser launch arguments' => sub {
  my ($out, $err, $exit) = _run(
    _frame({type => 'request', id => 'cli', method => 'agent.info'}),
    [
      $^X,   '-I' . File::Spec->catdir($root, 'lib'),
      $host, '--auth-sock', $endpoint, '/native/manifest.json', 'test-extension@overnet'
    ],
    fragmented => 1,
  );
  is $exit, 0,   'native executable exits cleanly';
  is $err,  q{}, 'native executable reports no errors';
  my $reply = _decode_frames($out)->[0];
  is $reply->{id}, 'cli', 'native executable preserves the request ID';
  ok $reply->{ok}, 'native executable reaches the daemon';
};

subtest 'the connector blocks raw signing and administration' => sub {
  for my $method (qw(policies.grant sessions.authorize sessions.revoke service_pins.set)) {
    my ($out, $err, $exit) = _native(_frame({type => 'request', id => 'blocked', method => $method}), $endpoint);
    is $exit, 0, "$method returns a structured rejection";
    my $response = _decode_frames($out)->[0];
    ok !$response->{ok}, "$method cannot succeed through the host";
    is $response->{error}{code}, 'protocol.unknown_method', "$method is rejected at the native boundary";
  }
  for my $method (undef, []) {
    my ($out) = _native(_frame({type => 'request', id => 'bad-method', method => $method}), $endpoint);
    is _decode_frames($out)->[0]{error}{code}, 'protocol.unknown_method', 'malformed method is rejected';
  }
  for my $params ([], {endpoint => '/another/agent.sock'}, {action => 'session.delegate'}) {
    my ($out) =
      _native(_frame({type => 'request', id => 'params', method => 'agent.info', params => $params}), $endpoint);
    is _decode_frames($out)->[0]{error}{code}, 'protocol.invalid_params',
      'browser input cannot configure the agent client';
  }
  my $client = $trusted_client;
  is $client->policies_list->{result}{policies}, [], 'agent policies remain empty';
  is $client->sessions_list->{result}{sessions}, [], 'agent sessions remain empty';
};

subtest 'public socket cannot authenticate a native host by request content' => sub {
  my ($out) = _native(_frame({type => 'request', id => 'unverified', method => 'browser.authenticate',
    params => _browser_params()}), $endpoint);
  is _decode_frames($out)->[0]{error}{code}, 'auth.policy_denied',
    'the default daemon refuses signing without an authenticated launch binding';
  my $client = Overnet::Auth::Client->new(endpoint => $endpoint);
  is $client->policies_list->{error}{code}, 'auth.policy_denied', 'socket access is not administration';
};

subtest 'browser approval signs the shared exchange and leaves no reusable authority' => sub {
  my $client     = $trusted_client;
  my ($listing)  = _native(_frame({type => 'request', id => 'identities', method => 'identities.list'}), $endpoint);
  my $identities = _decode_frames($listing)->[0]{result}{identities};
  is $identities->[0]{identity_id}, 'test', 'the trusted UI can choose a local identity';
  ok !exists $identities->[0]{backend_config}, 'identity listing contains no secret configuration';
  for my $delegate (0, 1) {
    my $params = _browser_params();
    if (!$delegate) {
      $params->{challenge}{scope} = 'https://lists.example.test/family';
      delete @{$params->{challenge}}{qw(relay_url grant_kind delegate_pubkey session_id expires_at)};
    }
    my $result = _browser_response($params);
    ok $result->{ok}, 'approved authentication succeeds' or diag $json->encode($result);
    my $auth = $result->{result}{auth_event};
    is $auth->{kind}, 22242, 'authentication uses the canonical kind';
    is $auth->{tags}, [['relay', $params->{challenge}{scope}], ['challenge', 'browser-test']],
      'challenge and scope are signed exactly';
    my $verified = Overnet::Authority::Delegation->verify_auth_event(
      event     => $auth,
      scope     => $params->{challenge}{scope},
      challenge => 'browser-test'
    );
    ok $verified->{valid}, 'the identity signature verifies';

    if ($delegate) {
      my $grant = $result->{result}{delegate_event};
      is $grant->{kind},   14142,           'delegation uses the canonical kind';
      is $grant->{pubkey}, $auth->{pubkey}, 'the same identity authorizes the session';
      my $verified_grant = Overnet::Authority::Delegation->verify_delegation_grant(
        event => $grant,
        %{$params->{challenge}},
        authority_pubkey => $auth->{pubkey},
        kind             => 14142
      );
      ok $verified_grant->{valid}, 'the delegation signature verifies';
    } else {
      ok !exists $result->{result}{delegate_event}, 'authentication also works without delegation';
    }
    is $client->policies_list->{result}{policies}, [], 'temporary approval policies are removed';
    is $client->sessions_list->{result}{sessions}, [], 'local renewal handles are removed';
    is [sort keys %{$result->{result}}], $delegate ? ['auth_event', 'delegate_event'] : ['auth_event'],
      'only public signed artifacts leave the connector';
  }
};

subtest 'invalid browser requests fail closed before policy changes' => sub {
  for my $override (
    {origin      => 'file:///tmp/page'},
    {origin      => 'https://example.test/path'},
    {origin      => []},
    {identity_id => q{}},
    {request_id  => 'chosen#program'},
    {challenge   => []},
    {challenge   => {scope => 'scope'}},
  ) {
    my $response = _browser_response({%{_browser_params()}, %{$override}});
    is $response->{error}{code}, 'protocol.invalid_params', 'invalid browser context is rejected';
  }
  for my $override (
    {scope           => []},
    {challenge       => "bad\nchallenge"},
    {relay_url       => undef},
    {grant_kind      => 1},
    {delegate_pubkey => 'invalid'},
    {session_id      => []},
    {expires_at      => time - 1},
    {expires_at      => time + 90_000},
    {expires_at      => 'tomorrow'},
  ) {
    my $params = _browser_params();
    $params->{challenge} = {%{$params->{challenge}}, %{$override}};
    is _browser_response($params)->{error}{code}, 'protocol.invalid_params',
      'malformed delegation cannot downgrade to authentication alone';
  }
  my $client = $trusted_client;
  is $client->policies_list->{result}{policies}, [], 'rejected requests do not leave policies';
};

subtest 'signing errors clean up temporary policies and pins cannot be downgraded' => sub {
  my $client = $trusted_client;
  my $params = _browser_params();
  $params->{identity_id} = 'missing';
  is _browser_response($params)->{error}{code},  'auth.unknown_identity', 'signing error is returned';
  is $client->policies_list->{result}{policies}, [],                      'policy is revoked after signing failure';
  $params = _browser_params();
  my $pin = $client->service_pins_set(
    locator          => $params->{challenge}{scope},
    service_identity => {scheme => 'nostr.pubkey', value => 'a' x 64}
  );
  ok $pin->{ok}, 'test service is pinned';
  is _browser_response($params)->{error}{code}, 'auth.service_identity_required',
    'a pinned service cannot silently fall back to locator trust';
  $client->service_pins_forget(locator => $params->{challenge}{scope});
};

subtest 'backend diagnostics stay local and failed cleanup cannot return artifacts' => sub {
  {

    package t::auth_native::FailingClient;
    sub new { my ($class, %args) = @_; return bless \%args, $class; }

    sub request {
      my ($self, %args) = @_;
      if ($args{method} eq $self->{fail}) {
        return {ok => 0, error => {code => 'auth.backend_unavailable', message => 'private-backend-diagnostic'}};
      }
      return $self->{real}->request(%args);
    }
  }
  my $real = $trusted_client;
  for my $fail ('sessions.authorize', 'policies.revoke') {
    my $client = t::auth_native::FailingClient->new(real => $real, fail => $fail);
    my ($out) = _native(
      _frame({type => 'request', id => 'failed', method => 'browser.authenticate', params => _browser_params()}),
      $endpoint, client => $client);
    my $response = _decode_frames($out)->[0];
    ok !$response->{ok},            'failure is returned without artifacts';
    ok !exists $response->{result}, 'no signed result leaves a failed transaction';
    unlike $out, qr/private-backend-diagnostic/, 'private backend diagnostics are not returned to a website';
    is $response->{error}{code}, $fail eq 'policies.revoke' ? 'native.cleanup_failed' : 'auth.backend_unavailable',
      'error identifies signing or cleanup failure';
    for my $policy (@{$real->policies_list->{result}{policies}}) {
      $real->policies_revoke(policy_id => $policy->{policy_id});
    }
    for my $session (@{$real->sessions_list->{result}{sessions}}) {
      $real->sessions_revoke(session_handle => $session->{session_handle});
    }
  }
};

subtest 'stopped and unresponsive agents return a bounded failure' => sub {
  my $request = _frame({type => 'request', id => 'offline', method => 'agent.info'});
  my ($out, $err, $exit) = _native($request, File::Spec->catfile($dir, 'missing.sock'));
  is $exit,                                  0, 'a stopped agent is a status result, not a broken native transport';
  is _decode_frames($out)->[0]{error}{code}, 'native.agent_unavailable', 'stopped agent result';

  my $silent_path = File::Spec->catfile($dir, 'silent.sock');
  my $silent      = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $silent_path, Listen => 1)
    or die "listen: $!";
  my $started = time();
  ($out, $err, $exit) = _native($request, $silent_path);
  is $exit,                                  0,                          'a stalled agent receives a structured result';
  is _decode_frames($out)->[0]{error}{code}, 'native.agent_unavailable', 'stalled agent result';
  ok time() - $started < 9, 'the status request does not wait indefinitely';
  close $silent or die "close: $!";
};

subtest 'invalid native input closes the host without sending agent requests' => sub {
  for my $case (
    ['partial header',  "\x01\x00"],
    ['partial body',    pack('L', 10) . '{}'],
    ['missing body',    pack('L', 10)],
    ['empty frame',     pack('L', 0)],
    ['oversized frame', pack('L', 1024 * 1024 + 1)],
    ['invalid JSON',    pack('L', 1) . '{'],
    ['non-object JSON', _frame([])],
    ['missing ID',      _frame({type => 'request',      method => 'agent.info'})],
    ['empty ID',        _frame({type => 'request',      id     => q{}, method => 'agent.info'})],
    ['reference ID',    _frame({type => 'request',      id     => [],  method => 'agent.info'})],
    ['missing type',    _frame({id   => 'missing',      method => 'agent.info'})],
    ['reference type',  _frame({type => [],             id     => 'bad',   method => 'agent.info'})],
    ['wrong envelope',  _frame({type => 'notification', id     => 'wrong', method => 'agent.info'})],
  ) {
    my ($out, $err, $exit) = _native($case->[1], $endpoint);
    isnt $exit, 0,   "$case->[0] is rejected";
    is $out,    q{}, "$case->[0] writes no unframed stdout";
    ok length($err), "$case->[0] raises a framing error";
  }
  my ($out, $err, $exit) = _native(q{}, $endpoint);
  is [$out, $err, $exit], [q{}, q{}, 0], 'EOF between messages is clean';
};

subtest 'response limits and input I/O failures are enforced' => sub {
  {

    package t::auth_native::LargeClient;
    sub new     { return bless {}, shift; }
    sub request { return {data => 'x' x (1024 * 1024)}; }
  }
  my ($out, $err, $exit) = _native(_frame({type => 'request', id => 'large', method => 'agent.info'}),
    $endpoint, client => t::auth_native::LargeClient->new,);
  is $out, q{}, 'an oversized agent reply is not written';
  like $err, qr/Native response exceeds maximum size/, 'oversized reply raises an error';

  open my $input, '<:raw', $dir or die "open directory: $!";
  like dies { Overnet::Auth::NativeMessaging->serve(input => $input) },
    qr/Read native message failed/, 'input read failures raise an error';
  close $input or die "close directory: $!";
};

subtest 'the connector starts one detached agent and reuses it across native processes' => sub {
  my $bin = File::Spec->catdir($dir, 'autostart-bin');
  make_path($bin);
  my $native = File::Spec->catfile($bin, 'overnet-auth-native.pl');
  copy $host, $native or die "copy native host: $!";
  my $agent = File::Spec->catfile($bin, 'overnet-auth-agent.pl');
  _write($agent, <<'AGENT');
use strict;
use warnings;
open my $starts, '>>', $ENV{OVERNET_TEST_STARTS} or die "open starts: $!";
print {$starts} "$$\n" or die "write starts: $!";
close $starts or die "close starts: $!";
exec $^X, $ENV{OVERNET_TEST_AGENT}, @ARGV or die "exec agent: $!";
AGENT
  local $ENV{OVERNET_TEST_AGENT}  = File::Spec->catfile($root, 'bin', 'overnet-auth-agent.pl');
  local $ENV{OVERNET_TEST_STARTS} = File::Spec->catfile($dir,  'agent.starts');
  my $sock = File::Spec->catfile($dir, 'new-runtime', 'agent.sock');
  my $conf = File::Spec->catfile($dir, 'autostart.json');
  _write($conf, $json->encode({daemon => {endpoint => $sock}}));
  my @command = ($^X, '-I' . File::Spec->catdir($root, 'lib'), $native, '--auth-sock', $sock, '--config-file', $conf);
  my $request = _frame({type => 'request', id => 'autostart', method => 'agent.info'});

  my ($out, $err, $exit) = _run(_frame({type => 'request', id => 'blocked', method => 'policies.grant'}), \@command);
  is _decode_frames($out)->[0]{error}{code}, 'protocol.unknown_method', 'invalid methods do not trigger startup';
  ok !-e $ENV{OVERNET_TEST_STARTS}, 'no agent was started for a rejected request';

  # Launch both native hosts before reading either response, as two popups could.
  my @hosts;
  local $SIG{ALRM} = sub { die "parallel native startup timed out\n"; };
  alarm 10;
  for (1 .. 2) {
    my $error = gensym;
    my $pid   = open3(my $input, my $output, $error, @command);
    $children{$pid} = 1;
    binmode $input, ':raw';
    Overnet::Auth::SocketIO->write_all(socket => $input, bytes => $request);
    close $input or die "close native input: $!";
    push @hosts, [$pid, $output, $error];
  }
  for my $process (@hosts) {
    my ($pid, $output, $error) = @{$process};
    binmode $output, ':raw';
    my $reply  = do { local $/; <$output> };
    my $errors = do { local $/; <$error> };
    close $output or die "close native output: $!";
    close $error  or die "close native error: $!";
    waitpid($pid, 0);
    is $? >> 8, 0, 'native host exits without waiting for the detached agent';
    delete $children{$pid};
    ok _decode_frames($reply)->[0]{ok}, 'concurrent status check succeeds';
    is $errors, q{}, 'agent output does not leak into browser pipes';
  }
  alarm 0;
  open my $starts, '<', $ENV{OVERNET_TEST_STARTS} or die "open starts: $!";
  my @pids = <$starts>;
  close $starts or die "close starts: $!";
  chomp @pids;
  $children{$_} = 1 for @pids;
  is scalar @pids, 1, 'simultaneous requests started exactly one agent';
  ok kill(0, $pids[0]), 'agent survives both native hosts exiting';
  ($out, $err, $exit) = _run($request, \@command);
  ok _decode_frames($out)->[0]{ok}, 'a later native host reuses the running agent';
  open $starts, '<', $ENV{OVERNET_TEST_STARTS} or die "open starts: $!";
  is scalar(() = <$starts>), 1, 'reuse did not start another process';
  close $starts or die "close starts: $!";
};

subtest 'agent startup is requested only for valid status checks and errors are reported' => sub {
  my $calls = 0;
  my ($out) = _native(_frame({type => 'request', id => 'prepare', method => 'agent.info'}),
    $endpoint, ensure_agent => sub { $calls++; });
  is $calls, 1, 'a valid status request ensures the agent is available';
  ok _decode_frames($out)->[0]{ok}, 'status is requested after preparation';
  ($out) = _native(_frame({type => 'request', id => 'blocked', method => 'policies.grant'}),
    $endpoint, ensure_agent => sub { $calls++; });
  is $calls, 1, 'rejected methods cannot trigger startup';
  ($out) = _native(_frame({type => 'request', id => 'failure', method => 'agent.info'}),
    $endpoint, ensure_agent => sub { die 'startup failed'; });
  is _decode_frames($out)->[0]{error}{code}, 'native.agent_unavailable', 'startup exceptions are status errors';
};

subtest 'failed startup returns an error and releases the startup lock for retry' => sub {
  my $sock    = File::Spec->catfile($dir, 'failed.sock');
  my $conf    = File::Spec->catfile($dir, 'missing.json');
  my $request = _frame({type => 'request', id => 'failed-start', method => 'agent.info'});
  my @command = ($^X, '-I' . File::Spec->catdir($root, 'lib'), $host, '--auth-sock', $sock, '--config-file', $conf);
  my ($out, $err, $exit) = _run($request, \@command);
  is $exit,                                  0,                          'failed startup is a status result';
  is _decode_frames($out)->[0]{error}{code}, 'native.agent_unavailable', 'startup failure is reported';
  ok !-S $sock,      'failed agent never started listening';
  ok -s "$sock.log", 'agent startup diagnostics are available locally';

  # A launcher that stalls must also finish within the same five-second limit.
  my $bin = File::Spec->catdir($dir, 'stalled-bin');
  make_path($bin);
  my $native = File::Spec->catfile($bin, 'overnet-auth-native.pl');
  copy $host, $native or die "copy native host: $!";
  $command[2] = $native;
  my $stalled = File::Spec->catfile($bin, 'overnet-auth-agent.pl');
  _write($stalled, 'sleep 30;');
  my $started = time();
  ($out, $err, $exit) = _run($request, \@command);
  is _decode_frames($out)->[0]{error}{code}, 'native.agent_unavailable', 'a subsequent launch can acquire the lock';
  ok time() - $started < 9, 'stalled startup times out';
};

subtest 'development registration reads the extension ID and quotes launcher arguments' => sub {
  plan skip_all => 'Linux development installer' if $^O ne 'linux';
  my $workspace = File::Spec->catdir($dir,       q{workspace with 'quotes' and $(false)});
  my $manifests = File::Spec->catdir($workspace, 'repos', 'overnet-client', 'manifests');
  my $install   = File::Spec->catdir($workspace, 'native hosts');
  my $bin       = File::Spec->catdir($workspace, 'tools');
  make_path($manifests, $bin, File::Spec->catdir($workspace, '.plx'));
  _write(
    File::Spec->catfile($manifests, 'firefox.json'),
    $json->encode(
      {
        browser_specific_settings => {gecko => {id => 'test-extension@overnet'}},
      }
    )
  );
  my $fake_plx = File::Spec->catfile($bin, 'plx');
  _write($fake_plx, "#!$^X\n" . 'use JSON (); print JSON->new->utf8->encode(\@ARGV);' . "\n");
  chmod 0700, $fake_plx or die "chmod: $!";
  local $ENV{PATH} = $bin . q{:} . $ENV{PATH};
  my $sock = File::Spec->catfile($workspace, q{agent's $(false).sock});
  my $conf = File::Spec->catfile($workspace, q{agent's $(false).json});
  _write($conf, $json->encode({daemon => {endpoint => $sock}}));
  my ($out, $err, $exit) = _run(
    q{},
    [
      $^X,
      '-I' . File::Spec->catdir($root, 'lib'),
      File::Spec->catfile($root, 'deploy', 'native-messaging', 'install-firefox.pl'),
      '--workspace', $workspace, '--config-file', $conf, '--manifest-dir', $install,
    ]
  );
  is $exit, 0,   'registration succeeds';
  is $err,  q{}, 'registration has no errors';
  open my $input, '<:raw', File::Spec->catfile($install, 'org.overnet.auth.json') or die "open: $!";
  my $registration = $json->decode(do { local $/; <$input> });
  close $input or die "close: $!";
  is $registration->{allowed_extensions}, ['test-extension@overnet'], 'only the configured extension is allowed';
  is $registration->{name},               'org.overnet.auth',         'shared native host name';
  ($out, $err, $exit) = _run(q{}, [$registration->{path}, 'browser-manifest', 'browser-id']);
  is $exit, 0, 'generated launcher executes';
  is $json->decode($out),
    ['--base', $workspace, $host, '--auth-sock', $sock, '--config-file', $conf, 'browser-manifest', 'browser-id'],
    'paths and browser metadata reach plx verbatim';
};

kill 'TERM', $daemon;
waitpid($daemon, 0);
delete $children{$daemon};
done_testing;

sub _browser_params {
  return {
    origin      => 'https://chat.example.test',
    request_id  => 'test-approval',
    identity_id => 'test',
    challenge   => {
      scope           => 'irc://irc.example.test/overnet',
      challenge       => 'browser-test',
      relay_url       => 'wss://relay.example.test',
      grant_kind      => 14142,
      delegate_pubkey => 'a' x 64,
      session_id      => 'test-session',
      expires_at      => int(time) + 600,
    },
  };
}

sub _browser_response {
  my ($params) = @_;
  my ($out) = _native(_frame({type => 'request', id => 'sign-in', method => 'browser.authenticate', params => $params}),
    $endpoint, client => $trusted_client);
  return _decode_frames($out)->[0];
}

sub _native {
  my ($bytes, $socket, %args) = @_;
  my ($input)  = tempfile(DIR => $dir, UNLINK => 1);
  my ($output) = tempfile(DIR => $dir, UNLINK => 1);
  binmode $input,  ':raw';
  binmode $output, ':raw';
  Overnet::Auth::SocketIO->write_all(socket => $input, bytes => $bytes);
  seek $input, 0, 0 or die "seek: $!";
  my $ok = eval {
    Overnet::Auth::NativeMessaging->serve(
      input        => $input,
      output       => $output,
      client       => $args{client} || Overnet::Auth::Client->new(endpoint => $socket),
      ensure_agent => $args{ensure_agent},
    );
    1;
  };
  my $err = $@;
  seek $output, 0, 0 or die "seek: $!";
  my $out = do { local $/; <$output> }
    // q{};
  close $input  or die "close: $!";
  close $output or die "close: $!";
  return ($out, $err, $ok ? 0 : 1);
}

sub _run {
  my ($bytes, $command, %args) = @_;
  my $error = gensym;
  my $pid   = open3(my $input, my $output, $error, @{$command});
  $children{$pid} = 1;
  binmode $input,  ':raw';
  binmode $output, ':raw';
  binmode $error,  ':raw';
  local $SIG{ALRM} = sub { die "native host test timed out\n"; };
  alarm 10;

  if ($args{fragmented}) {
    for my $byte (split //, $bytes) {
      Overnet::Auth::SocketIO->write_all(socket => $input, bytes => $byte);
    }
  } else {
    Overnet::Auth::SocketIO->write_all(socket => $input, bytes => $bytes);
  }
  close $input or die "close stdin: $!";
  my $out = do { local $/; <$output> }
    // q{};
  my $err = do { local $/; <$error> }
    // q{};
  close $output or die "close stdout: $!";
  close $error  or die "close stderr: $!";
  waitpid($pid, 0);
  my $exit = $? >> 8;
  delete $children{$pid};
  alarm 0;
  return ($out, $err, $exit);
}

sub _frame {
  my ($message) = @_;
  my $bytes = $json->encode($message);
  return pack('L', length($bytes)) . $bytes;
}

sub _decode_frames {
  my ($bytes) = @_;
  my @messages;
  while (length($bytes)) {
    die 'incomplete response header' if length($bytes) < 4;
    my $length = unpack('L', substr($bytes, 0, 4, q{}));
    die 'incomplete response body' if length($bytes) < $length;
    push @messages, $json->decode(substr($bytes, 0, $length, q{}));
  }
  return \@messages;
}

sub _write {
  my ($path, $bytes) = @_;
  open my $output, '>:raw', $path or die "open: $!";
  print {$output} $bytes or die "write: $!";
  close $output          or die "close: $!";
  return;
}
