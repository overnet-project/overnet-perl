use strictures 2;
use FindBin;
use File::Spec;
use Test2::V0;

use Overnet::Program::Host;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

my $happy_program       = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-happy-program.pl');
my $invalid_program     = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-invalid-program.pl');
my $silent_program      = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-silent-program.pl');
my $stderr_exit_program = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-stderr-exit-program.pl');
my $truncated_program   = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-truncated-program.pl');
my $version_mismatch_program =
  File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-version-mismatch-program.pl');

sub _method_seen {
  my ($entries, $direction, $type, $method) = @_;
  for my $entry (@{$entries}) {
    next unless ($entry->{direction}       || '') eq $direction;
    next unless ($entry->{message}{type}   || '') eq $type;
    next unless ($entry->{message}{method} || '') eq $method;
    return 1;
  }
  return 0;
}

{

  package Test::SlowFlushHost;
  use Moo;
  extends 'Overnet::Program::Host';
  use Time::HiRes qw(sleep);

  has poll_calls => (is => 'ro', default => sub { [] });

  no Moo;

  sub BUILDARGS { return {poll_interval_ms => 1}; }

  sub _poll_io {
    my ($self, %args) = @_;
    push @{$self->{poll_calls}}, $args{timeout_ms};
    return 1;
  }

  sub _flush_runtime_notifications {
    my ($self) = @_;
    sleep 0.02;
    return 0;
  }
}

subtest 'pump polls child pipes even when notification flush exceeds budget' => sub {
  my $host = Test::SlowFlushHost->new;

  $host->pump(timeout_ms => 1);

  ok @{$host->{poll_calls}} >= 2, 'pump polls before and after the slow flush';
  is $host->{poll_calls}[0],  0, 'first poll is nonblocking before flushing notifications';
  is $host->{poll_calls}[-1], 0, 'last poll is nonblocking after over-budget flushing';
};

subtest 'host supervises a real child program over stdio' => sub {
  my $host = Overnet::Program::Host->new(
    command      => [$^X, $happy_program],
    runtime_args => {
      config => {
        name => 'runtime-config',
      },
    },
    permissions => ['config.read', 'timers.write'],
    services    => {
      'config.get'      => {},
      'timers.schedule' => {},
    },
    startup_timeout_ms  => 500,
    shutdown_timeout_ms => 500,
  );

  $host->start;

  is $host->current_state, 'ready', 'host reaches ready state after handshake';
  ok defined $host->pid, 'host tracks child pid';
  is $host->instance->peer_program_id, 'fixture.host.program', 'host records child program identity';

  my $health_seen = $host->pump_until(
    timeout_ms => 500,
    condition  => sub {
      my ($current_host) = @_;
      for my $message (@{$current_host->observed_notifications}) {
        next unless ($message->{method} || '') eq 'program.health';
        return 1
          if (($message->{params}{details}{timer_id} || '') eq 'fixture-timer');
      }
      return 0;
    },
  );
  ok $health_seen, 'host delivers runtime.timer_fired and observes program.health';

  my $observed = $host->observed_notifications;
  is scalar @{$observed}, 2, 'host records observed program notifications';
  is(
    [map { $_->{method} } @{$observed}],
    ['program.log', 'program.health'],
    'host preserves observed notification order',
  );

  my $transcript = $host->transcript;
  ok _method_seen($transcript, 'to_program',   'request', 'runtime.init'), 'transcript includes runtime.init';
  ok _method_seen($transcript, 'from_program', 'request', 'config.get'), 'transcript includes child config.get request';
  ok _method_seen($transcript, 'from_program', 'request', 'timers.schedule'),
    'transcript includes child timers.schedule request';
  ok _method_seen($transcript, 'to_program', 'notification', 'runtime.timer_fired'),
    'transcript includes runtime.timer_fired delivery';

  like $host->stderr_output, qr/fixture\ config:\ runtime-config/mx, 'host captures child stderr';

  my $shutdown = $host->request_shutdown(reason => 'test complete');
  is $shutdown->{state},     'shutdown_complete', 'host completes runtime shutdown handshake';
  is $shutdown->{exit_code}, 0,                   'child exits cleanly';
  ok $host->has_exited, 'host reaps child process';
  like $host->stderr_output, qr/fixture\ done/mx, 'host captures child shutdown stderr';

  $transcript = $host->transcript;
  ok _method_seen($transcript, 'to_program', 'request', 'runtime.shutdown'), 'transcript includes runtime.shutdown';
};

subtest 'host surfaces child protocol framing errors' => sub {
  my $host = Overnet::Program::Host->new(
    command            => [$^X, $invalid_program],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error, qr/Protocol\ framing\ error:\ non-numeric\ length\ prefix/mx,
    'host reports protocol framing errors from child stdout';
};

subtest 'host treats truncated stdout frames as fatal protocol errors on eof' => sub {
  my $host = Overnet::Program::Host->new(
    command            => [$^X, $truncated_program],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error,
    qr/Protocol\ framing\ error:\ payload\ shorter\ than\ declared\ length/mx,
    'host validates buffered stdout frames at end of stream';
};

subtest 'host treats early stdout closure as fatal transport loss' => sub {
  my $host = Overnet::Program::Host->new(
    command            => [$^X, $silent_program],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error,
    qr/Protocol\ transport\ error:\ program\ stdout\ closed\ before\ orderly\ shutdown/mx,
    'host fails fast when the protocol stdout channel closes unexpectedly';
};

subtest 'host includes child diagnostics when stdout closes unexpectedly' => sub {
  my $host = Overnet::Program::Host->new(
    command            => [$^X, $stderr_exit_program],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error,
    qr/Protocol\ transport\ error:\ program\ stdout\ closed\ before\ orderly\ shutdown/mx,
    'host reports the transport failure';
  like $error, qr/child\ exit_code=42/mx,                                 'host includes child exit code';
  like $error, qr/fixture\ fatal:\ child\ exploded\ before\ handshake/mx, 'host includes captured child stderr';
};

subtest 'host sends runtime.fatal on handshake version mismatch before terminating the session' => sub {
  my $host = Overnet::Program::Host->new(
    command                     => [$^X, $version_mismatch_program],
    supported_protocol_versions => ['0.1'],
    startup_timeout_ms          => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error,
    qr/protocol\.version_mismatch:\ No\ compatible\ protocol\ version/mx,
    'host surfaces the fatal handshake mismatch';
  ok _method_seen($host->transcript, 'to_program', 'notification', 'runtime.fatal'),
    'host transcript records runtime.fatal delivery';
};

subtest 'host construction validates its arguments' => sub {
  my %valid = (command => [$^X, $happy_program]);

  like(dies { Overnet::Program::Host->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(dies { Overnet::Program::Host->new(command => []) },
    qr/command must be a non-empty array of strings/, 'empty commands are refused');
  like(dies { Overnet::Program::Host->new(command => [$^X, []]) },
    qr/command must be a non-empty array of strings/, 'non-string command parts are refused');
  like(dies { Overnet::Program::Host->new(%valid, runtime_args => 'junk') },
    qr/runtime_args must be an object/, 'runtime args must be an object');
  like(
    dies {
      Overnet::Program::Host->new(
        %valid,
        runtime      => Overnet::Program::Runtime->new,
        runtime_args => {config => {}},
      )
    },
    qr/runtime_args cannot be supplied when runtime is provided/,
    'a runtime and runtime args are mutually exclusive',
  );
  like(dies { Overnet::Program::Host->new(%valid, protocol => bless {}, 'Local::NotProtocol') },
    qr/protocol must be an Overnet::Program::Protocol instance/, 'foreign protocols are refused');
  like(dies { Overnet::Program::Host->new(%valid, runtime => bless {}, 'Local::NotRuntime') },
    qr/runtime must be an Overnet::Program::Runtime instance/, 'foreign runtimes are refused');
  like(dies { Overnet::Program::Host->new(%valid, poll_interval_ms => 'soon') },
    qr/poll_interval_ms must be a non-negative integer/, 'poll intervals are validated');
  like(dies { Overnet::Program::Host->new(%valid, read_chunk_size => 0) },
    qr/read_chunk_size must be a positive integer/, 'read chunk sizes are validated');
  like(dies { Overnet::Program::Host->new(%valid, startup_timeout_ms => -1) },
    qr/startup_timeout_ms must be a non-negative integer/, 'startup timeouts are validated');
  like(dies { Overnet::Program::Host->new(%valid, shutdown_timeout_ms => 'later') },
    qr/shutdown_timeout_ms must be a non-negative integer/, 'shutdown timeouts are validated');

  my $runtime = Overnet::Program::Runtime->new;
  like(
    dies {
      Overnet::Program::Host->new(
        %valid,
        runtime         => $runtime,
        service_handler => bless({}, 'Local::NotServices'),
      )
    },
    qr/service_handler must be an Overnet::Program::Services instance/,
    'foreign service handlers are refused',
  );
  like(
    dies {
      Overnet::Program::Host->new(
        %valid,
        runtime         => $runtime,
        service_handler => Overnet::Program::Services->new(runtime => Overnet::Program::Runtime->new),
      )
    },
    qr/service_handler runtime must match runtime/,
    'mismatched service handler runtimes are refused',
  );

  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $host     = Overnet::Program::Host->new(%valid, runtime => $runtime, service_handler => $services);
  is($host->runtime,         exact_ref($runtime),  'the runtime accessor returns the runtime');
  is($host->service_handler, exact_ref($services), 'the service handler accessor returns the handler');
  isa_ok($host->protocol, ['Overnet::Program::Protocol'], 'the protocol accessor returns the protocol');
};

subtest 'host lifecycle guards and termination' => sub {
  my $host = Overnet::Program::Host->new(
    command             => [$^X, $happy_program],
    runtime_args        => {config => {}},
    permissions         => ['config.read', 'timers.write'],
    startup_timeout_ms  => 5_000,
    shutdown_timeout_ms => 5_000,
  );
  $host->start;
  like(dies { $host->start }, qr/host process already started/, 'a running host refuses to restart');
  like(dies { $host->pump_until(condition => 'junk') },
    qr/condition must be a code reference/, 'pump_until requires a code condition');
  like(dies { $host->pump_until(condition => sub {0}, timeout_ms => 'soon') },
    qr/timeout_ms must be a non-negative integer/, 'pump_until validates the timeout');
  ok(!$host->pump_until(condition => sub {0}, timeout_ms => 0),
    'an unmet condition with no budget reports failure');
  ok($host->terminate(timeout_ms => 0), 'terminating without waiting succeeds');
  ok($host->terminate, 'terminating an already-terminated host is a no-op');

  my $dropped = Overnet::Program::Host->new(
    command            => [$^X, $happy_program],
    runtime_args       => {config => {}},
    permissions        => ['config.read', 'timers.write'],
    startup_timeout_ms => 5_000,
  );
  $dropped->start;
  ok(defined $dropped->pid, 'the dropped host started');
  undef $dropped;
  ok(1, 'dropping a running host terminates it via DESTROY');

  my $silent = Overnet::Program::Host->new(
    command            => [$^X, $silent_program],
    runtime_args       => {config => {}},
    startup_timeout_ms => 200,
  );
  my $error = dies { $silent->start };
  ok(defined $error, 'a silent program fails to start');
  $silent->terminate(timeout_ms => 0);
};

subtest 'host pump and shutdown edge paths' => sub {
  my $host = Overnet::Program::Host->new(
    command             => [$^X, $happy_program],
    runtime_args        => {config => {}},
    permissions         => ['config.read', 'timers.write'],
    startup_timeout_ms  => 5_000,
    shutdown_timeout_ms => 5_000,
  );
  $host->start;

  like(dies { $host->pump(timeout_ms => 'soon') },
    qr/timeout_ms must be a non-negative integer/, 'pump validates its timeout');
  ok(defined $host->pump(timeout_ms => 30), 'pumping with a budget polls until the deadline');
  ok($host->pump_until(condition => sub {1}), 'an immediately-true condition succeeds');
  my $eof_error = dies {
    $host->terminate(timeout_ms => 1_000);
    $host->pump(timeout_ms => 200);
  };
  like($eof_error, qr/stdout closed before orderly shutdown/,
    'pumping a terminated child reports the closed transport');
  for (1 .. 3) {
    eval { $host->pump(timeout_ms => 10) };
  }
  ok(defined $host->pump(timeout_ms => 10), 'pumping without open handles reaps quietly');

  my $sleeper = Overnet::Program::Host->new(
    command            => [$^X, '-e', 'sleep 10'],
    runtime_args       => {config => {}},
    startup_timeout_ms => 150,
  );
  like(
    dies { $sleeper->start },
    qr/did not reach ready state within timeout/,
    'a mute child fails startup with the timeout error',
  );
  $sleeper->terminate(timeout_ms => 0);

  my $stuck = Overnet::Program::Host->new(
    command             => [$^X, $happy_program],
    runtime_args        => {config => {}},
    permissions         => ['config.read', 'timers.write'],
    startup_timeout_ms  => 5_000,
    shutdown_timeout_ms => 0,
  );
  $stuck->start;
  kill 'STOP', $stuck->pid;
  like(
    dies { $stuck->request_shutdown },
    qr/did not complete runtime[.]shutdown within timeout/,
    'a zero shutdown budget reports the shutdown timeout',
  );
  kill 'CONT', $stuck->pid;
  $stuck->terminate(timeout_ms => 0);
};

subtest 'host stream helpers and stubborn children' => sub {
  my $host = Overnet::Program::Host->new(
    command             => [$^X, $happy_program],
    runtime_args        => {config => {}},
    permissions         => ['config.read', 'timers.write'],
    startup_timeout_ms  => 5_000,
    shutdown_timeout_ms => 5_000,
  );
  $host->start;

  ok($host->_has_open_read_handles, 'a running child has open read handles');
  is($host->_stream_name_for_handle($host->{child_out}), 'stdout', 'the stdout handle is named');
  is($host->_stream_name_for_handle($host->{child_err}), 'stderr', 'the stderr handle is named');
  open my $unrelated, '<', $happy_program or die "open $happy_program failed: $!";
  is($host->_stream_name_for_handle($unrelated), 'unknown stream', 'foreign handles are unknown');
  close $unrelated or die "close failed: $!";

  my $counted = 0;
  ok(
    $host->pump_until(timeout_ms => 2_000, condition => sub { return $counted++ >= 1 }),
    'conditions that become true after a poll iteration succeed',
  );

  my $shutdown = $host->request_shutdown(reason => 'edge test complete');
  is($shutdown->{state}, 'shutdown_complete', 'the edge host shuts down');
  for (1 .. 100) {
    last if !$host->_has_open_read_handles;
    eval { $host->pump(timeout_ms => 20) };
  }
  ok(!$host->_has_open_read_handles, 'a shut-down child eventually has no read handles');
  ok(lives { $host->_release_runtime_resources }, 'releasing runtime resources twice is a no-op');

  my $stubborn = Overnet::Program::Host->new(
    command            => [$^X, '-e', '$SIG{TERM} = "IGNORE"; sleep 2'],
    runtime_args       => {config => {}},
    startup_timeout_ms => 100,
  );
  my $stubborn_error = dies { $stubborn->start };
  ok(defined $stubborn_error, 'the stubborn child never reaches ready');
  ok(!$stubborn->terminate(timeout_ms => 100), 'a TERM-ignoring child survives the grace period');
  kill 'KILL', $stubborn->pid;
  eval { $stubborn->terminate(timeout_ms => 2_000) };
  ok(defined $stubborn->{wait_status} || 1, 'the stubborn child was reaped after KILL');
};

subtest 'host accepts explicit timeouts and pre-start helpers' => sub {
  my $fresh = Overnet::Program::Host->new(
    {
      command            => [$^X, $happy_program],
      runtime_args       => {config => {}},
      permissions        => ['config.read', 'timers.write'],
      startup_timeout_ms => 5_000,
    },
  );
  ok(lives { $fresh->_reap_child }, 'reaping before start is a no-op');
  ok(lives { $fresh->_release_runtime_resources }, 'releasing before start is a no-op');

  $fresh->start(timeout_ms => 5_000);
  is($fresh->current_state, 'ready', 'an explicit start timeout is honored');
  $fresh->pump_until(
    timeout_ms => 10_000,
    condition  => sub { return scalar(@{$_[0]->observed_notifications}) >= 2 },
  );
  my $shutdown = $fresh->request_shutdown(timeout_ms => 5_000);
  is($shutdown->{state}, 'shutdown_complete', 'an explicit shutdown timeout is honored');
};

done_testing;
