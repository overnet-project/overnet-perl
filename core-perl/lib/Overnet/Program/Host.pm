package Overnet::Program::Host;

use strictures 2;
use Moo;
use Carp       qw(croak);
use English    qw(-no_match_vars);
use IO::Handle ();
use IO::Select;
use IPC::Open3  qw(open3);
use JSON        ();
use POSIX       qw(WNOHANG);
use Symbol      qw(gensym);
use Time::HiRes qw(sleep time);
use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

our $VERSION = '0.001';

has command                => (is => 'ro', reader   => '_command');
has runtime                => (is => 'ro', reader   => '_runtime');
has service_handler        => (is => 'ro', reader   => '_service_handler');
has protocol               => (is => 'ro', reader   => '_protocol');
has instance               => (is => 'ro', reader   => '_instance');
has poll_interval_ms       => (is => 'ro', reader   => '_poll_interval_ms');
has read_chunk_size        => (is => 'ro', reader   => '_read_chunk_size');
has startup_timeout_ms     => (is => 'ro', reader   => '_startup_timeout_ms');
has shutdown_timeout_ms    => (is => 'ro', reader   => '_shutdown_timeout_ms');
has transcript             => (is => 'rw', accessor => '_transcript');
has observed_notifications => (is => 'rw', accessor => '_observed_notifications');
has stderr_output          => (is => 'rw', accessor => '_raw_stderr_output');
has pid                    => (is => 'rw', accessor => '_pid');
has wait_status            => (is => 'rw', accessor => '_wait_status');
has exit_code              => (is => 'rw', accessor => '_exit_code');
has exit_signal            => (is => 'rw', accessor => '_exit_signal');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $command             = $args{command};
  my $runtime             = $args{runtime};
  my $runtime_args        = exists $args{runtime_args} ? $args{runtime_args} : {};
  my $service_handler     = $args{service_handler};
  my $protocol            = $args{protocol} || Overnet::Program::Protocol->new;
  my $poll_interval_ms    = exists $args{poll_interval_ms}    ? $args{poll_interval_ms}    : 25;
  my $read_chunk_size     = exists $args{read_chunk_size}     ? $args{read_chunk_size}     : 4096;
  my $startup_timeout_ms  = exists $args{startup_timeout_ms}  ? $args{startup_timeout_ms}  : 1_000;
  my $shutdown_timeout_ms = exists $args{shutdown_timeout_ms} ? $args{shutdown_timeout_ms} : 1_000;

  _validate_host_args(
    command             => $command,
    runtime             => $runtime,
    runtime_args        => $runtime_args,
    protocol            => $protocol,
    poll_interval_ms    => $poll_interval_ms,
    read_chunk_size     => $read_chunk_size,
    startup_timeout_ms  => $startup_timeout_ms,
    shutdown_timeout_ms => $shutdown_timeout_ms,
  );

  $runtime         = _build_runtime($runtime, $runtime_args);
  $service_handler = _build_service_handler($service_handler, $runtime);
  my $instance = _build_instance($protocol, $service_handler, \%args);

  return {
    command                => [@{$command}],
    runtime                => $runtime,
    service_handler        => $service_handler,
    protocol               => $protocol,
    instance               => $instance,
    poll_interval_ms       => 0 + $poll_interval_ms,
    read_chunk_size        => 0 + $read_chunk_size,
    startup_timeout_ms     => 0 + $startup_timeout_ms,
    shutdown_timeout_ms    => 0 + $shutdown_timeout_ms,
    transcript             => [],
    observed_notifications => [],
    stderr_output          => q{},
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub _validate_host_args {
  my (%args) = @_;
  if (!(_is_string_array($args{command}))) {
    croak "command must be a non-empty array of strings\n";
  }
  if (!(ref($args{runtime_args}) eq 'HASH')) {
    croak "runtime_args must be an object\n";
  }
  if (defined $args{runtime} && keys %{$args{runtime_args}}) {
    croak "runtime_args cannot be supplied when runtime is provided\n";
  }
  if (!(ref($args{protocol}) && $args{protocol}->isa('Overnet::Program::Protocol'))) {
    croak "protocol must be an Overnet::Program::Protocol instance\n";
  }
  _validate_timeout_args(%args);
  return;
}

sub _validate_timeout_args {
  my (%args) = @_;
  if (!(_is_non_negative_integer($args{poll_interval_ms}))) {
    croak "poll_interval_ms must be a non-negative integer\n";
  }
  if (!(_is_positive_integer($args{read_chunk_size}))) {
    croak "read_chunk_size must be a positive integer\n";
  }
  if (!(_is_non_negative_integer($args{startup_timeout_ms}))) {
    croak "startup_timeout_ms must be a non-negative integer\n";
  }
  if (!(_is_non_negative_integer($args{shutdown_timeout_ms}))) {
    croak "shutdown_timeout_ms must be a non-negative integer\n";
  }
  return;
}

sub _build_runtime {
  my ($runtime, $runtime_args) = @_;
  if (!(defined $runtime)) {
    return Overnet::Program::Runtime->new(%{$runtime_args});
  }
  if (!(ref($runtime) && $runtime->isa('Overnet::Program::Runtime'))) {
    croak "runtime must be an Overnet::Program::Runtime instance\n";
  }
  return $runtime;
}

sub _build_service_handler {
  my ($service_handler, $runtime) = @_;
  if (!(defined $service_handler)) {
    return Overnet::Program::Services->new(runtime => $runtime);
  }
  if (!(ref($service_handler) && $service_handler->isa('Overnet::Program::Services'))) {
    croak "service_handler must be an Overnet::Program::Services instance\n";
  }
  if (!($service_handler->runtime == $runtime)) {
    croak "service_handler runtime must match runtime\n";
  }
  return $service_handler;
}

sub _build_instance {
  my ($protocol, $service_handler, $args) = @_;
  my %instance_args = (
    protocol        => $protocol,
    service_handler => $service_handler,
  );
  for my $field (
    qw(
    supported_protocol_versions
    program_id
    instance_id
    runtime_program_id
    permissions
    services
    config
    )
  ) {

    if (exists $args->{$field}) {
      $instance_args{$field} = $args->{$field};
    }
  }

  return Overnet::Program::Instance->new(%instance_args);
}

sub runtime {
  my ($self) = @_;
  return $self->{runtime};
}

sub service_handler {
  my ($self) = @_;
  return $self->{service_handler};
}

sub protocol {
  my ($self) = @_;
  return $self->{protocol};
}

sub instance {
  my ($self) = @_;
  return $self->{instance};
}

sub pid {
  my ($self) = @_;
  return $self->{pid};
}

sub current_state {
  my ($self) = @_;
  return $self->{instance}->current_state;
}

sub wait_status {
  my ($self) = @_;
  return $self->{wait_status};
}

sub exit_code {
  my ($self) = @_;
  return $self->{exit_code};
}

sub exit_signal {
  my ($self) = @_;
  return $self->{exit_signal};
}

sub has_exited {
  my ($self) = @_;
  return defined $self->{wait_status} ? 1 : 0;
}

sub stderr_output {
  my ($self) = @_;
  return $self->{stderr_output};
}

sub transcript {
  my ($self) = @_;
  return _clone_json($self->{transcript});
}

sub observed_notifications {
  my ($self) = @_;
  return _clone_json($self->{observed_notifications});
}

sub start {
  my ($self, %args) = @_;
  my $timeout_ms =
    exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{startup_timeout_ms};

  if (defined $self->{pid} && !defined $self->{wait_status}) {
    croak "host process already started\n";
  }

  $self->_spawn_child;
  my $ready = eval {
    $self->pump_until(
      timeout_ms => $timeout_ms,
      condition  => sub { $_[0]->instance->is_ready },
    );
  };
  if (!$ready) {
    my $error = $EVAL_ERROR;
    $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 200);
    if (length $error) {
      croak $error;
    }
    croak "Program did not reach ready state within timeout\n";
  }

  return $self;
}

sub pump {
  my ($self, %args) = @_;
  my $timeout_ms =
    exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{poll_interval_ms};

  if (!(_is_non_negative_integer($timeout_ms))) {
    croak "timeout_ms must be a non-negative integer\n";
  }

  my $deadline = _now_ms() + $timeout_ms;
  my $progress = 0;

  while (1) {
    $progress += $self->_poll_io(timeout_ms => 0);
    $progress += $self->_flush_runtime_notifications;

    my $remaining = $deadline - _now_ms();
    if ($remaining < 0) {
      $progress += $self->_poll_io(timeout_ms => 0);
      last;
    }

    my $step_timeout =
        $remaining > $self->{poll_interval_ms}
      ? $self->{poll_interval_ms}
      : $remaining;
    $progress += $self->_poll_io(timeout_ms => $step_timeout);

    if (_now_ms() >= $deadline) {
      last;
    }
    if (defined $self->{wait_status} && !$self->_has_open_read_handles) {
      last;
    }
  }

  return $progress;
}

sub pump_until {
  my ($self, %args) = @_;
  my $condition = $args{condition};
  my $timeout_ms =
    exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{startup_timeout_ms};

  if (!(ref($condition) eq 'CODE')) {
    croak "condition must be a code reference\n";
  }
  if (!(_is_non_negative_integer($timeout_ms))) {
    croak "timeout_ms must be a non-negative integer\n";
  }

  my $deadline = _now_ms() + $timeout_ms;

  while (1) {
    if ($condition->($self)) {
      return 1;
    }

    my $remaining = $deadline - _now_ms();
    if ($remaining < 0) {
      last;
    }

    $self->_poll_io(timeout_ms => 0);
    if ($condition->($self)) {
      return 1;
    }

    $self->_flush_runtime_notifications;
    if ($condition->($self)) {
      return 1;
    }

    $remaining = $deadline - _now_ms();
    if ($remaining < 0) {
      $self->_poll_io(timeout_ms => 0);
      if ($condition->($self)) {
        return 1;
      }
      last;
    }

    my $step_timeout =
        $remaining > $self->{poll_interval_ms}
      ? $self->{poll_interval_ms}
      : $remaining;
    $self->_poll_io(timeout_ms => $step_timeout);

    if ($condition->($self)) {
      return 1;
    }
    if (defined $self->{wait_status} && !$self->_has_open_read_handles) {
      last;
    }
  }

  return $condition->($self) ? 1 : 0;
}

sub request_shutdown {
  my ($self, %args) = @_;
  my $timeout_ms =
    exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{shutdown_timeout_ms};

  my $request = $self->{instance}->request_shutdown((exists $args{reason} ? (reason => $args{reason}) : ()),);
  $self->_send_message($request->{send});

  my $complete = eval {
    $self->pump_until(
      timeout_ms => $timeout_ms,
      condition  => sub {
        my $state = $_[0]->current_state;
        return $state eq 'shutdown_complete' || $state eq 'failed';
      },
    );
  };
  if (!$complete) {
    my $error = $EVAL_ERROR;
    $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 200);
    if (length $error) {
      croak $error;
    }
    croak "Program did not complete runtime.shutdown within timeout\n";
  }

  $self->_close_child_stdin;

  my $exited = $self->pump_until(
    timeout_ms => $timeout_ms,
    condition  => sub { $_[0]->has_exited },
  );
  if (!($exited)) {
    $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 200);
    croak "Program did not exit after runtime.shutdown\n";
  }

  return {
    state       => $self->current_state,
    wait_status => $self->wait_status,
    exit_code   => $self->exit_code,
    exit_signal => $self->exit_signal,
  };
}

sub terminate {
  my ($self, %args) = @_;
  my $signal     = exists $args{signal}     ? $args{signal}     : 'TERM';
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 0;

  if (!(defined $self->{pid} && !defined $self->{wait_status})) {
    return 0;
  }

  $self->_close_child_stdin;
  kill $signal, $self->{pid};

  if (!$timeout_ms) {
    return 1;
  }
  return $self->pump_until(
    timeout_ms => $timeout_ms,
    condition  => sub { $_[0]->has_exited },
  );
}

sub DESTROY {
  my ($self) = @_;
  if (!(defined $self->{pid} && !defined $self->{wait_status})) {
    return;
  }
  $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 100);
  return;
}

sub _spawn_child {
  my ($self) = @_;

  my $child_err = gensym();
  my ($child_in, $child_out);
  my $pid = open3($child_in, $child_out, $child_err, @{$self->{command}});

  binmode($child_in,  ':raw');
  binmode($child_out, ':raw');
  binmode($child_err, ':raw');

  $child_in->autoflush(1);
  $child_out->autoflush(1);
  $child_err->autoflush(1);

  $self->{pid}                        = $pid;
  $self->{child_in}                   = $child_in;
  $self->{child_out}                  = $child_out;
  $self->{child_err}                  = $child_err;
  $self->{wait_status}                = undef;
  $self->{exit_code}                  = undef;
  $self->{exit_signal}                = undef;
  $self->{released_runtime_resources} = 0;
  return;
}

sub _poll_io {
  my ($self, %args) = @_;
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 0;

  $self->_reap_child;

  my @handles =
    grep {defined} ($self->{child_out}, $self->{child_err});
  if (!@handles) {
    if ($timeout_ms > 0) {
      sleep $timeout_ms / 1000;
    }
    $self->_reap_child;
    return 0;
  }

  my $selector = IO::Select->new(@handles);
  my @ready    = $selector->can_read($timeout_ms / 1000);
  my $progress = 0;

  for my $handle (@ready) {
    my $bytes = sysread($handle, my $chunk, $self->{read_chunk_size});

    # uncoverable branch true reason: select reported the handle readable, so sysread fails only under fault injection
    if (!defined $bytes) {

      # uncoverable statement reason: reached only when sysread fails after select
      # uncoverable branch true reason: reached only when a signal interrupts sysread
      # uncoverable branch false reason: reached only when sysread fails after select
      if ($OS_ERROR{EINTR}) {

        # uncoverable statement reason: reached only when a signal interrupts sysread
        next;
      }

      # uncoverable statement reason: reached only when sysread fails after select
      my $stream = $self->_stream_name_for_handle($handle);

      # uncoverable statement reason: reached only when sysread fails after select
      croak "Failed to read $stream from child process: $OS_ERROR\n";
    }

    if ($bytes == 0) {
      $self->_handle_eof($handle);
      next;
    }

    $progress++;
    if ($self->_is_child_out($handle)) {
      $progress += $self->_process_stdout_chunk($chunk);
      next;
    }

    $self->{stderr_output} .= $chunk;
  }

  $self->_reap_child;
  return $progress;
}

sub _process_stdout_chunk {
  my ($self, $chunk) = @_;
  my $messages = eval { $self->{protocol}->feed($chunk) };
  if (!$messages) {
    my $error = $EVAL_ERROR || "Unknown protocol framing error\n";
    croak $error;
  }

  my $progress = 0;
  for my $message (@{$messages}) {
    $progress++;
    push @{$self->{transcript}},
      {
      direction => 'from_program',
      message   => _clone_json($message),
      };

    my $result =
      eval { $self->{instance}->process_program_message($message) };
    if (!$result) {
      my $error = $EVAL_ERROR || "Unknown program protocol error\n";
      croak $error;
    }

    if ($message->{type} eq 'notification'
      && ($result->{observed} || q{}) =~ /\Aprogram\.(?:log|health)\z/mxs) {
      push @{$self->{observed_notifications}}, _clone_json($message);
    }

    if (defined $result->{send}) {
      $self->_send_message($result->{send});
    }

    $progress += $self->_flush_runtime_notifications;

    if ($result->{fatal}) {
      my $error = $result->{error} || {};
      my $code =
        (ref($error) eq 'HASH' && defined $error->{code} && !ref($error->{code}))
        ? $error->{code}
        : 'runtime.fatal';
      my $message_text =
        (ref($error) eq 'HASH' && defined $error->{message} && !ref($error->{message}))
        ? $error->{message}
        : 'Fatal runtime error';
      croak "$code: $message_text\n";
    }
  }

  return $progress;
}

sub _send_message {
  my ($self, $message) = @_;
  if (!(defined $self->{child_in})) {
    croak "child stdin is not available\n";
  }

  my $frame  = $self->{protocol}->encode_message($message);
  my $offset = 0;
  while ($offset < length $frame) {
    my $written = syswrite($self->{child_in}, $frame, length($frame) - $offset, $offset);

    # uncoverable branch true reason: writing to the child stdin pipe fails only under fault injection
    if (!defined $written) {

      # uncoverable statement reason: reached only when syswrite fails
      # uncoverable branch true reason: reached only when a signal interrupts syswrite
      # uncoverable branch false reason: reached only when syswrite fails
      if ($OS_ERROR{EINTR}) {

        # uncoverable statement reason: reached only when a signal interrupts syswrite
        next;
      }

      # uncoverable statement reason: reached only when syswrite fails
      croak "Failed to write protocol frame to child process: $OS_ERROR\n";
    }
    $offset += $written;
  }

  push @{$self->{transcript}},
    {
    direction => 'to_program',
    message   => _clone_json($message),
    };

  return 1;
}

sub _flush_runtime_notifications {
  my ($self) = @_;
  if (!($self->{instance}->is_ready)) {
    return 0;
  }
  if (!(defined $self->{child_in})) {
    return 0;
  }

  my $notifications = $self->{instance}->drain_runtime_notifications;
  for my $message (@{$notifications}) {
    $self->_send_message($message);
  }

  return scalar @{$notifications};
}

sub _close_child_stdin {
  my ($self) = @_;
  if (!(defined $self->{child_in})) {
    return;
  }
  my $child_in = delete $self->{child_in};

  # uncoverable branch true reason: closing a pipe handle cannot fail here
  close $child_in
    or croak "close child stdin failed: $OS_ERROR";
  return;
}

sub _handle_eof {
  my ($self, $handle) = @_;

  if ($self->_is_child_out($handle)) {
    $self->{protocol}->finish;
    my $child_out = delete $self->{child_out};

    # uncoverable branch true reason: closing a pipe handle cannot fail here
    close $child_out
      or croak "close child stdout failed: $OS_ERROR";
    if (!($self->current_state eq 'shutdown_complete')) {
      $self->_drain_child_stderr;
      $self->_reap_child_until(timeout_ms => 50);
      $self->_drain_child_stderr;
      croak $self->_unexpected_stdout_close_error;
    }
    return;
  }

  if ($self->_is_child_err($handle)) {
    my $child_err = delete $self->{child_err};

    # uncoverable branch true reason: closing a pipe handle cannot fail here
    close $child_err
      or croak "close child stderr failed: $OS_ERROR";
    return;
  }
}

sub _reap_child {
  my ($self) = @_;
  if (!(defined $self->{pid})) {
    return;
  }
  if (defined $self->{wait_status}) {
    return;
  }

  my $result = waitpid($self->{pid}, WNOHANG);
  if (!($result == $self->{pid})) {
    return;
  }

  my $wait_status = $CHILD_ERROR;
  $self->{wait_status} = $wait_status;
  $self->{exit_code}   = ($wait_status & 127) ? undef : ($wait_status >> 8);
  $self->{exit_signal} = $wait_status & 127;
  $self->_release_runtime_resources;
  return;
}

sub _reap_child_until {
  my ($self, %args) = @_;
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 0;
  my $deadline   = _now_ms() + $timeout_ms;

  while (1) {
    $self->_reap_child;
    if (defined $self->{wait_status}) {
      return 1;
    }
    if (_now_ms() >= $deadline) {
      return 0;
    }

    my $remaining_ms = $deadline - _now_ms();
    my $sleep_ms     = $remaining_ms < 5 ? $remaining_ms : 5;
    if ($sleep_ms > 0) {
      sleep $sleep_ms / 1000;
    }
  }

  return 0;
}

sub _release_runtime_resources {
  my ($self) = @_;
  if ($self->{released_runtime_resources}) {
    return;
  }
  if (!(defined $self->{runtime})) {
    return;
  }
  if (!(defined $self->{instance})) {
    return;
  }

  my $instance_id = $self->{instance}->instance_id;
  if (!(defined $instance_id && length $instance_id)) {
    return;
  }

  $self->{runtime}->release_session_resources(session_id => $instance_id,);
  $self->{released_runtime_resources} = 1;
  return;
}

sub _has_open_read_handles {
  my ($self) = @_;
  return (defined $self->{child_out} || defined $self->{child_err}) ? 1 : 0;
}

sub _is_child_out {
  my ($self, $handle) = @_;
  return
       defined $self->{child_out}
    && defined $handle
    && defined fileno($self->{child_out})
    && defined fileno($handle)
    && fileno($self->{child_out}) == fileno($handle)
    ? 1
    : 0;
}

sub _is_child_err {
  my ($self, $handle) = @_;
  return
       defined $self->{child_err}
    && defined $handle
    && defined fileno($self->{child_err})
    && defined fileno($handle)
    && fileno($self->{child_err}) == fileno($handle)
    ? 1
    : 0;
}

sub _stream_name_for_handle {
  my ($self, $handle) = @_;
  if ($self->_is_child_out($handle)) {
    return 'stdout';
  }
  if ($self->_is_child_err($handle)) {
    return 'stderr';
  }
  return 'unknown stream';
}

sub _drain_child_stderr {
  my ($self) = @_;
  if (!(defined $self->{child_err})) {
    return;
  }

  my $selector = IO::Select->new($self->{child_err});
  while ($selector->can_read(0)) {
    my $bytes =
      sysread($self->{child_err}, my $chunk, $self->{read_chunk_size});

    # uncoverable branch true reason: draining stderr fails only under fault injection
    if (!defined $bytes) {

      # uncoverable statement reason: reached only when sysread fails while draining stderr
      # uncoverable branch true reason: reached only when a signal interrupts sysread
      # uncoverable branch false reason: reached only when sysread fails while draining stderr
      if ($OS_ERROR{EINTR}) {

        # uncoverable statement reason: reached only when a signal interrupts sysread
        next;
      }

      # uncoverable statement reason: reached only when sysread fails while draining stderr
      last;
    }
    if ($bytes == 0) {
      my $child_err = delete $self->{child_err};

      # uncoverable branch true reason: closing a pipe handle cannot fail here
      close $child_err
        or croak "close child stderr failed: $OS_ERROR";
      last;
    }
    $self->{stderr_output} .= $chunk;
  }
  return;
}

sub _unexpected_stdout_close_error {
  my ($self) = @_;

  my @details;
  if (defined $self->{wait_status}) {
    if (defined $self->{exit_signal} && $self->{exit_signal}) {
      push @details, "child signal=$self->{exit_signal}";
    } elsif (defined $self->{exit_code}) {
      push @details, "child exit_code=$self->{exit_code}";
    } else {
      push @details, "child wait_status=$self->{wait_status}";
    }
  } else {
    push @details, 'child exit_status=unavailable';
  }

  my $stderr = $self->{stderr_output};
  if (defined $stderr && length $stderr) {
    my $max_stderr_bytes = 4096;
    if (length($stderr) > $max_stderr_bytes) {
      $stderr = substr($stderr, -$max_stderr_bytes);
      push @details, "child stderr_tail_bytes=$max_stderr_bytes";
    } else {
      push @details, "child stderr_bytes=" . length($stderr);
    }
  } else {
    push @details, 'child stderr_bytes=0';
  }

  my $message = 'Protocol transport error: program stdout closed before orderly shutdown';
  $message .= ' (' . join(', ', @details) . ')';
  $message .= "\n";
  if (defined $stderr && length $stderr) {
    $message .= "Child stderr:\n$stderr";
  }

  return $message;
}

sub _best_effort_terminate {
  my ($self, %args) = @_;
  eval {
    $self->terminate(%args);
    1;
  } or do {
    return 0;
  };
  return 1;
}

sub _is_string_array {
  my ($value) = @_;
  if (!(ref($value) eq 'ARRAY' && @{$value})) {
    return 0;
  }
  for my $item (@{$value}) {
    if (!(defined $item && !ref($item) && length($item))) {
      return 0;
    }
  }
  return 1;
}

sub _is_non_negative_integer {
  my ($value) = @_;
  return
       defined $value
    && !ref($value)
    && $value =~ /\A(?:0|[1-9]\d*)\z/mxs ? 1 : 0;
}

sub _is_positive_integer {
  my ($value) = @_;
  return defined $value && !ref($value) && $value =~ /\A[1-9]\d*\z/mxs ? 1 : 0;
}

sub _clone_json {
  my ($value) = @_;
  return JSON->new->canonical->decode(JSON->new->canonical->encode($value));
}

sub _now_ms {
  return int(time() * 1000);
}

1;

=head1 NAME

Overnet::Program::Host - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Host;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 runtime

Public API entry point.

=head2 service_handler

Public API entry point.

=head2 protocol

Public API entry point.

=head2 instance

Public API entry point.

=head2 pid

Public API entry point.

=head2 current_state

Public API entry point.

=head2 wait_status

Public API entry point.

=head2 exit_code

Public API entry point.

=head2 exit_signal

Public API entry point.

=head2 has_exited

Public API entry point.

=head2 stderr_output

Public API entry point.

=head2 transcript

Public API entry point.

=head2 observed_notifications

Public API entry point.

=head2 start

Public API entry point.

=head2 pump

Public API entry point.

=head2 pump_until

Public API entry point.

=head2 request_shutdown

Public API entry point.

=head2 terminate

Public API entry point.

=head2 DESTROY

Public API entry point.

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
