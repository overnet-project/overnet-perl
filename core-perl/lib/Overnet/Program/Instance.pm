package Overnet::Program::Instance;

use strictures 2;
use Moo;
use Carp    qw(croak);
use English qw(-no_match_vars);
use Overnet::CommandBus;
use Overnet::Program::Protocol;
use Overnet::Program::Services;

our $VERSION = '0.001';

has protocol                    => (is => 'ro', reader   => '_protocol');
has supported_protocol_versions => (is => 'ro', reader   => '_supported_protocol_versions');
has program_id                  => (is => 'ro', reader   => '_program_id');
has instance_id                 => (is => 'ro', reader   => '_instance_id');
has runtime_program_id          => (is => 'ro', reader   => '_runtime_program_id');
has config                      => (is => 'ro', reader   => '_config');
has permissions                 => (is => 'ro', reader   => '_permissions');
has services                    => (is => 'ro', reader   => '_services');
has service_handler             => (is => 'ro', reader   => '_service_handler');
has state                       => (is => 'rw', accessor => '_state');
has next_request_id             => (is => 'rw', accessor => '_next_request_id');
has inflight                    => (is => 'rw', accessor => '_inflight');
has selected_protocol_version   => (is => 'rw', accessor => '_selected_protocol_version');
has peer_program_id             => (is => 'rw', accessor => '_peer_program_id');
has peer_program_version        => (is => 'rw', accessor => '_peer_program_version');
has peer_metadata               => (is => 'rw', accessor => '_peer_metadata');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $protocol                    = $args{protocol}                    || Overnet::Program::Protocol->new;
  my $supported_protocol_versions = $args{supported_protocol_versions} || ['0.1'];
  my $program_id                  = $args{program_id};
  my $instance_id                 = $args{instance_id}        // 'instance-1';
  my $runtime_program_id          = $args{runtime_program_id} // 'overnet.runtime';
  my $service_handler             = $args{service_handler};
  my $config                      = _config_from_args(\%args, $service_handler);

  _validate_new_args(
    protocol                    => $protocol,
    supported_protocol_versions => $supported_protocol_versions,
    instance_id                 => $instance_id,
    runtime_program_id          => $runtime_program_id,
    service_handler             => $service_handler,
    config                      => $config,
  );

  return {
    protocol                    => $protocol,
    supported_protocol_versions => [@{$supported_protocol_versions}],
    program_id                  => $program_id,
    instance_id                 => $instance_id,
    runtime_program_id          => $runtime_program_id,
    config                      => $config,
    permissions                 => $args{permissions} || [],
    services                    => $args{services}    || {},
    service_handler             => $service_handler,
    state                       => 'awaiting_hello',
    next_request_id             => 1,
    inflight                    => {},
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub _config_from_args {
  my ($args, $service_handler) = @_;
  if (exists $args->{config}) {
    return $args->{config};
  }
  if (defined $service_handler) {
    return $service_handler->runtime->config;
  }
  return {};
}

sub _validate_new_args {
  my (%args) = @_;
  if (!(ref($args{protocol}) && $args{protocol}->isa('Overnet::Program::Protocol'))) {
    croak "protocol must be an Overnet::Program::Protocol instance\n";
  }
  if (!(ref($args{supported_protocol_versions}) eq 'ARRAY' && @{$args{supported_protocol_versions}})) {
    croak "supported_protocol_versions must be a non-empty array\n";
  }
  _validate_instance_ids(%args);
  _validate_instance_services(%args);
  return;
}

sub _validate_instance_ids {
  my (%args) = @_;
  if (!(defined $args{instance_id} && length $args{instance_id})) {
    croak "instance_id is required\n";
  }
  if (!(defined $args{runtime_program_id} && length $args{runtime_program_id})) {
    croak "runtime_program_id is required\n";
  }
  return;
}

sub _validate_instance_services {
  my (%args) = @_;
  if (defined $args{service_handler}) {
    if (!(ref($args{service_handler}) && $args{service_handler}->isa('Overnet::Program::Services'))) {
      croak "service_handler must be an Overnet::Program::Services instance\n";
    }
  }
  if (!(ref($args{config}) eq 'HASH')) {
    croak "config must be an object\n";
  }
  return;
}

sub current_state {
  my ($self) = @_;
  return $self->{state};
}

sub instance_id {
  my ($self) = @_;
  return $self->{instance_id};
}

sub is_ready {
  my ($self) = @_;
  return $self->{state} eq 'ready' ? 1 : 0;
}

sub selected_protocol_version {
  my ($self) = @_;
  return $self->{selected_protocol_version};
}

sub peer_program_id {
  my ($self) = @_;
  return $self->{peer_program_id};
}

sub inflight_request_ids {
  my ($self) = @_;
  return [sort keys %{$self->{inflight}}];
}

sub drain_runtime_notifications {
  my ($self) = @_;

  if (!($self->{state} eq 'ready')) {
    croak "Runtime notifications can only be drained from ready state\n";
  }

  my $handler = $self->{service_handler}
    or return [];
  my $runtime = $handler->runtime;
  if (!(defined $runtime)) {
    return [];
  }

  my $notifications = $runtime->drain_runtime_notifications($self->{instance_id});
  return [map { Overnet::Program::Protocol::build_notification(method => $_->{method}, params => $_->{params} || {},) }
      @{$notifications}];
}

sub process_program_message {
  my ($self, $message) = @_;

  my ($ok, $code, $error) = $self->{protocol}->validate_message($message);
  if (!($ok)) {
    croak "$code: $error\n";
  }

  my $state = $self->{state};

  if ($state eq 'awaiting_hello') {
    return $self->_handle_program_hello($message);
  }

  if ($state eq 'awaiting_init_response') {
    return $self->_handle_init_response($message);
  }

  if ($state eq 'awaiting_ready') {
    return $self->_handle_ready_phase($message);
  }

  if ($state eq 'ready') {
    return $self->_handle_ready_message($message);
  }

  if ($state eq 'shutdown_requested') {
    return $self->_handle_shutdown_response($message);
  }

  if ($state eq 'shutdown_complete') {
    return $self->_handle_post_shutdown_message($message);
  }

  croak "Cannot process messages in state $state\n";
}

sub request_shutdown {
  my ($self, %args) = @_;

  if (!($self->{state} eq 'ready')) {
    croak "Shutdown can only be requested from ready state\n";
  }

  my $id      = $self->_allocate_request_id;
  my $request = Overnet::Program::Protocol::build_runtime_shutdown(
    id     => $id,
    reason => $args{reason},
  );

  $self->{inflight}{$id} = 'runtime.shutdown';
  $self->{state} = 'shutdown_requested';

  return {send => $request,};
}

sub _handle_program_hello {
  my ($self, $message) = @_;

  if (!($message->{type} eq 'notification')) {
    croak "Expected notification in awaiting_hello state\n";
  }
  if (!($message->{method} eq 'program.hello')) {
    croak "Expected program.hello notification\n";
  }

  my $params   = $message->{params} || {};
  my $selected = $self->_select_protocol_version($params->{supported_protocol_versions});
  if (!(defined $selected)) {
    $self->{state} = 'failed';
    return {
      send => Overnet::Program::Protocol::build_runtime_fatal(
        code    => 'protocol.version_mismatch',
        message => 'No compatible protocol version',
        phase   => 'handshake',
        details => {
          runtime_supported_protocol_versions => [@{$self->{supported_protocol_versions}}],
          program_supported_protocol_versions => [@{$params->{supported_protocol_versions} || []}],
        },
      ),
      fatal => 1,
      error => {
        code    => 'protocol.version_mismatch',
        message => 'No compatible protocol version',
      },
    };
  }

  $self->{selected_protocol_version} = $selected;
  $self->{peer_program_id}           = $params->{program_id};
  if (defined $params->{program_version}) {
    $self->{peer_program_version} = $params->{program_version};
  }
  if (defined $params->{metadata}) {
    $self->{peer_metadata} = $params->{metadata};
  }

  my $id = $self->_allocate_request_id;
  my $known_program_id =
    defined $self->{program_id} && length $self->{program_id}
    ? $self->{program_id}
    : $self->{peer_program_id};
  my $request = Overnet::Program::Protocol::build_runtime_init(
    id               => $id,
    protocol_version => $selected,
    instance_id      => $self->{instance_id},
    program_id       => $known_program_id,
    config           => $self->{config},
    permissions      => $self->{permissions},
    services         => $self->{services},
  );

  $self->{inflight}{$id} = 'runtime.init';
  $self->{state} = 'awaiting_init_response';

  return {send => $request,};
}

sub _handle_init_response {
  my ($self, $message) = @_;

  if (!($message->{type} eq 'response')) {
    croak "Expected response while awaiting runtime.init response\n";
  }

  my $method = delete $self->{inflight}{$message->{id}}
    or croak "protocol.unknown_request_id: Unexpected response id while awaiting runtime.init response\n";

  # uncoverable branch true reason: runtime.init is the only request in flight while awaiting its response
  if (!($method eq 'runtime.init')) {
    croak "Expected runtime.init response\n";    # uncoverable statement reason: guarded by the branch above
  }

  if ($message->{ok}) {
    $self->{state} = 'awaiting_ready';
    return {accepted => 1};
  }

  $self->{state} = 'failed';
  return {
    rejected => 1,
    error    => $message->{error},
  };
}

sub _handle_ready_phase {
  my ($self, $message) = @_;

  if (!($message->{type} eq 'notification')) {
    croak "Expected notification while awaiting program.ready\n";
  }

  if ($message->{method} eq 'program.ready') {
    $self->{state} = 'ready';
    return {ready => 1};
  }

  if ( $message->{method} eq 'program.log'
    || $message->{method} eq 'program.health') {
    return {observed => $message->{method}};
  }

  croak "Unexpected notification while awaiting program.ready\n";
}

sub _handle_ready_message {
  my ($self, $message) = @_;

  if ($message->{type} eq 'notification') {
    if ( $message->{method} eq 'program.log'
      || $message->{method} eq 'program.health') {
      return {observed => $message->{method}};
    }

    croak "protocol.unknown_method: Unexpected notification in ready state: $message->{method}\n";
  }

  if ($message->{type} eq 'request') {
    return $self->_handle_service_request($message);
  }

  if ($message->{type} eq 'response') {
    my $method = delete $self->{inflight}{$message->{id}}
      or croak "protocol.unknown_request_id: Unexpected response id in ready state\n";
    return {
      response_to => $method,
      ok          => $message->{ok} ? 1 : 0,
      ($message->{ok} ? () : (error => $message->{error})),
    };
  }

  croak "Unexpected message type in ready state\n";
}

sub _handle_service_request {
  my ($self, $message) = @_;

  if (!(Overnet::Program::Services->is_service_method($message->{method}))) {
    return {
      send => Overnet::Program::Protocol::build_response_error(
        id      => $message->{id},
        code    => 'protocol.unknown_method',
        message => "Unknown request method in this context: $message->{method}",
      ),
    };
  }

  my $handler = $self->{service_handler}
    or return {
    send => Overnet::Program::Protocol::build_response_error(
      id      => $message->{id},
      code    => 'runtime.service_unavailable',
      message => 'No service handler configured for request processing',
    ),
    };

  my $result;
  my $error;
  eval {
    $result = $handler->dispatch_request(
      $message->{method},
      $message->{params} || {},
      permissions => $self->{permissions},
      session_id  => $self->{instance_id},
      program_id  => $self->_known_program_id,
    );
    1;
  } or $error = $EVAL_ERROR;

  if ($error) {
    my $normalized = Overnet::CommandBus->normalize_error($error, code => 'program.operation_failed');
    my %response   = (
      id      => $message->{id},
      code    => $normalized->{code},
      message => $normalized->{message},
    );
    if (defined $normalized->{details}) {
      $response{details} = $normalized->{details};
    }

    return {send => Overnet::Program::Protocol::build_response_error(%response),};
  }

  return {
    send => Overnet::Program::Protocol::build_response_ok(
      id     => $message->{id},
      result => $result || {},
    ),
  };
}

sub _handle_shutdown_response {
  my ($self, $message) = @_;

  if ($message->{type} eq 'notification') {
    if ( $message->{method} eq 'program.log'
      || $message->{method} eq 'program.health') {
      return {observed => $message->{method}};
    }

    croak
      "protocol.unknown_method: Unexpected notification while awaiting runtime.shutdown response: $message->{method}\n";
  }

  if ($message->{type} eq 'request') {
    return {};
  }

# uncoverable branch true reason: protocol validation admits only notification, request, and response types, and the first two are handled above
  if (!($message->{type} eq 'response')) {
    croak "Expected response while awaiting runtime.shutdown response\n"
      ;    # uncoverable statement reason: guarded by the branch above
  }

  my $method = delete $self->{inflight}{$message->{id}}
    or croak "protocol.unknown_request_id: Unexpected response id while awaiting runtime.shutdown response\n";

  # uncoverable branch true reason: runtime.shutdown is the only request in flight while awaiting its response
  if ($method ne 'runtime.shutdown') {
    return {
      response_to => $method,
      ok          => $message->{ok} ? 1 : 0,
      ($message->{ok} ? () : (error => $message->{error})),
    };
  }

  if ($message->{ok}) {
    $self->_revoke_secret_handles;
    $self->{state} = 'shutdown_complete';
    return {shutdown_complete => 1};
  }

  $self->_revoke_secret_handles;
  $self->{state} = 'failed';
  return {
    shutdown_rejected => 1,
    error             => $message->{error},
  };
}

sub _handle_post_shutdown_message {
  my ($self, $message) = @_;

  if ($message->{type} eq 'notification') {
    if ( $message->{method} eq 'program.log'
      || $message->{method} eq 'program.health') {
      return {observed => $message->{method}};
    }
    return {};
  }

  if ($message->{type} eq 'response') {
    my $method = delete $self->{inflight}{$message->{id}};
    return {
      (defined $method ? (response_to => $method) : ()),
      ok => $message->{ok} ? 1 : 0,
      ($message->{ok} ? () : (error => $message->{error})),
    };
  }

  if ($message->{type} eq 'request') {
    return {};
  }

  return {};
}

sub _allocate_request_id {
  my ($self) = @_;
  my $id = 'runtime-' . $self->{next_request_id}++;
  return $id;
}

sub _select_protocol_version {
  my ($self, $peer_versions) = @_;

  # uncoverable branch true reason: protocol validation requires program.hello to carry a non-empty version array
  if (!(ref($peer_versions) eq 'ARRAY' && @{$peer_versions})) {
    return;    # uncoverable statement reason: guarded by the branch above
  }

  my %peer = map { $_ => 1 } @{$peer_versions};
  for my $version (@{$self->{supported_protocol_versions}}) {
    if ($peer{$version}) {
      return $version;
    }
  }

  return;
}

sub _known_program_id {
  my ($self) = @_;
  if (defined $self->{program_id} && length $self->{program_id}) {
    return $self->{program_id};
  }
  return $self->{peer_program_id};
}

sub _revoke_secret_handles {
  my ($self) = @_;
  my $handler = $self->{service_handler}
    or return 0;
  my $runtime = $handler->runtime
    or return 0;

  return $runtime->revoke_secret_handles_for_session(session_id => $self->{instance_id},);
}

1;

=head1 NAME

Overnet::Program::Instance - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Instance;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 current_state

Public API entry point.

=head2 instance_id

Public API entry point.

=head2 is_ready

Public API entry point.

=head2 selected_protocol_version

Public API entry point.

=head2 peer_program_id

Public API entry point.

=head2 inflight_request_ids

Public API entry point.

=head2 drain_runtime_notifications

Public API entry point.

=head2 process_program_message

Public API entry point.

=head2 request_shutdown

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
