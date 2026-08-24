package Overnet::Program::AdapterSession;

use strictures 2;
use Moo;
use Carp qw(croak);

our $VERSION = '0.001';

has session_id         => (is => 'ro');
has adapter_id         => (is => 'ro');
has adapter            => (is => 'ro', reader => '_adapter');
has config             => (is => 'ro');
has program_session_id => (is => 'ro');
has program_id         => (is => 'ro');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $session_id         = $args{session_id};
  my $adapter_id         = $args{adapter_id};
  my $adapter            = $args{adapter};
  my $config             = $args{config} || {};
  my $program_session_id = $args{program_session_id};
  my $program_id         = $args{program_id};

  if (!(defined $session_id && !ref($session_id) && length($session_id))) {
    croak "session_id is required\n";
  }
  if (!(defined $adapter_id && !ref($adapter_id) && length($adapter_id))) {
    croak "adapter_id is required\n";
  }
  if (!(defined $adapter && ref($adapter))) {
    croak "adapter is required\n";
  }
  if (ref($config) ne 'HASH') {
    croak "config must be an object\n";
  }
  if (defined $program_session_id
    && (ref($program_session_id) || !length($program_session_id))) {
    croak "program_session_id must be a non-empty string\n";
  }
  if (defined $program_id && (ref($program_id) || !length($program_id))) {
    croak "program_id must be a non-empty string\n";
  }

  return {
    session_id         => $session_id,
    adapter_id         => $adapter_id,
    adapter            => $adapter,
    config             => $config,
    program_session_id => $program_session_id,
    program_id         => $program_id,
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub open_session {
  my ($self, %args) = @_;
  my $secret_values = $args{secret_values} || {};

  if (ref($secret_values) ne 'HASH') {
    croak "secret_values must be an object\n";
  }
  if (!($self->{adapter}->can('open_session'))) {
    return 1;
  }

  return $self->{adapter}->open_session(
    adapter_session_id => $self->{session_id},
    adapter_id         => $self->{adapter_id},
    session_config     => $self->{config},
    secret_values      => $secret_values,
    (
      defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id})
      : ()
    ),
    (
      defined $self->{program_id} ? (program_id => $self->{program_id})
      : ()
    ),
  );
}

sub map_input {
  my ($self, $input) = @_;
  if (!($self->{adapter}->can('map_input'))) {
    croak "adapter does not support map_input\n";
  }
  return $self->{adapter}->map_input(
    %{$input || {}},
    session_config     => $self->{config},
    adapter_session_id => $self->{session_id},
    (
      defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id})
      : ()
    ),
    (
      defined $self->{program_id} ? (program_id => $self->{program_id})
      : ()
    ),
  );
}

sub derive {
  my ($self, %args) = @_;
  my $operation = $args{operation};
  my $input     = $args{input} || {};

  if (!(defined $operation && !ref($operation) && length($operation))) {
    croak "operation is required\n";
  }
  if (ref($input) ne 'HASH') {
    croak "input must be an object\n";
  }
  if ($self->{adapter}->can('derive')) {
    return $self->{adapter}->derive(
      operation          => $operation,
      input              => $input,
      session_config     => $self->{config},
      adapter_session_id => $self->{session_id},
      (
        defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id})
        : ()
      ),
      (
        defined $self->{program_id} ? (program_id => $self->{program_id})
        : ()
      ),
    );
  }

  my $operation_method = 'derive_' . $operation;
  if ($self->{adapter}->can($operation_method)) {
    return $self->{adapter}->$operation_method(
      %{$input},
      session_config     => $self->{config},
      adapter_session_id => $self->{session_id},
      (
        defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id})
        : ()
      ),
      (
        defined $self->{program_id} ? (program_id => $self->{program_id})
        : ()
      ),
    );
  }

  croak "adapter does not support derive\n";
}

sub close_session {
  my ($self) = @_;
  if (!($self->{adapter}->can('close_session'))) {
    return 1;
  }

  return $self->{adapter}->close_session(
    adapter_session_id => $self->{session_id},
    adapter_id         => $self->{adapter_id},
    session_config     => $self->{config},
    (
      defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id})
      : ()
    ),
    (
      defined $self->{program_id} ? (program_id => $self->{program_id})
      : ()
    ),
  );
}

1;

=head1 NAME

Overnet::Program::AdapterSession - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::AdapterSession;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 session_id

Public API entry point.

=head2 adapter_id

Public API entry point.

=head2 config

Public API entry point.

=head2 program_session_id

Public API entry point.

=head2 program_id

Public API entry point.

=head2 open_session

Public API entry point.

=head2 map_input

Public API entry point.

=head2 derive

Public API entry point.

=head2 close_session

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
