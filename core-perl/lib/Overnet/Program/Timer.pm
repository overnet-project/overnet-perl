package Overnet::Program::Timer;

use strictures 2;
use Moo;
use Carp qw(croak);
use JSON ();

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;

has session_id => (is => 'ro');
has timer_id   => (is => 'ro');
has due_at_ms  => (is => 'rw');
has repeat_ms  => (is => 'ro');
has payload    => (is => 'ro', reader => '_payload');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $session_id = $args{session_id};
  my $timer_id   = $args{timer_id};
  my $due_at_ms  = $args{due_at_ms};
  my $repeat_ms  = $args{repeat_ms};
  my $payload    = $args{payload};

  if (!(defined $session_id && !ref($session_id) && length($session_id))) {
    croak "session_id is required\n";
  }
  if (!(defined $timer_id && !ref($timer_id) && length($timer_id))) {
    croak "timer_id is required\n";
  }
  if (!(defined $due_at_ms && !ref($due_at_ms) && $due_at_ms =~ /\A-?\d+\z/mxs)) {
    croak "due_at_ms must be an integer\n";
  }
  if (defined $repeat_ms
    && (ref($repeat_ms) || $repeat_ms !~ /\A[1-9]\d*\z/mxs)) {
    croak "repeat_ms must be a positive integer\n";
  }
  if (defined $payload && ref($payload) ne 'HASH') {
    croak "payload must be an object\n";
  }

  return {
    session_id => $session_id,
    timer_id   => $timer_id,
    due_at_ms  => 0 + $due_at_ms,
    (defined $repeat_ms ? (repeat_ms => 0 + $repeat_ms)        : ()),
    (defined $payload   ? (payload   => _clone_json($payload)) : ()),
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub payload {
  my ($self) = @_;
  return exists $self->{payload} ? _clone_json($self->{payload}) : undef;
}

sub is_due {
  my ($self, $now_ms) = @_;

  if (!(defined $now_ms && !ref($now_ms) && $now_ms =~ /\A-?\d+\z/mxs)) {
    croak "now_ms must be an integer\n";
  }

  return $self->{due_at_ms} <= $now_ms ? 1 : 0;
}

sub is_repeating {
  my ($self) = @_;
  return defined $self->{repeat_ms} ? 1 : 0;
}

sub advance_after_fire {
  my ($self) = @_;

  if (!($self->is_repeating)) {
    croak "Timer is not repeating\n";
  }

  $self->{due_at_ms} += $self->{repeat_ms};
  return $self->{due_at_ms};
}

sub advance_after_fire_until_after {
  my ($self, $now_ms) = @_;

  if (!($self->is_repeating)) {
    croak "Timer is not repeating\n";
  }
  if (!(defined $now_ms && !ref($now_ms) && $now_ms =~ /\A-?\d+\z/mxs)) {
    croak "now_ms must be an integer\n";
  }

  $self->advance_after_fire;
  while ($self->{due_at_ms} <= $now_ms) {
    $self->{due_at_ms} += $self->{repeat_ms};
  }

  return $self->{due_at_ms};
}

sub build_notification_params {
  my ($self, %args) = @_;
  my $fired_at = $args{fired_at};

  if (!(defined $fired_at && !ref($fired_at) && $fired_at =~ /\A-?\d+\z/mxs)) {
    croak "fired_at must be an integer\n";
  }

  my %params = (
    timer_id => $self->{timer_id},
    fired_at => 0 + $fired_at,
  );
  if (exists $self->{payload}) {
    $params{payload} = _clone_json($self->{payload});
  }

  return \%params;
}

sub _clone_json {
  my ($value) = @_;
  return $JSON->decode($JSON->encode($value));
}

1;

=head1 NAME

Overnet::Program::Timer - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Timer;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 session_id

Public API entry point.

=head2 timer_id

Public API entry point.

=head2 due_at_ms

Public API entry point.

=head2 repeat_ms

Public API entry point.

=head2 payload

Public API entry point.

=head2 is_due

Public API entry point.

=head2 is_repeating

Public API entry point.

=head2 advance_after_fire

Public API entry point.

=head2 advance_after_fire_until_after

Public API entry point.

=head2 build_notification_params

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
