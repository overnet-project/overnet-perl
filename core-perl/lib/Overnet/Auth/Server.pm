package Overnet::Auth::Server;

use strictures 2;
use Moo;
use Carp         qw(croak);
use English      qw(-no_match_vars);
use Scalar::Util qw(blessed);

use Overnet::Program::Protocol;
use Overnet::Auth::SocketIO;

our $VERSION = '0.001';

has agent    => (is => 'ro', reader => '_agent');
has protocol => (is => 'ro', reader => '_protocol');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);
  if (!(blessed($args{agent}) && $args{agent}->can('dispatch'))) {
    croak "agent is required\n";
  }

  return {
    agent    => $args{agent},
    protocol => $args{protocol} || Overnet::Program::Protocol->new,
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub serve_socket {
  my ($self, $socket) = @_;
  if (!($socket)) {
    croak "socket is required\n";
  }

  my $reader = Overnet::Program::Protocol->new(max_frame_size => $self->{protocol}->max_frame_size,);

  while (1) {
    my $chunk = q{};
    my $read  = sysread($socket, $chunk, 4096);
    if (!(defined $read)) {
      croak "read from auth-agent socket failed: $OS_ERROR";
    }
    if ($read == 0) {
      last;
    }

    my $messages = $reader->feed($chunk);
    for my $message (@{$messages}) {
      my $response = $self->{agent}->dispatch($message);
      my $frame    = $self->{protocol}->encode_message($response);
      _write_all($socket, $frame);
      return 1;
    }
  }

  $reader->finish;
  return 1;
}

sub _write_all {
  my ($socket, $bytes) = @_;
  return Overnet::Auth::SocketIO->write_all(
    socket => $socket,
    bytes  => $bytes,
    target => 'auth-agent socket',
  );
}

1;

=head1 NAME

Overnet::Auth::Server - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Server;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 serve_socket

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
