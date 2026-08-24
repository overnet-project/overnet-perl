package Overnet::Auth::Daemon;

use strictures 2;
use Moo;
use Carp         qw(croak);
use English      qw(-no_match_vars);
use Scalar::Util qw(blessed);

use File::Basename qw(dirname);
use File::Path     qw(make_path);
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

use Overnet::Auth::Agent;
use Overnet::Auth::Config;
use Overnet::Auth::Server;
use Overnet::Auth::StateStore;

our $VERSION = '0.001';

has config          => (is => 'ro', reader => '_config');
has endpoint        => (is => 'ro');
has socket_mode     => (is => 'ro', reader   => '_socket_mode');
has max_connections => (is => 'ro', reader   => '_max_connections');
has server          => (is => 'ro', reader   => '_server');
has state_store     => (is => 'ro', reader   => '_state_store');
has listen_factory  => (is => 'ro', reader   => '_listen_factory');
has listen_socket   => (is => 'rw', accessor => '_current_listen_socket');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $config          = _daemon_config(%args);
  my $endpoint        = _daemon_endpoint($config, %args);
  my $socket_mode     = _daemon_socket_mode($config, %args);
  my $max_connections = _daemon_max_connections(%args);
  my $state_store     = _daemon_state_store($config, %args);
  my $agent           = _daemon_agent($config, $state_store, %args);
  my $server          = $args{server} || Overnet::Auth::Server->new(agent => $agent);

  return {
    config          => $config,
    endpoint        => $endpoint,
    socket_mode     => $socket_mode,
    max_connections => $max_connections,
    server          => $server,
    state_store     => $state_store,
    listen_factory  => $args{listen_factory},
    listen_socket   => undef,
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub _daemon_config {
  my (%args) = @_;
  my $config = $args{config};
  if (!defined($config) && defined($args{config_file})) {
    $config = Overnet::Auth::Config->load_file(path => $args{config_file});
  }
  if (!(defined $config)) {
    $config = Overnet::Auth::Config->new(config => {});
  }
  if (!(blessed($config) && $config->isa('Overnet::Auth::Config'))) {
    croak "config must be an Overnet::Auth::Config\n";
  }
  return $config;
}

sub _daemon_endpoint {
  my ($config, %args) = @_;
  my $endpoint =
       defined($args{endpoint})
    && !ref($args{endpoint})
    && length($args{endpoint})
    ? $args{endpoint}
    : $config->endpoint;
  if (!(defined $endpoint && !ref($endpoint) && length($endpoint))) {
    croak "auth-agent endpoint is required\n";
  }
  return $endpoint;
}

sub _daemon_socket_mode {
  my ($config, %args) = @_;
  my $socket_mode =
    exists($args{socket_mode})
    ? $args{socket_mode}
    : $config->socket_mode;
  return defined $socket_mode ? $socket_mode : oct('0600');
}

sub _daemon_state_store {
  my ($config, %args) = @_;
  if (defined $args{state_store}) {
    return $args{state_store};
  }
  my $state_file =
       defined($args{state_file})
    && !ref($args{state_file})
    && length($args{state_file})
    ? $args{state_file}
    : $config->state_file;
  if (defined($state_file) && !ref($state_file) && length($state_file)) {
    return Overnet::Auth::StateStore->new(path => $state_file);
  }
  return;
}

sub _daemon_max_connections {
  my (%args) = @_;
  if (!(exists $args{max_connections})) {
    return;
  }
  my $max_connections = $args{max_connections};
  if (!(defined $max_connections && !ref($max_connections) && $max_connections =~ /\A[1-9]\d*\z/mxs)) {
    croak "max_connections must be a positive integer\n";
  }
  return 0 + $max_connections;
}

sub _daemon_agent {
  my ($config, $state_store, %args) = @_;
  my $agent = $args{agent} || _build_daemon_agent($config, $state_store);
  if (!(blessed($agent) && $agent->can('dispatch'))) {
    croak "agent must support dispatch\n";
  }
  return $agent;
}

sub _build_daemon_agent {
  my ($config, $state_store) = @_;
  my $mutable_state = _daemon_mutable_state($config, $state_store);
  return Overnet::Auth::Agent->new(%{$config->agent_args(state => $mutable_state)}, _state_writer_arg($state_store),);
}

sub _daemon_mutable_state {
  my ($config, $state_store) = @_;
  my $mutable_state = $config->mutable_state;
  if ($state_store) {
    my $loaded_state = $state_store->load_state;
    if (defined $loaded_state) {
      $mutable_state = $loaded_state;
    }
  }
  return $mutable_state;
}

sub _state_writer_arg {
  my ($state_store) = @_;
  if (!(ref($state_store))) {
    return;
  }
  return (
    state_writer => sub {
      my ($state) = @_;
      return $state_store->save_state(state => $state);
    },
  );
}

sub run {
  my ($self) = @_;
  my $socket = $self->_listen_socket;
  my $served = 0;

  while (1) {
    if (defined($self->{max_connections})
      && $served >= $self->{max_connections}) {
      last;
    }

    my $client = $socket->accept;
    if (!($client)) {
      croak "accept on auth-agent endpoint failed: $OS_ERROR";
    }

    eval {
      $self->{server}->serve_socket($client);
      1;
    } or do {
      my $error = $EVAL_ERROR || 'unknown auth-agent socket failure';
      close $client
        or croak "close auth-agent client socket failed: $OS_ERROR";
      $self->_teardown_socket;
      croak $error;
    };

    close $client
      or croak "close auth-agent client socket failed: $OS_ERROR";
    $served++;
  }

  $self->_teardown_socket;
  return 1;
}

sub _listen_socket {
  my ($self) = @_;
  if ($self->{listen_socket}) {
    return $self->{listen_socket};
  }

  my $endpoint = $self->{endpoint};
  my $parent   = dirname($endpoint);
  if (!(-d $parent)) {
    make_path($parent);
  }

  if (-e $endpoint) {
    if (!(-S $endpoint)) {
      croak "auth-agent endpoint path already exists and is not a socket\n";
    }
    unlink $endpoint
      or croak "unlink stale auth-agent socket $endpoint failed: $OS_ERROR";
  }

  my $socket;
  if (ref($self->{listen_factory}) eq 'CODE') {
    $socket = $self->{listen_factory}->($endpoint);
  } else {
    $socket = IO::Socket::UNIX->new(
      Type   => SOCK_STREAM,
      Local  => $endpoint,
      Listen => 5,
    );
  }
  if (!($socket)) {
    croak "listen on auth-agent endpoint $endpoint failed: $OS_ERROR";
  }

  if (-S $endpoint) {
    chmod $self->{socket_mode}, $endpoint
      or croak "chmod auth-agent endpoint $endpoint failed: $OS_ERROR";
  }

  $self->{listen_socket} = $socket;
  return $socket;
}

sub _teardown_socket {
  my ($self) = @_;
  my $socket = delete $self->{listen_socket};
  if ($socket) {
    if (ref($socket) && $socket->can('close')) {
      $socket->close
        or croak "close auth-agent listener socket failed\n";
    } else {
      close $socket
        or croak "close auth-agent listener socket failed: $OS_ERROR";
    }
  }

  my $endpoint = $self->{endpoint};
  if (defined($endpoint) && -S $endpoint) {
    unlink $endpoint
      or croak "unlink auth-agent endpoint $endpoint failed: $OS_ERROR";
  }

  return 1;
}

1;

=head1 NAME

Overnet::Auth::Daemon - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Daemon;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 endpoint

Public API entry point.

=head2 run

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
