package Overnet::CommandBus;

use strictures 2;
use Moo;

use Carp    qw(croak);
use English qw(-no_match_vars);

our $VERSION = '0.001';

has handlers   => (is => 'ro');
has middleware => (is => 'ro');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $handlers = defined $args{handlers} ? $args{handlers} : {};
  if (ref($handlers) ne 'HASH') {
    croak "handlers must be a hash reference\n";
  }
  for my $method (sort keys %{$handlers}) {
    if (ref($handlers->{$method}) ne 'CODE') {
      croak "handler for method $method must be a code reference\n";
    }
  }

  my $middleware = defined $args{middleware} ? $args{middleware} : [];
  if (ref($middleware) ne 'ARRAY') {
    croak "middleware must be an array reference\n";
  }
  for my $entry (@{$middleware}) {
    if (ref($entry) ne 'CODE') {
      croak "middleware entries must be code references\n";
    }
  }

  return {
    handlers   => {%{$handlers}},
    middleware => [@{$middleware}],
  };
}

sub register {
  my ($self, $method, $handler) = @_;

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  if (ref($handler) ne 'CODE') {
    croak "handler must be a code reference\n";
  }
  if (exists $self->handlers->{$method}) {
    croak "handler already registered for method: $method\n";
  }

  $self->handlers->{$method} = $handler;
  return $self;
}

sub add_middleware {
  my ($self, $middleware) = @_;

  if (ref($middleware) ne 'CODE') {
    croak "middleware must be a code reference\n";
  }

  push @{$self->middleware}, $middleware;
  return $self;
}

sub has_handler {
  my ($self, $method) = @_;
  return (defined $method && !ref($method) && exists $self->handlers->{$method}) ? 1 : 0;
}

sub dispatch {
  my ($self, $method, $params, $context) = @_;

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  if (!defined $params) {
    $params = {};
  }
  if (ref($params) ne 'HASH') {
    croak "params must be a hash reference\n";
  }
  if (!defined $context) {
    $context = {};
  }
  if (ref($context) ne 'HASH') {
    croak "context must be a hash reference\n";
  }

  my $handler = $self->handlers->{$method};
  if (!$handler) {
    croak "no handler registered for method: $method\n";
  }

  my $next = sub { $handler->($method, $params, $context) };
  for my $entry (reverse @{$self->middleware}) {
    my $inner = $next;
    $next = sub { $entry->($method, $params, $context, $inner) };
  }

  return $next->();
}

sub normalize_error {
  my ($class, $error, %args) = @_;

  my $code = $args{code};
  if (!(defined $code && !ref($code) && length($code))) {
    croak "code is required\n";
  }

  if (ref($error) eq 'HASH' && defined $error->{code} && defined $error->{message}) {
    return $error;
  }

  my $message = $error;
  if (ref($message)) {
    $message = "$message";
  } else {
    chomp $message;
  }

  return {
    code    => $code,
    message => $message,
  };
}

sub error_normalizer {
  my ($class, %args) = @_;

  my $code = $args{code};
  if (!(defined $code && !ref($code) && length($code))) {
    croak "code is required\n";
  }

  return sub {
    my ($method, $params, $context, $next) = @_;

    my $result;
    my $error;
    eval {
      $result = $next->();
      1;
    } or $error = $EVAL_ERROR;

    if ($error) {
      CORE::die $class->normalize_error($error, code => $code);
    }

    return $result;
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

1;

=head1 NAME

Overnet::CommandBus - command dispatch with a middleware pipeline

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::CommandBus;

  my $bus = Overnet::CommandBus->new;
  $bus->register('storage.get', sub {
    my ($method, $params, $context) = @_;
    ...
  });
  $bus->add_middleware(sub {
    my ($method, $params, $context, $next) = @_;
    # before dispatch
    my $result = $next->();
    # after dispatch
    return $result;
  });

  my $result = $bus->dispatch('storage.get', {key => 'k'}, {session_id => 's-1'});

=head1 DESCRIPTION

This module is the execution bus behind the dispatch surfaces that this
distribution owns: the program service layer and the auth agent. A bus
instance maps method names to handler code references and routes every
C<dispatch> call through its middleware pipeline, so cross-cutting concerns
such as permission checks, logging, and error normalization are implemented
once as middleware instead of being duplicated at each dispatch site.

This class is internal to the core distribution. Systems outside core
interact with these dispatch surfaces through the specified protocol
envelopes and error codes; they never construct or observe the bus. Do not
depend on this module from other distributions.

Middleware runs in registration order, with the first added middleware
outermost. Each middleware receives the dispatched method, params, context,
and a C<$next> code reference; calling C<$next-E<gt>()> continues the chain,
and returning without calling it short-circuits dispatch. Errors thrown by
handlers propagate unchanged unless middleware chooses to intercept them.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 handlers

Public API entry point.

=head2 middleware

Public API entry point.

=head2 register

Public API entry point.

=head2 add_middleware

Public API entry point.

=head2 has_handler

Public API entry point.

=head2 dispatch

Public API entry point.

=head2 normalize_error

Public API entry point.

=head2 error_normalizer

Public API entry point.

=head1 DIAGNOSTICS

Errors are raised via C<croak> with messages describing the rejected input.

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
