package Overnet::Auth::Config;

use strictures 2;
use Moo;
use Carp    qw(croak);
use English qw(-no_match_vars);

use JSON ();

our $VERSION = '0.001';

has config => (is => 'ro', reader => '_raw_config');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args   = _constructor_args_hash(@args);
  my $config = exists $args{config} ? $args{config} : {};

  if (!(ref($config) eq 'HASH')) {
    croak "auth config must be an object\n";
  }
  if (exists($config->{daemon}) && ref($config->{daemon}) ne 'HASH') {
    croak "auth config daemon section must be an object\n";
  }
  my $daemon = ref($config->{daemon}) eq 'HASH' ? $config->{daemon} : {};
  if (exists($daemon->{state_file})
    && (ref($daemon->{state_file}) || !length($daemon->{state_file}))) {
    croak "auth config daemon.state_file must be a string\n";
  }
  if (exists($config->{identities})
    && ref($config->{identities}) ne 'ARRAY') {
    croak "auth config identities must be an array\n";
  }
  if (exists($config->{policies})
    && ref($config->{policies}) ne 'ARRAY') {
    croak "auth config policies must be an array\n";
  }
  if (exists($config->{service_pins})
    && ref($config->{service_pins}) ne 'HASH') {
    croak "auth config service_pins must be an object\n";
  }
  if (exists($config->{sessions})
    && ref($config->{sessions}) ne 'ARRAY') {
    croak "auth config sessions must be an array\n";
  }
  if (exists($config->{allow_unattended_autoapprove})
    && !JSON::is_bool($config->{allow_unattended_autoapprove})) {
    croak "auth config allow_unattended_autoapprove must be a boolean\n";
  }

  return {config => _clone($config),};
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub load_file {
  my ($class, %args) = @_;
  my $path = $args{path};

  if (!(defined $path && !ref($path) && length($path))) {
    croak "path is required\n";
  }

  open my $fh, '<', $path
    or croak "open $path failed: $OS_ERROR";
  my $json = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  close $fh
    or croak "close $path failed: $OS_ERROR";

  my $decoded = eval { JSON->new->utf8->decode($json) };
  if (!(defined $decoded)) {
    croak "auth config file $path is not valid JSON: $EVAL_ERROR";
  }
  if (!(ref($decoded) eq 'HASH')) {
    croak "auth config must decode to an object\n";
  }

  return $class->new(config => $decoded);
}

sub endpoint {
  my ($self) = @_;
  my $daemon = $self->{config}{daemon} || {};
  return $daemon->{endpoint};
}

sub socket_mode {
  my ($self) = @_;
  my $daemon = $self->{config}{daemon} || {};
  return $daemon->{socket_mode};
}

sub state_file {
  my ($self) = @_;
  my $daemon = $self->{config}{daemon} || {};
  return $daemon->{state_file};
}

sub agent_args {
  my ($self, %args) = @_;
  my $state = exists($args{state}) ? $args{state} : $self->mutable_state;

  if (!(ref($state) eq 'HASH')) {
    croak "auth mutable state must be an object\n";
  }
  if (exists($state->{policies}) && ref($state->{policies}) ne 'ARRAY') {
    croak "auth mutable state policies must be an array\n";
  }
  if (exists($state->{service_pins})
    && ref($state->{service_pins}) ne 'HASH') {
    croak "auth mutable state service_pins must be an object\n";
  }
  if (exists($state->{sessions}) && ref($state->{sessions}) ne 'ARRAY') {
    croak "auth mutable state sessions must be an array\n";
  }

  return {
    identities                   => $self->identities,
    policies                     => _clone($state->{policies}     || []),
    service_pins                 => _clone($state->{service_pins} || {}),
    sessions                     => _clone($state->{sessions}     || []),
    allow_unattended_autoapprove => $self->{config}{allow_unattended_autoapprove} ? 1 : 0,
  };
}

sub identities {
  my ($self) = @_;
  my $config = $self->{config};
  return _clone($config->{identities} || []);
}

sub mutable_state {
  my ($self) = @_;
  my $config = $self->{config};

  return {
    policies     => _clone($config->{policies}     || []),
    service_pins => _clone($config->{service_pins} || {}),
    sessions     => _clone($config->{sessions}     || []),
  };
}

sub _clone {
  my ($value) = @_;
  if (!(defined $value)) {
    return $value;
  }
  if (!(ref($value))) {
    return $value;
  }

  if (ref($value) eq 'HASH') {
    return {
      map { $_ => _clone($value->{$_}) }
        keys %{$value}
    };
  }

  if (ref($value) eq 'ARRAY') {
    return [map { _clone($_) } @{$value}];
  }

  return "$value";
}

1;

=head1 NAME

Overnet::Auth::Config - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Config;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 load_file

Public API entry point.

=head2 endpoint

Public API entry point.

=head2 socket_mode

Public API entry point.

=head2 state_file

Public API entry point.

=head2 agent_args

Public API entry point.

=head2 identities

Public API entry point.

=head2 mutable_state

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
