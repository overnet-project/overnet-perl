package Overnet::Program::AdapterRegistry;

use strictures 2;
use Moo;
use Carp qw(croak);
use Overnet::Program::AdapterFactory;

our $VERSION = '0.001';

has adapters        => (is => 'rw', accessor => '_adapters');
has adapter_factory => (is => 'ro', reader   => '_adapter_factory');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args            = _constructor_args_hash(@args);
  my $adapter_factory = $args{adapter_factory} || Overnet::Program::AdapterFactory->new;

  if (!(ref($adapter_factory) && $adapter_factory->isa('Overnet::Program::AdapterFactory'))) {
    croak "adapter_factory must be an Overnet::Program::AdapterFactory instance\n";
  }

  return {
    adapters        => {},
    adapter_factory => $adapter_factory,
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub register {
  my ($self, %args) = @_;

  my $adapter_id = $args{adapter_id};
  my $adapter    = $args{adapter};

  if (!(defined $adapter_id && !ref($adapter_id) && length($adapter_id))) {
    croak "adapter_id is required\n";
  }
  if (!(defined $adapter && ref($adapter))) {
    croak "adapter is required\n";
  }

  $self->{adapters}{$adapter_id} = $adapter;
  return 1;
}

sub register_definition {
  my ($self, %args) = @_;

  my $adapter_id = $args{adapter_id};
  my $definition = $args{definition};

  if (!(defined $adapter_id && !ref($adapter_id) && length($adapter_id))) {
    croak "adapter_id is required\n";
  }
  if (!(defined $definition && ref($definition) eq 'HASH')) {
    croak "definition is required\n";
  }

  $self->{adapters}{$adapter_id} = $definition;
  return 1;
}

sub get {
  my ($self, $adapter_id) = @_;
  if (!(defined $adapter_id)) {
    return;
  }
  return $self->{adapters}{$adapter_id};
}

sub build {
  my ($self, $adapter_id) = @_;
  my $entry = $self->get($adapter_id);
  if (!(defined $entry)) {
    return;
  }

  if (ref($entry) eq 'HASH' && exists $entry->{kind}) {
    return $self->{adapter_factory}->build(definition => $entry);
  }

  return $entry;
}

sub has {
  my ($self, $adapter_id) = @_;
  return defined $self->get($adapter_id) ? 1 : 0;
}

sub adapter_ids {
  my ($self) = @_;
  return [sort keys %{$self->{adapters}}];
}

1;

=head1 NAME

Overnet::Program::AdapterRegistry - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::AdapterRegistry;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 register

Public API entry point.

=head2 register_definition

Public API entry point.

=head2 get

Public API entry point.

=head2 build

Public API entry point.

=head2 has

Public API entry point.

=head2 adapter_ids

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
