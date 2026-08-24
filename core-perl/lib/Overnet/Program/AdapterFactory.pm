package Overnet::Program::AdapterFactory;

use strictures 2;
use Moo;
use Carp    qw(croak);
use English qw(-no_match_vars);

our $VERSION = '0.001';

no Moo;

sub build {
  my ($self, %args) = @_;

  my $definition = $args{definition};
  if (!(defined $definition && ref($definition) eq 'HASH')) {
    croak "definition is required\n";
  }

  my $kind = $definition->{kind} || 'object';

  if ($kind eq 'object') {
    my $adapter = $definition->{adapter};
    if (!(defined $adapter && ref($adapter))) {
      croak "definition.adapter is required for object adapters\n";
    }
    return $adapter;
  }

  if ($kind eq 'class') {
    my $class            = $definition->{class};
    my $constructor_args = $definition->{constructor_args} || {};
    my $lib_dirs         = $definition->{lib_dirs}         || [];

    if (!(defined $class && !ref($class) && length($class))) {
      croak "definition.class is required for class adapters\n";
    }
    if (ref($constructor_args) ne 'HASH') {
      croak "definition.constructor_args must be an object\n";
    }
    if (ref($lib_dirs) ne 'ARRAY') {
      croak "definition.lib_dirs must be an array\n";
    }

    if (!($class->can('new'))) {
      local @INC = (@{$lib_dirs}, @INC);
      eval {
        (my $path = "$class.pm") =~ s{::}{/}gmxs;
        require $path;
        1;
      }
        or croak "Unable to load adapter class $class: $EVAL_ERROR";
    }

    my $adapter = $class->new(%{$constructor_args});
    if (!(defined $adapter && ref($adapter))) {
      croak "Adapter class $class did not return an object from new()\n";
    }

    return $adapter;
  }

  croak "Unsupported adapter definition kind: $kind\n";
}

1;

=head1 NAME

Overnet::Program::AdapterFactory - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::AdapterFactory;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 build

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
