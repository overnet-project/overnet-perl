package Overnet::Auth::Backend;

use strictures 2;
use Moo;
use Carp qw(croak);

our $VERSION = '0.001';

no Moo;

sub backend_type {
  my ($self) = @_;
  croak "backend_type must be implemented by " . ref($self) . "\n";
}

sub load_signing_key {
  my ($self) = @_;
  croak "load_signing_key must be implemented by " . ref($self) . "\n";
}

1;

=head1 NAME

Overnet::Auth::Backend - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Backend;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 backend_type

Public API entry point.

=head2 load_signing_key

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
