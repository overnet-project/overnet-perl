package Overnet::Relay::Deploy;

use strictures 2;
use parent 'Overnet::Relay';

our $VERSION = '0.001';

1;

=head1 NAME

Overnet::Relay::Deploy - Deployment policy wrapper for the Overnet relay

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $relay = Overnet::Relay::Deploy->new(service_policies => \%policies);

=head1 DESCRIPTION

Compatibility subclass of L<Overnet::Relay>. Service policies are enforced
by the base relay on all publication, query, sync and object-read paths.

=head1 SUBROUTINES/METHODS

This package uses the public constructor and API inherited from
L<Overnet::Relay>.

=head1 DIAGNOSTICS

Denied services return protocol-level policy errors.

=head1 CONFIGURATION AND ENVIRONMENT

Service policies are supplied by the relay configuration.

=head1 DEPENDENCIES

Requires L<Overnet::Relay>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/overnet-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
