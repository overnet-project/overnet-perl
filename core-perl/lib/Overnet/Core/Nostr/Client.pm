package Overnet::Core::Nostr::Client;

use strictures 2;
use parent 'Net::Nostr::Client';
use Overnet::Core::Nostr::Connection;

our $VERSION = '0.001';

sub _setup_handlers {
  my ($self) = @_;
  $self->_conn(Overnet::Core::Nostr::Connection->new(connection => $self->_conn));
  return $self->SUPER::_setup_handlers;
}

1;

=head1 NAME

Overnet::Core::Nostr::Client - Nostr client with strict Overnet JSON ingress

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $client = Overnet::Core::Nostr::Client->new;

=head1 DESCRIPTION

Uses the existing Nostr client for transport and signature verification. Before
its parser can discard duplicate members or coerce scalar types, checks original
relay messages with the shared strict JSON decoder and event type validator.
Rejects malformed or larger-than-one-MiB incoming messages. Signed content is
never rewritten. The inherited client API is unchanged.

=head1 SUBROUTINES/METHODS

The public API is inherited from L<Net::Nostr::Client>.

=head1 DIAGNOSTICS

Malformed incoming messages are discarded. Callers must bound operation lifetime
and must not interpret missing evidence as proof of authority or absence.

=head1 CONFIGURATION AND ENVIRONMENT

Transport configuration is inherited from L<Net::Nostr::Client>.

=head1 DEPENDENCIES

Net::Nostr::Client, Scalar::Util and the Overnet core validators.

=head1 INCOMPATIBILITIES

Duplicate JSON members and coerced event field types are rejected.

=head1 BUGS AND LIMITATIONS

This is a transport boundary, not application-profile authorization.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the repository LICENSE file.

=cut
