package Overnet::Core::Nostr::Key;

use strictures 2;
use Moo;

our $VERSION = '0.001';

has key => (is => 'ro');

no Moo;

sub pubkey_hex {
  my ($self) = @_;
  return $self->{key}->pubkey_hex;
}

sub create_event_hash {
  my ($self, %args) = @_;
  my $event = $self->{key}->create_event(
    kind       => $args{kind},
    created_at => $args{created_at},
    tags       => $args{tags},
    content    => $args{content},
  );
  return $event->to_hash;
}

sub sign_event_hash {
  my ($self, %args) = @_;
  require Overnet::Core::Nostr;
  return Overnet::Core::Nostr->sign_event_hash(
    key   => $self,
    event => $args{event},
  )->to_hash;
}

sub save_privkey {
  my ($self, $path) = @_;
  return $self->{key}->save_privkey($path);
}

1;

=head1 NAME

Overnet::Core::Nostr::Key - Overnet Nostr key wrapper

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Core::Nostr::Key;

=head1 DESCRIPTION

This module wraps a C<Net::Nostr::Key> for the Overnet core API.

=head1 SUBROUTINES/METHODS

=head2 pubkey_hex

Public API entry point.

=head2 create_event_hash

Public API entry point.

=head2 sign_event_hash

Public API entry point.

=head2 save_privkey

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

See the repository LICENSE file.

=cut
