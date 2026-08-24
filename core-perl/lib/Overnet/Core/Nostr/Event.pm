package Overnet::Core::Nostr::Event;

use strictures 2;
use Moo;

our $VERSION = '0.001';

has event => (is => 'ro');

no Moo;

sub id {
  my ($self) = @_;
  return $self->{event}->id;
}

sub kind {
  my ($self) = @_;
  return $self->{event}->kind;
}

sub pubkey {
  my ($self) = @_;
  return $self->{event}->pubkey;
}

sub created_at {
  my ($self) = @_;
  return $self->{event}->created_at;
}

sub content {
  my ($self) = @_;
  return $self->{event}->content;
}

sub tags {
  my ($self) = @_;
  return $self->{event}->tags;
}

sub to_hash {
  my ($self) = @_;
  return $self->{event}->to_hash;
}

sub validate {
  my ($self) = @_;
  return $self->{event}->validate;
}

1;

=head1 NAME

Overnet::Core::Nostr::Event - Overnet Nostr event wrapper

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Core::Nostr::Event;

=head1 DESCRIPTION

This module wraps a C<Net::Nostr::Event> for the Overnet core API.

=head1 SUBROUTINES/METHODS

=head2 id

Public API entry point.

=head2 kind

Public API entry point.

=head2 pubkey

Public API entry point.

=head2 created_at

Public API entry point.

=head2 content

Public API entry point.

=head2 tags

Public API entry point.

=head2 to_hash

Public API entry point.

=head2 validate

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
