package Overnet::Core::Nostr::Event;

use strictures 2;
use Moo;
use B      ();
use Encode qw(encode FB_CROAK LEAVE_SRC);

our $VERSION = '0.001';

has event => (is => 'ro');

no Moo;

sub assert_wire_types {
  my ($class, $input) = @_;
  die "Nostr event must be an object\n" if ref($input) ne 'HASH';
  for my $field (qw(kind created_at)) {
    die "$field must be an integer\n" if !_wire_integer($input->{$field});
  }
  for my $field (qw(id pubkey content sig)) {
    my $value = $input->{$field};
    die "$field must be a string\n"
      if !defined $value
      || ref $value
      || !(B::svref_2object(\$value)->FLAGS & B::SVp_POK());
    encode('utf8', $value, FB_CROAK | LEAVE_SRC);
  }
  die "tags must be an array\n" if ref($input->{tags}) ne 'ARRAY';
  for my $tag (@{$input->{tags}}) {
    die "tags must contain arrays\n" if ref($tag) ne 'ARRAY';
    for my $value (@{$tag}) {
      die "tag values must be strings\n"
        if !defined $value
        || ref $value
        || !(B::svref_2object(\$value)->FLAGS & B::SVp_POK());
      encode('utf8', $value, FB_CROAK | LEAVE_SRC);
    }
  }
  return;
}

sub _wire_integer {
  my ($value) = @_;
  return
       defined $value
    && !ref $value
    && (B::svref_2object(\$value)->FLAGS & (B::SVp_IOK() | B::SVp_NOK()))
    && $value =~ /\A[0-9]+\z/mxs;
}

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

=head2 assert_wire_types

Checks scalar types and Unicode in a signed Nostr wire object before coercion.
Throws for malformed fields; cryptographic verification remains separate.

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
