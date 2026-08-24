package Overnet::Program::Subscription;

use strictures 2;
use Moo;
use Carp qw(croak);
use Net::Nostr::Event;

our $VERSION = '0.001';

has session_id      => (is => 'ro');
has subscription_id => (is => 'ro');
has query           => (is => 'ro', reader => '_query');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $session_id      = $args{session_id};
  my $subscription_id = $args{subscription_id};
  my $query           = $args{query} || {};

  if (!(defined $session_id && !ref($session_id) && length($session_id))) {
    croak "session_id is required\n";
  }
  if (!(defined $subscription_id && !ref($subscription_id) && length($subscription_id))) {
    croak "subscription_id is required\n";
  }
  if (!(ref($query) eq 'HASH')) {
    croak "query must be an object\n";
  }

  return {
    session_id      => $session_id,
    subscription_id => $subscription_id,
    query           => {%{$query}},
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub query {
  my ($self) = @_;
  return {%{$self->{query}}};
}

sub matches {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $query     = $self->{query};

  if (!(defined $item_type && !ref($item_type))) {
    return 0;
  }
  if ( $item_type ne 'event'
    && $item_type ne 'state'
    && $item_type ne 'private_message'
    && keys %{$query}) {
    return 0;
  }

  if (!(keys %{$query})) {
    return 1;
  }

  if ($item_type eq 'private_message') {
    return _matches_private_message($query, $args{data});
  }

  return _matches_event($query, $args{event});
}

sub _matches_private_message {
  my ($query, $data) = @_;

  if (!(ref($data) eq 'HASH')) {
    return 0;
  }

  if (exists $query->{kind} && !(_private_message_kind_matches($query, $data))) {
    return 0;
  }

  for my $field ([overnet_et => 'private_type'], [overnet_ot => 'object_type'], [overnet_oid => 'object_id'],) {
    if (!(_query_field_matches($query, $data, $field->[0], $field->[1]))) {
      return 0;
    }
  }

  return 1;
}

sub _private_message_kind_matches {
  my ($query, $data) = @_;
  my $kind =
    ref($data->{transport}) eq 'HASH'
    ? $data->{transport}{kind}
    : undef;
  return defined $kind && !ref($kind) && $kind == $query->{kind} ? 1 : 0;
}

sub _query_field_matches {
  my ($query, $data, $query_field, $data_field) = @_;
  if (!(exists $query->{$query_field})) {
    return 1;
  }
  return (($data->{$data_field} || q{}) eq $query->{$query_field}) ? 1 : 0;
}

sub _matches_event {
  my ($query, $event) = @_;

  if (!(defined $event && ref($event) && $event->isa('Net::Nostr::Event'))) {
    return 0;
  }

  if (exists $query->{kind} && $event->kind != $query->{kind}) {
    return 0;
  }

  my %tag_values = _first_tag_values($event->tags);
  for my $field (qw(overnet_et overnet_ot overnet_oid)) {
    if (!(exists $query->{$field})) {
      next;
    }
    if (!(defined $tag_values{$field} && $tag_values{$field} eq $query->{$field})) {
      return 0;
    }
  }

  return 1;
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    if (exists $values{$tag->[0]}) {
      next;
    }
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

1;

=head1 NAME

Overnet::Program::Subscription - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Subscription;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 session_id

Public API entry point.

=head2 subscription_id

Public API entry point.

=head2 query

Public API entry point.

=head2 matches

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
