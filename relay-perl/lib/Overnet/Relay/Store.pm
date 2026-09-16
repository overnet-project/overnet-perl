package Overnet::Relay::Store;

use strictures 2;
use parent 'Net::Nostr::RelayStore';
use JSON ();

our $VERSION = '0.001';

sub store {
  my ($self, $event, $acceptance) = @_;
  my $stored = $self->SUPER::store($event);
  if ($stored && $self->get_by_id($event->id) && defined $acceptance) {
    $self->{_accepted_at}{$event->id} = $acceptance;
  }
  return $stored;
}

sub acceptance_for {
  my ($self, $id) = @_;
  return if !exists $self->{_accepted_at}{$id};
  return {event_id => $id, accepted_at => $self->{_accepted_at}{$id}};
}

sub delete_by_id {
  my ($self, $id) = @_;
  my $event = $self->SUPER::delete_by_id($id);
  delete $self->{_accepted_at}{$id};
  if ($event) {
    my %tags = map { @{$_} >= 2 ? ($_->[0] => $_->[1]) : () } @{$event->tags};
    if ($event->kind == 37_800) {
      my $key = $self->object_key($tags{overnet_ot}, $tags{overnet_oid}, $event->pubkey);
      my $old = $self->{_discarded_states}{$key};
      if (!$old
        || $event->created_at > $old->{created_at}
        || ($event->created_at == $old->{created_at} && $id lt $old->{id})) {
        $self->{_discarded_states}{$key} = {id => $id, created_at => $event->created_at};
      }
    } elsif ($event->kind == 7801 && defined $tags{e}) {
      $self->{_discarded_removals}{$tags{e}} = 1;
    }
  }
  return $event;
}

sub object_key {
  my ($self, @parts) = @_;
  return JSON::encode_json(\@parts);
}

sub discarded_state {
  my ($self, @parts) = @_;
  return $self->{_discarded_states}{$self->object_key(@parts)};
}

sub discarded_removal {
  my ($self, $id) = @_;
  return $self->{_discarded_removals}{$id};
}

sub clear {
  my ($self) = @_;
  $self->SUPER::clear;
  delete @{$self}{qw(_accepted_at _discarded_states _discarded_removals)};
  return 1;
}

1;

=head1 NAME

Overnet::Relay::Store - Relay storage with local admission and retention evidence

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $store = Overnet::Relay::Store->new;
  $store->store($event, $accepted_at);

=head1 DESCRIPTION

Extends the Nostr memory store with trusted local acceptance times and compact
markers for discarded state and removals. Markers prevent object reads from
resurrecting older state when evidence is missing. The file store persists them.

=head1 SUBROUTINES/METHODS

=head2 store

Stores an event. The optional second argument is a trusted local admission time
supplied only after validation, never a timestamp received from a peer.

=head2 acceptance_for

Returns local acceptance evidence for an exact retained event ID, if available.

=head2 delete_by_id

Deletes an event while retaining a marker when its absence affects object reads.

=head2 object_key

Encodes an exact object type, ID and author tuple without delimiter ambiguity.

=head2 discarded_state

Returns the newest discarded state marker for an object tuple.

=head2 discarded_removal

Reports whether a removal of a target ID has been discarded.

=head2 clear

Clears all events and local evidence.

=head1 DIAGNOSTICS

Uses the underlying store's exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

Accepts the underlying store's maximum event count.

=head1 DEPENDENCIES

Net::Nostr::RelayStore and JSON.

=head1 INCOMPATIBILITIES

No wire protocol changes are introduced by local evidence.

=head1 BUGS AND LIMITATIONS

In-memory evidence is lost when the store is destroyed. Use the file store for
restart persistence. Discard markers are intentionally retained until a full
store reset; retention may require more space than the remaining event bodies.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the repository LICENSE file.

=cut
