package Overnet::Authority::HostedChannel::Transport;

use strictures 2;
use parent 'Net::Nostr::Relay';
use JSON ();
use Net::Nostr::Message;
use Overnet::Core::Nostr::Event;
use Overnet::Relay::Connection;

our $VERSION = '0.001';

sub _on_connection {
  my ($self, $connection, $peer) = @_;
  return $self->SUPER::_on_connection(
    Overnet::Relay::Connection->new(
      connection         => $connection,
      max_message_length => $self->max_message_length
    ),
    $peer
  );
}

sub _handle_event {
  my ($self, $connection_id, $event) = @_;
  my $error =
    eval { Overnet::Core::Nostr::Event->assert_wire_types($event->to_hash); 1 }
    ? $self->_validate_event($event)
    : 'invalid: malformed event';
  my $authoritative =
    Overnet::Authority::HostedChannel::Relay::is_authoritative_kind($event->kind, $self->{authority_grant_kind});
  if (!$error && !$authoritative) {
    my $before = $self->store->get_by_id($event->id);
    $self->SUPER::_handle_event($connection_id, $event);
    if (!$before && $self->store->get_by_id($event->id)) {
      $self->{authority_on_stored}->($event);
    }
    return;
  }

  # Authority evidence is retained by ID, including concurrent grants and
  # metadata history. Nostr's replaceable slots cannot be the grant database.
  my $duplicate = !$error && $self->store->get_by_id($event->id);
  my $now       = $self->{authority_clock}->();
  local $self->{authority_admission_time} = $now;    ## no critic (Variables::ProhibitLocalVars) -- Scope the receiver clock to this admission.
  $error ||= $self->_authority_rejection($connection_id, $event, $duplicate, $now);
  if (!$error && !$duplicate) {
    $self->store->store($event, $now);
    $self->broadcast($event);
  }
  $self->_connections->{$connection_id}->send(
    Net::Nostr::Message->new(
      type     => 'OK',
      event_id => $event->id,
      accepted => $error ? 0 : 1,
      message  => $error || ($duplicate ? 'accepted: duplicate' : 'accepted: stored'),
    )->serialize
  );
  return;
}

sub _authority_rejection {
  my ($self, $connection_id, $event, $duplicate, $now) = @_;
  if (!defined($now) || ref($now) || $now !~ /\A[0-9]+\z/mxs) {
    return 'unavailable: current time is unavailable';
  }
  if (!$duplicate
    && $event->is_protected
    && !((($self->_authenticated || {})->{$connection_id} || {})->{$event->pubkey})) {
    return 'unauthorized: protected event requires its authenticated author';
  }
  if (!$duplicate && $event->is_expired) {
    return 'invalid: event has expired';
  }
  if (!$duplicate) {
    my ($accepted, $reason) = $self->on_event->($event);
    if (!$accepted) {
      return $reason || 'unauthorized: authority rejected event';
    }
  }
  return;
}

1;

=head1 NAME

Overnet::Authority::HostedChannel::Transport - Authority admission and durable grant retention

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  # Created internally by Overnet::Authority::HostedChannel::Relay.

=head1 DESCRIPTION

Internal transport used by C<build_authoritative_relay>. Retains accepted
session grants and authoritative history by ID, records local acceptance time,
and suppresses duplicate side effects. Uses the normal Nostr path for other
traffic. Strict JSON checking precedes the Nostr parser.

=head1 SUBROUTINES/METHODS

=head2 new

Configured by the authority relay builder; applications use that builder.

=head1 DIAGNOSTICS

Returns Nostr publication results; persistence failures raise exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

The builder supplies the grant kind, trusted local clock and retention hook.

=head1 DEPENDENCIES

Net::Nostr::Relay and the Overnet core and relay modules.

=head1 INCOMPATIBILITIES

Concurrent accepted grants are retained instead of replacing one another.

=head1 BUGS AND LIMITATIONS

Historical authority evidence is intentionally retained. Operators must retain
this evidence when backing up or migrating the authority store.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
