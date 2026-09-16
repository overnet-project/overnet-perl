package Overnet::Relay::Connection;

use strictures 2;
use Moo;
use Carp                qw(croak);
use Scalar::Util        qw(weaken);
use JSON                ();
use Overnet::Core::JSON ();
use Overnet::Core::Nostr::Event;

our $VERSION = '0.001';
has connection         => (is => 'ro', required => 1, handles => [qw(close)]);
has max_message_length => (is => 'ro');

no Moo;

sub on {
  my ($self, $event, $callback) = @_;
  my $weak = $self;
  weaken $weak;
  return $self->connection->on(
    $event => sub {
      my (undef, @args) = @_;
      my $wrapper = $weak or return;
      if ($event eq 'each_message') {
        my $raw = $args[0]->body;
        my $ok  = (!defined $wrapper->max_message_length || length($raw) <= $wrapper->max_message_length)
          && eval {
          my $decoded = Overnet::Core::JSON::decode_json($raw);
          croak 'invalid message' if ref($decoded) ne 'ARRAY' || !@{$decoded};
          if ($decoded->[0] eq 'EVENT' || $decoded->[0] eq 'AUTH') {
            Overnet::Core::Nostr::Event->assert_wire_types($decoded->[1]);
          }
          1;
          };
        if (!$ok) {
          $wrapper->send(JSON::encode_json(['NOTICE', 'invalid: malformed or oversized JSON message']));
          return;
        }
      }
      return $callback->($wrapper, @args);
    }
  );
}

sub send {    ## no critic (Subroutines::ProhibitBuiltinHomonyms) -- Implements the inherited connection interface.
  my ($self, $wire) = @_;
  my $message  = Overnet::Core::JSON::decode_json($wire);
  my $outcomes = join q{|},
    qw(accepted invalid unauthorized payment_required policy_denied not_found unsupported unavailable);
  if ($message->[0] eq 'OK' || $message->[0] eq 'CLOSED') {
    my $index = $message->[0] eq 'OK' ? 3 : 2;
    my $text  = $message->[$index] // q{};
    if ($text !~ /\A(?:$outcomes):/mxs) {
      my $code = $message->[0] eq 'OK' && $message->[2] ? 'accepted' : 'invalid';
      $message->[$index] = "$code: $text";
      $wire = JSON::encode_json($message);
    }
  }
  return $self->connection->send($wire);
}

1;

=head1 NAME

Overnet::Relay::Connection - Strict JSON boundary for the Nostr relay transport

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $connection = Overnet::Relay::Connection->new(connection => $websocket);

=head1 DESCRIPTION

Validates original WebSocket JSON before the underlying Nostr parser can
discard duplicate keys. Adapts inherited OK and CLOSED messages to Overnet
outcome prefixes without changing signed event content.

=head1 SUBROUTINES/METHODS

=head2 on

Registers a callback, checking incoming message size and JSON before delivery.

=head2 send

Sends a message with an Overnet outcome prefix where required.

=head2 close

Closes the underlying connection.

=head1 DIAGNOSTICS

Invalid frames receive an invalid NOTICE and are not delivered to the parser.

=head1 CONFIGURATION AND ENVIRONMENT

C<connection> is the underlying WebSocket connection. C<max_message_length>
optionally limits incoming bytes.

=head1 DEPENDENCIES

Moo, JSON, Scalar::Util and Overnet::Core::JSON.

=head1 INCOMPATIBILITIES

Duplicate JSON member names are rejected.

=head1 BUGS AND LIMITATIONS

This wrapper implements only the connection methods used by the relay.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the repository LICENSE file.

=cut
