package Overnet::Core::Nostr::Connection;

use strictures 2;
use Moo;
use Carp                qw(croak);
use Scalar::Util        qw(weaken);
use Overnet::Core::JSON ();
use Overnet::Core::Nostr::Event;

our $VERSION = '0.001';
has connection => (is => 'ro', required => 1, handles => [qw(send close)]);
no Moo;

sub on {
  my ($self, $name, $callback) = @_;
  my $weak = $self;
  weaken $weak;
  return $self->connection->on(
    $name => sub {
      my (undef, @args) = @_;
      my $wrapper = $weak or return;
      if ($name eq 'each_message') {
        my $ok = eval { _validate_message($args[0]->body); 1; };
        return if !$ok;
      }
      return $callback->($wrapper, @args);
    }
  );
}

sub _validate_message {
  my ($raw) = @_;
  croak 'oversized relay message' if length($raw) > 1_048_576;
  my $message = Overnet::Core::JSON::decode_json($raw);
  croak 'invalid relay message' if ref($message) ne 'ARRAY' || !@{$message};
  if ($message->[0] eq 'EVENT') {
    Overnet::Core::Nostr::Event->assert_wire_types($message->[2]);
  }
  return;
}

1;

=head1 NAME

Overnet::Core::Nostr::Connection - Strict relay message boundary

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $connection = Overnet::Core::Nostr::Connection->new(connection => $websocket);

=head1 DESCRIPTION

Checks raw relay JSON and signed-event field types before the inherited Nostr
client parser. Used internally by Overnet::Core::Nostr::Client.

=head1 SUBROUTINES/METHODS

=head2 on

Registers a callback. Malformed or oversized message frames are discarded.

=head2 send

=head2 close

Delegate unchanged to the underlying WebSocket connection.

=head1 DIAGNOSTICS

Invalid messages are discarded without logging their contents.

=head1 CONFIGURATION AND ENVIRONMENT

Incoming messages are limited to one MiB.

=head1 DEPENDENCIES

Moo, Scalar::Util, and the Overnet core validators.

=head1 INCOMPATIBILITIES

Malformed JSON or coerced event fields are not accepted.

=head1 BUGS AND LIMITATIONS

Cryptographic validation remains the Nostr client's responsibility.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the repository LICENSE file.

=cut
