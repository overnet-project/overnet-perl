package Overnet::Core::Nostr;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);

use AnyEvent;
use Crypt::PK::ECC;
use Digest::SHA        qw(sha256_hex);
use JSON               ();
use List::Util         qw(any);
use Net::Nostr::Bech32 qw(decode_nsec);
use Net::Nostr::DirectMessage;
use Net::Nostr::Client;
use Net::Nostr::Event;
use Net::Nostr::Filter;
use Net::Nostr::Key;
use Overnet::Core::Nostr::Event;
use Overnet::Core::Nostr::Key;

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;

sub load_key {
  my ($class, %args) = @_;
  if (!(defined $args{privkey} && !ref($args{privkey}) && length($args{privkey}))) {
    croak "privkey is required\n";
  }

  my $input = $args{privkey};
  my $key;

  if ($input =~ /\A[0-9a-f]{64}\z/mxs) {
    $key = _key_from_hex_secret($input);
  } elsif ($input =~ /\Ansec1/imxs) {
    $key = _key_from_hex_secret(decode_nsec(lc $input));
  } elsif ($input =~ /\A-----BEGIN\ /mxs) {
    $key = Net::Nostr::Key->new(privkey => \$input);
  } else {
    $key = Net::Nostr::Key->new(privkey => $input);
  }

  return Overnet::Core::Nostr::Key->new(key => $key);
}

sub generate_key {
  my ($class) = @_;
  my $key = Net::Nostr::Key->new;
  return Overnet::Core::Nostr::Key->new(key => $key);
}

sub event_from_wire {
  my ($class, $input) = @_;
  my $event = eval { Net::Nostr::Event->from_wire($input) };
  if (!($event)) {
    return;
  }
  return Overnet::Core::Nostr::Event->new(event => $event);
}

sub wrap_private_message {
  my ($class, %args) = @_;
  my $sender_key        = _require_key_wrapper($args{sender_key});
  my $payload           = $args{payload};
  my $recipient_pubkeys = $args{recipient_pubkeys};

  if (!(ref($payload) eq 'HASH')) {
    croak "payload must be an object\n";
  }
  if (!(ref($recipient_pubkeys) eq 'ARRAY' && @{$recipient_pubkeys})) {
    croak "recipient_pubkeys must be a non-empty array\n";
  }
  if (any { !defined || ref || !length } @{$recipient_pubkeys}) {
    croak "recipient_pubkeys must contain non-empty strings\n";
  }

  my $rumor = Net::Nostr::DirectMessage->create(
    sender_pubkey => $sender_key->{key}->pubkey_hex,
    content       => $JSON->encode($payload),
    recipients    => [@{$recipient_pubkeys}],
  );
  my ($wrap) = Net::Nostr::DirectMessage->wrap_for_recipients(
    rumor       => $rumor,
    sender_key  => $sender_key->{key},
    skip_sender => $args{skip_sender} ? 1 : 0,
  );

  return {
    transport       => Overnet::Core::Nostr::Event->new(event => $wrap),
    decrypted_rumor => Overnet::Core::Nostr::Event->new(event => $rumor),
  };
}

sub sign_event_hash {
  my ($class, %args) = @_;
  my $key        = _require_key_wrapper($args{key});
  my $event_hash = $args{event};

  if (!(ref($event_hash) eq 'HASH')) {
    croak "event must be an object\n";
  }
  if (!(defined $event_hash->{kind} && !ref($event_hash->{kind}))) {
    croak "event kind is required\n";
  }
  if (!(defined $event_hash->{created_at} && !ref($event_hash->{created_at}))) {
    croak "event created_at is required\n";
  }
  if (!(ref($event_hash->{tags}) eq 'ARRAY')) {
    croak "event tags must be an array\n";
  }
  if (defined($event_hash->{content}) && ref($event_hash->{content})) {
    croak "event content must be a string\n";
  }

  my $expected_pubkey = $key->{key}->pubkey_hex;
  if (defined $event_hash->{pubkey}) {
    if (!(!ref($event_hash->{pubkey}) && $event_hash->{pubkey} eq $expected_pubkey)) {
      croak "event pubkey does not match the signing key\n";
    }
  }

  my $event = $key->{key}->create_event(
    kind       => $event_hash->{kind},
    created_at => $event_hash->{created_at},
    tags       => [@{$event_hash->{tags}}],
    content    => defined $event_hash->{content}
    ? $event_hash->{content}
    : q{},
  );
  return Overnet::Core::Nostr::Event->new(event => $event);
}

sub publish_event {
  my ($class, %args) = @_;
  my $relay_url  = $args{relay_url};
  my $event      = _coerce_signed_event($args{event});
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 5_000;

  if (!(defined $relay_url && !ref($relay_url) && length($relay_url))) {
    croak "relay_url is required\n";
  }
  if (!(defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/mxs)) {
    croak "timeout_ms must be a positive integer\n";
  }

  my $client = Net::Nostr::Client->new;
  my $cv     = AnyEvent->condvar;
  my $done   = 0;
  my $timer  = AnyEvent->timer(
    after => $timeout_ms / 1000,
    cb    => sub {
      if ($done) {
        return;
      }
      $done = 1;
      $cv->send(
        {
          accepted => 0,
          message  => 'publish timed out',
        }
      );
    },
  );

  $client->on(
    ok => sub {
      my ($event_id, $accepted, $message) = @_;
      if ($done) {
        return;
      }
      if (!($event_id eq $event->id)) {
        return;
      }
      $done = 1;
      undef $timer;
      $cv->send(
        {
          accepted => $accepted ? 1 : 0,
          message  => $message,
        }
      );
    }
  );

  $client->connect($relay_url);
  $client->publish($event->{event});
  my $result = $cv->recv;
  $client->disconnect;

  return {%{$result || {}}, event_id => $event->id,};
}

sub query_events {
  my ($class, %args) = @_;
  my $relay_url  = $args{relay_url};
  my $filters    = $args{filters};
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 5_000;

  if (!(defined $relay_url && !ref($relay_url) && length($relay_url))) {
    croak "relay_url is required\n";
  }
  if (!(ref($filters) eq 'ARRAY' && @{$filters})) {
    croak "filters must be a non-empty array\n";
  }
  if (!(defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/mxs)) {
    croak "timeout_ms must be a positive integer\n";
  }

  my @filters = map { ref eq 'Net::Nostr::Filter' ? $_ : Net::Nostr::Filter->new(%{$_}) } @{$filters};

  my $client = Net::Nostr::Client->new;
  my $state  = _query_state(
    relay_url  => $relay_url,
    timeout_ms => $timeout_ms,
  );
  _install_query_handlers($client, $state);

  $client->connect($relay_url);
  $client->subscribe($state->{subscription_id}, @filters);
  my $events = $state->{cv}->recv;
  if ($client->is_connected) {
    $client->close($state->{subscription_id});
  }
  $client->disconnect;

  return [map { $_->to_hash } @{$events || []}];
}

sub _query_state {
  my (%args) = @_;
  my $state = {
    cv              => AnyEvent->condvar,
    done            => 0,
    events          => [],
    seen_ids        => {},
    subscription_id => sha256_hex(join q{:}, time(), rand(), $PROCESS_ID, $args{relay_url}),
  };
  $state->{timer} = AnyEvent->timer(
    after => $args{timeout_ms} / 1000,
    cb    => sub { _finish_query($state); },
  );
  return $state;
}

sub _install_query_handlers {
  my ($client, $state) = @_;
  $client->on(event  => sub { _record_query_event($state, @_); });
  $client->on(eose   => sub { _finish_query_for_subscription($state, @_); });
  $client->on(closed => sub { _finish_query_for_subscription($state, @_); });
  return;
}

sub _record_query_event {
  my ($state, $sub_id, $event) = @_;
  if ($state->{done} || !($sub_id eq $state->{subscription_id})) {
    return;
  }
  if ($state->{seen_ids}{$event->id}++) {
    return;
  }
  push @{$state->{events}}, $event;
  return;
}

sub _finish_query_for_subscription {
  my ($state, $sub_id) = @_;
  if ($state->{done} || !($sub_id eq $state->{subscription_id})) {
    return;
  }
  _finish_query($state);
  return;
}

sub _finish_query {
  my ($state) = @_;
  if ($state->{done}) {
    return;
  }
  $state->{done} = 1;
  undef $state->{timer};
  $state->{cv}->send([@{$state->{events}}]);
  return;
}

sub _require_key_wrapper {
  my ($key) = @_;
  if (!(ref($key) && ref($key) eq 'Overnet::Core::Nostr::Key')) {
    croak "key must be an Overnet::Core::Nostr::Key instance\n";
  }
  return $key;
}

sub _coerce_signed_event {
  my ($input) = @_;
  if (ref($input) && ref($input) eq 'Overnet::Core::Nostr::Event') {
    return $input;
  }
  if (!(ref($input) eq 'HASH')) {
    croak "event must be an object\n";
  }

  my $event = Net::Nostr::Event->from_wire($input);
  return Overnet::Core::Nostr::Event->new(event => $event);
}

sub _key_from_hex_secret {
  my ($hex) = @_;
  my $pk = Crypt::PK::ECC->new;
  $pk->import_key_raw(pack('H*', $hex), 'secp256k1');

  my $der = $pk->export_key_der('private');
  return Net::Nostr::Key->new(privkey => \$der);
}

1;

=head1 NAME

Overnet::Core::Nostr - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Core::Nostr;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 load_key

Public API entry point.

=head2 generate_key

Public API entry point.

=head2 event_from_wire

Public API entry point.

=head2 wrap_private_message

Public API entry point.

=head2 sign_event_hash

Public API entry point.

=head2 publish_event

Public API entry point.

=head2 query_events

Public API entry point.

=head2 pubkey_hex

Public API entry point.

=head2 create_event_hash

Public API entry point.

=head2 save_privkey

Public API entry point.

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

See the project license.

=cut
