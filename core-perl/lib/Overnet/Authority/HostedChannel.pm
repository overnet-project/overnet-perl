package Overnet::Authority::HostedChannel;

use strictures 2;
use Scalar::Util qw(blessed);
use Encode       qw(encode decode FB_CROAK LEAVE_SRC);

use Net::Nostr::Group ();

our $VERSION = '0.001';

sub irc_casefold {
  my ($value) = @_;
  if (!(defined $value && !ref($value))) {
    return;
  }

  my $folded = $value;
  $folded =~ tr/A-Z[]\\^/a-z{}|~/;
  return $folded;
}

sub ordered_events {
  my ($events, %options) = @_;
  my (%seen, %timestamps);
  for my $event (@{$events}) {
    my $item = _order_record($event, \%options) or next;
    next if $seen{$item->{id}}++;
    push @{$timestamps{$item->{created_at}}}, $item;
  }
  my @ordered;
  for my $timestamp (sort { $a <=> $b } keys %timestamps) {
    push @ordered, _order_at_timestamp($timestamps{$timestamp});
  }
  return \@ordered;
}

sub _event_data {
  my ($event) = @_;
  return $event          if ref($event) eq 'HASH';
  return $event->to_hash if blessed($event) && $event->can('to_hash');
  return;
}

sub _matches_scalar {
  my ($value, $pattern) = @_;
  return defined($value) && !ref($value) && $value =~ $pattern;
}

sub _order_record {
  my ($event, $options) = @_;
  my $data = _event_data($event);
  return if ref($data) ne 'HASH';
  return if !_matches_scalar($data->{id}, qr/\A[0-9a-f]{64}\z/mxs);
  for my $field (qw(kind created_at)) {
    return if !_matches_scalar($data->{$field}, qr/\A[0-9]+\z/mxs);
  }
  return if ref($data->{tags}) ne 'ARRAY';
  my %tags      = _first_tag_values($data->{tags});
  my $sequence  = $tags{overnet_sequence};
  my $authority = $tags{overnet_authority};
  if ( !_matches_scalar($sequence, qr/\A[1-9][0-9]*\z/mxs)
    || !_matches_scalar($authority, qr/\A.+\z/mxs)) {
    $sequence = undef;
  }
  my $delegated = _delegated_metadata($data)
    && !($options->{snapshot_signers} || {})->{$data->{pubkey}};
  return {
    event      => $event,
    id         => $data->{id},
    created_at => $data->{created_at},
    phase      => _event_phase($data->{kind}, $delegated),
    authority  => $authority,
    sequence   => $sequence
  };
}

sub _event_phase {
  my ($kind, $delegated) = @_;
  return 0 if $kind == 9_000 || $kind == 9_002 || $kind == 9_009 || $delegated;
  return 1 if $kind == 9_021;
  return 2 if $kind == 9_001 || $kind == 9_022;
  return 3 if $kind >= 39_000 && $kind <= 39_003;
  return 4;
}

sub _order_at_timestamp {
  my ($items) = @_;
  my @remaining = sort { $a->{phase} <=> $b->{phase} || $a->{id} cmp $b->{id} } @{$items};
  my @ordered;
  while (@remaining) {
    my %first_sequence;
    for my $item (@remaining) {
      next if !defined $item->{sequence};
      my $first = $first_sequence{$item->{authority}};
      if (!defined($first) || _compare_sequence($item->{sequence}, $first) < 0) {
        $first_sequence{$item->{authority}} = $item->{sequence};
      }
    }
    for my $index (0 .. $#remaining) {
      my $item = $remaining[$index];
      next
        if defined($item->{sequence})
        && _compare_sequence($item->{sequence}, $first_sequence{$item->{authority}}) != 0;
      push @ordered, $item->{event};
      splice @remaining, $index, 1;
      last;
    }
  }
  return @ordered;
}

sub _compare_sequence {
  my ($earlier_sequence, $later_sequence) = @_;
  return length($earlier_sequence) <=> length($later_sequence) || $earlier_sequence cmp $later_sequence;
}

sub trusted_snapshot {
  my ($event, $snapshot_pubkeys) = @_;
  my $data = _event_data($event);
  return 0 if ref($data) ne 'HASH' || !_matches_scalar($data->{kind}, qr/\A[0-9]+\z/mxs);
  return 0 if defined($snapshot_pubkeys) && ref($snapshot_pubkeys) ne 'ARRAY';
  return 1 if $data->{kind} < 39_000    || $data->{kind} > 39_003;
  return 0 if !defined($data->{pubkey}) || ref($data->{pubkey});
  for my $pubkey (@{$snapshot_pubkeys || []}) {
    return 1 if defined($pubkey) && !ref($pubkey) && $pubkey eq $data->{pubkey};
  }
  return _delegated_metadata($data);
}

sub _delegated_metadata {
  my ($data) = @_;
  return 0 if $data->{kind} != 39_000 || ref($data->{tags}) ne 'ARRAY';
  return 0 if !_matches_scalar($data->{pubkey}, qr/\A[0-9a-f]{64}\z/mxs);
  my %tags = _first_tag_values($data->{tags});
  for my $name (qw(overnet_actor overnet_authority)) {
    return 0 if !_matches_scalar($tags{$name}, qr/\A[0-9a-f]{64}\z/mxs);
  }
  return 0 if $tags{overnet_actor} eq $data->{pubkey};
  return _matches_scalar($tags{overnet_sequence}, qr/\A[1-9][0-9]*\z/mxs) ? 1 : 0;
}

sub irc_user_mask {
  my (%args) = @_;
  for my $field (qw(nick user host)) {
    if (!(defined $args{$field} && !ref($args{$field}) && length($args{$field}))) {
      return;
    }
  }

  return join(q{}, $args{nick}, q{!}, $args{user}, q{@}, $args{host},);
}

sub irc_mask_matches {
  my (%args) = @_;
  my $mask   = $args{mask};
  my $value  = $args{value};
  if (!(defined $mask && !ref($mask) && length($mask))) {
    return 0;
  }
  if (!(defined $value && !ref($value) && length($value))) {
    return 0;
  }

  my $folded_mask  = irc_casefold($mask);
  my $folded_value = irc_casefold($value);
  if (!(defined $folded_mask && defined $folded_value)) {
    return 0;
  }

  my $pattern = quotemeta($folded_mask);
  $pattern =~ s/\\\*/.*/gmxs;
  $pattern =~ s/\\\?/./gmxs;

  return $folded_value =~ /\A$pattern\z/mxs ? 1 : 0;
}

sub authoritative_group_id {
  my (%args)  = @_;
  my $network = $args{network};
  my $channel = $args{channel};

  if (!(defined $network && !ref($network) && length($network))) {
    return;
  }
  if (!(_is_channel_name($channel))) {
    return;
  }

  my $folded_channel = irc_casefold($channel);
  if (!(defined $folded_channel && length($folded_channel))) {
    return;
  }

  my $group_id = eval {
    join(q{-},
      q{irc},
      unpack(q{H*}, encode('UTF-8', $network,        FB_CROAK | LEAVE_SRC)),
      unpack(q{H*}, encode('UTF-8', $folded_channel, FB_CROAK | LEAVE_SRC)));
  };
  return if !defined $group_id;
  return Net::Nostr::Group->validate_group_id($group_id)
    ? $group_id
    : undef;
}

sub channel_name_from_group_id {
  my (%args)   = @_;
  my $network  = $args{network};
  my $group_id = $args{group_id};

  if (!(defined $network && !ref($network) && length($network))) {
    return;
  }
  if (!(defined $group_id && !ref($group_id) && length($group_id))) {
    return;
  }
  my ($network_hex, $channel_hex) = $group_id =~ /\Airc-((?:[0-9a-f]{2})+)-((?:[0-9a-f]{2})+)\z/mxs;
  if (!(defined $network_hex && defined $channel_hex)) {
    return;
  }

  my $decoded_network = eval { decode('UTF-8', pack('H*', $network_hex), FB_CROAK) };
  return if !defined $decoded_network;
  if (!($decoded_network eq $network)) {
    return;
  }

  my $channel = eval { decode('UTF-8', pack('H*', $channel_hex), FB_CROAK) };
  return if !defined $channel || irc_casefold($channel) ne $channel;
  if (!(_is_channel_name($channel))) {
    return;
  }

  return $channel;
}

sub resolve_nip29_group_binding {
  my (%args) = @_;
  my $session_config =
    ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};
  my $network = $args{network};
  my $target  = $args{target};

  if (
    !(
         defined $session_config->{group_host}
      && !ref($session_config->{group_host})
      && length($session_config->{group_host})
    )
  ) {
    return (undef, undef, 'authoritative NIP-29 mapping requires session_config.group_host');
  }
  if (!(_is_channel_name($target))) {
    return (undef, undef, 'authoritative NIP-29 mapping requires a channel target');
  }

  my $binding;
  if (ref($session_config->{channel_groups}) eq 'HASH') {
    if (exists $session_config->{channel_groups}{$target}) {
      $binding = $session_config->{channel_groups}{$target};
    } else {
      my $target_key = irc_casefold($target);
      for my $configured_channel (keys %{$session_config->{channel_groups}}) {
        if (!(defined irc_casefold($configured_channel))) {
          next;
        }
        if (!(irc_casefold($configured_channel) eq $target_key)) {
          next;
        }
        $binding = $session_config->{channel_groups}{$configured_channel};
        last;
      }
    }
  }

  my $group_id =
    ref($binding) eq 'HASH'
    ? $binding->{group_id}
    : $binding;
  if (!(defined $group_id && length($group_id))) {
    $group_id = authoritative_group_id(
      network => $network,
      channel => $target,
    );
  }

  if (!(defined $group_id && length($group_id))) {
    return (undef, undef, "authoritative NIP-29 binding for $target requires group_id");
  }
  if (!(Net::Nostr::Group->validate_group_id($group_id))) {
    return (undef, undef, "authoritative NIP-29 binding for $target uses an invalid group_id");
  }

  return ($session_config->{group_host}, $group_id, undef);
}

sub channel_name_from_group_event {
  my (%args)  = @_;
  my $network = $args{network};
  my $event   = $args{event};

  if (!(defined $network && !ref($network) && length($network))) {
    return;
  }
  my $tags = _event_tags($event);
  if (!(ref($tags) eq 'ARRAY')) {
    return;
  }

  my %first   = _first_tag_values($tags);
  my $channel = channel_name_from_group_id(
    network  => $network,
    group_id => $first{d} || $first{h},
  );
  if (!(defined $channel)) {
    return;
  }

  if (defined $first{name} && _is_channel_name($first{name})) {
    my $named  = irc_casefold($first{name});
    my $folded = irc_casefold($channel);
    if (defined $named && defined $folded && $named eq $folded) {
      return $first{name};
    }
  }

  return $channel;
}

sub group_event_is_tombstoned {
  my (%args) = @_;
  my $tags = _event_tags($args{event});
  if (!(ref($tags) eq 'ARRAY')) {
    return 0;
  }

  for my $tag (@{$tags}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 1)) {
      next;
    }
    if ( ($tag->[0] || q{}) eq 'status'
      && ($tag->[1] || q{}) eq 'tombstoned') {
      return 1;
    }
  }

  return 0;
}

sub _event_tags {
  my ($event) = @_;
  if (!(defined $event)) {
    return;
  }

  if (ref($event) eq 'HASH' && ref($event->{tags}) eq 'ARRAY') {
    return $event->{tags};
  }
  if (blessed($event) && $event->can('tags')) {
    return $event->tags;
  }
  return;
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 1)) {
      next;
    }
    if (exists $values{$tag->[0]}) {
      next;
    }
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _is_channel_name {
  my ($value) = @_;
  return
       defined $value
    && !ref($value)
    && $value =~ /\A[#&][^\x00\x07\r\n ,:]+\z/mxs
    ? 1
    : 0;
}

1;

=head1 NAME

Overnet::Authority::HostedChannel - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Authority::HostedChannel;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 irc_casefold

Public API entry point.

=head2 ordered_events

Returns accepted authoritative events in the deterministic order defined by IRC
section 11.4, collapsing duplicate IDs. Inputs may be event hashes or Nostr
event objects. The caller must authenticate and authorize history before using
it; sorting does not establish trust. C<snapshot_signers> identifies configured
relay snapshot keys when distinguishing delegated metadata from snapshots.

=head2 trusted_snapshot

Filters already accepted history under IRC section 11.4. Snapshot events need
an explicitly configured signer, except delegated kind 39000 metadata with the
required actor, grant and sequence tags. Ordinary control events pass through.
The caller remains responsible for signature and admission verification; this
helper does not authorize new writes.

=head2 irc_user_mask

Public API entry point.

=head2 irc_mask_matches

Public API entry point.

=head2 authoritative_group_id

Public API entry point.

=head2 channel_name_from_group_id

Public API entry point.

=head2 resolve_nip29_group_binding

Public API entry point.

=head2 channel_name_from_group_event

Public API entry point.

=head2 group_event_is_tombstoned

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
