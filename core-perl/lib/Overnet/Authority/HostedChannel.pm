package Overnet::Authority::HostedChannel;

use strictures 2;
use Scalar::Util qw(blessed);

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

  my $group_id = join(q{-}, q{irc}, unpack(q{H*}, $network), unpack(q{H*}, $folded_channel),);
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
  my ($network_hex, $channel_hex) = $group_id =~ /\Airc-([0-9a-f]+)-([0-9a-f]+)\z/mxs;
  if (!(defined $network_hex && defined $channel_hex)) {
    return;
  }

  my $decoded_network = pack('H*', $network_hex);
  if (!($decoded_network eq $network)) {
    return;
  }

  my $channel = pack('H*', $channel_hex);
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
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
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
