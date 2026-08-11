package Overnet::Adapter::IRC::Presence;

use strictures 2;
use Moo;
use JSON ();
use Overnet::Adapter::IRC::Role::Validation;

our $VERSION = '0.001';
my $JSON = JSON->new;

with 'Overnet::Adapter::IRC::Role::Validation';

has overnet_version => (
  is       => 'ro',
  required => 1,
);

no Moo;

sub derive {
  my ($self, %args) = @_;
  return $self->derive_channel_presence(%args);
}

sub derive_channel_presence {
  my ($self, %args) = @_;

  my $arg_error = _validate_presence_args(\%args);
  if (defined $arg_error) {
    return $arg_error;
  }

  my $network = $args{network};
  my $target  = $args{target};
  my ($members, $as_of, $derive_error) = _derive_presence_members($network, $target, $args{events});
  if (defined $derive_error) {
    return _error($derive_error);
  }
  if (!defined $as_of) {
    return _error('derived presence requires at least one relevant observed event');
  }

  return _presence_event_result($self, \%args, $members, $as_of);
}

sub _validate_presence_args {
  my ($args) = @_;

  if (!_non_empty_scalar($args->{network})) {
    return _error('IRC network is required');
  }
  if (!_non_empty_scalar($args->{target})) {
    return _error('IRC target is required');
  }
  if (!_is_channel_target($args->{target})) {
    return _error('Presence target must be a channel');
  }
  if (!_non_negative_integer($args->{created_at})) {
    return _error('created_at must be a non-negative integer');
  }
  if (ref($args->{events}) ne 'ARRAY' || !@{$args->{events}}) {
    return _error('events must be a non-empty array');
  }

  return;
}

sub _derive_presence_members {
  my ($network, $target, $events) = @_;
  my %members;
  my $as_of;
  my %handler_for = (
    JOIN => \&_apply_presence_join_event,
    PART => \&_apply_presence_part_event,
    QUIT => \&_apply_presence_part_event,
    KICK => \&_apply_presence_kick_event,
    NICK => \&_apply_presence_nick_event,
  );

  for my $event (@{$events}) {
    my ($context, $event_error) = _presence_event_context($network, $event);
    if (defined $event_error) {
      return (undef, undef, $event_error);
    }

    my $handler = $handler_for{$context->{command}};
    if (!defined $handler) {
      next;
    }

    my ($event_as_of, $handler_error) = $handler->(\%members, $context, $target);
    if (defined $handler_error) {
      return (undef, undef, $handler_error);
    }
    if (defined($event_as_of) && (!defined($as_of) || $event_as_of > $as_of)) {
      $as_of = $event_as_of;
    }
  }

  return (\%members, $as_of, undef);
}

sub _presence_event_context {
  my ($network, $event) = @_;

  if (ref($event) ne 'HASH') {
    return (undef, 'derived presence events must be objects');
  }
  if (!_non_empty_scalar($event->{command})) {
    return (undef, 'derived presence event command is required');
  }
  if (!defined($event->{network}) || $event->{network} ne $network) {
    return (undef, 'derived presence event network mismatch');
  }
  if (!_non_empty_scalar($event->{nick})) {
    return (undef, 'derived presence event nick is required');
  }
  if (!_non_negative_integer($event->{created_at})) {
    return (undef, 'derived presence event created_at must be a non-negative integer');
  }

  my ($irc_identity, $identity_error) = _presence_identity_from_event($event);
  if (defined $identity_error) {
    return (undef, $identity_error);
  }

  return (
    {
      command      => $event->{command},
      nick         => $event->{nick},
      target       => $event->{target},
      created_at   => $event->{created_at},
      target_nick  => $event->{target_nick},
      new_nick     => $event->{new_nick},
      irc_identity => $irc_identity,
    },
    undef,
  );
}

sub _presence_identity_from_event {
  my ($event) = @_;
  my %irc_identity;

  for my $field (qw(account user host)) {
    if (!exists $event->{$field}) {
      next;
    }
    if (!_non_empty_scalar($event->{$field})) {
      return (undef, "derived presence event $field must be a non-empty string");
    }
    $irc_identity{$field} = $event->{$field};
  }

  return (\%irc_identity, undef);
}

sub _apply_presence_join_event {
  my ($members, $context, $target) = @_;

  my $target_error = _presence_channel_target_error('JOIN', $context->{target});
  if (defined $target_error) {
    return (undef, $target_error);
  }
  if ($context->{target} ne $target) {
    return;
  }

  $members->{$context->{nick}} = {
    nick => $context->{nick},
    %{$context->{irc_identity}},
    last_event_type => 'chat.join',
  };

  return ($context->{created_at}, undef);
}

sub _apply_presence_part_event {
  my ($members, $context, $target) = @_;

  my $target_error = _presence_channel_target_error($context->{command}, $context->{target});
  if (defined $target_error) {
    return (undef, $target_error);
  }
  if ($context->{target} ne $target) {
    return;
  }

  delete $members->{$context->{nick}};
  return ($context->{created_at}, undef);
}

sub _apply_presence_kick_event {
  my ($members, $context, $target) = @_;

  my $target_error = _presence_channel_target_error('KICK', $context->{target});
  if (defined $target_error) {
    return (undef, $target_error);
  }
  if (!_non_empty_scalar($context->{target_nick})) {
    return (undef, 'KICK target_nick is required');
  }
  if ($context->{target} ne $target) {
    return;
  }

  delete $members->{$context->{target_nick}};
  return ($context->{created_at}, undef);
}

sub _apply_presence_nick_event {
  my ($members, $context) = @_;

  if (!_non_empty_scalar($context->{new_nick})) {
    return (undef, 'NICK new_nick is required');
  }
  if (!exists $members->{$context->{nick}}) {
    return;
  }

  my $member = delete $members->{$context->{nick}};
  $member->{nick} = $context->{new_nick};
  if (keys %{$context->{irc_identity}}) {
    @{$member}{keys %{$context->{irc_identity}}} = values %{$context->{irc_identity}};
  }
  $member->{last_event_type} = 'irc.nick';
  $members->{$context->{new_nick}} = $member;

  return ($context->{created_at}, undef);
}

sub _presence_channel_target_error {
  my ($command, $target) = @_;

  if (!_is_channel_target($target)) {
    return "$command target must be a channel";
  }

  return;
}

sub _presence_event_result {
  my ($self, $args, $members_by_nick, $as_of) = @_;
  my $network     = $args->{network};
  my $target      = $args->{target};
  my $partial     = exists $args->{partial} ? ($args->{partial} ? JSON::true : JSON::false) : JSON::true;
  my @limitations = qw(unsigned no_edit_history irc.ephemeral_presence);
  if ($partial) {
    push @limitations, 'irc.partial_membership';
  }

  my @members;
  for my $nick (sort keys %{$members_by_nick}) {
    my %member = %{$members_by_nick->{$nick}};
    push @members, \%member;
  }

  my $object_id = "irc:$network:$target";

  return {
    valid => 1,
    event => {
      kind       => 37_800,
      created_at => $args->{created_at} + 0,
      tags       => [$self->_overnet_tags('irc.channel_presence', 'chat.channel', $object_id)],
      content    => $JSON->encode(
        {
          provenance => {
            type           => 'adapted',
            protocol       => 'irc',
            origin         => "$network/$target",
            external_scope => 'channel_membership',
            limitations    => \@limitations,
          },
          body => {
            members => \@members,
            partial => $partial,
            as_of   => $as_of + 0,
          },
        }
      ),
    },
  };
}

sub _overnet_tags {
  my ($self, $event_type, $object_type, $object_id) = @_;
  return (
    ['overnet_v',   $self->{overnet_version}],
    ['overnet_et',  $event_type],
    ['overnet_ot',  $object_type],
    ['overnet_oid', $object_id],
    ['v',           $self->{overnet_version}],
    ['t',           $event_type],
    ['o',           $object_type],
    ['d',           $object_id],
  );
}

1;

=head1 NAME

Overnet::Adapter::IRC::Presence - IRC channel presence derivation

=head1 DESCRIPTION

This internal collaborator derives an Overnet channel-presence event from an
ordered set of observed IRC membership events.

=head1 SYNOPSIS

  my $presence = Overnet::Adapter::IRC::Presence->new(
    overnet_version => '0.1.0',
  );
  my $result = $presence->derive(%presence_input);

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

=head2 derive

Derives one channel-presence result.

=head2 derive_channel_presence

Implements channel-presence derivation for the adapter facade.

=head2 overnet_version

Returns the Overnet version used in generated event tags.

=head1 DIAGNOSTICS

Invalid input is returned as a structured adapter error.

=head1 CONFIGURATION AND ENVIRONMENT

This collaborator receives its Overnet version from the adapter facade.

=head1 DEPENDENCIES

This module depends on JSON and Moo.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

Presence remains a partial view when the input is not exhaustive.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
