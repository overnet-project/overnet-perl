use strictures 2;
use JSON ();
use Test2::V0;

use Net::Nostr::Group;
use Overnet::Authority::HostedChannel ();
use Overnet::Adapter::IRC;

my $adapter = Overnet::Adapter::IRC->new;

sub _authority_config {
  return {
    authority_profile => 'nip29',
    group_host        => 'groups.example.test',
    channel_groups    => {
      '#overnet' => 'overnet',
    },
  };
}

sub _dynamic_authority_config {
  return {
    authority_profile => 'nip29',
    group_host        => 'groups.example.test',
  };
}

sub _group_ref {
  my ($pubkey, $group_id) = @_;
  return Net::Nostr::Group->format_id(
    pubkey   => $pubkey,
    group_id => $group_id,
  );
}

subtest 'authoritative KICK maps to a NIP-29 remove-user event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'KICK',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    target_nick    => 'bob',
    target_pubkey  => 'b' x 64,
    text           => 'rule violation',
    created_at     => 1_744_301_000,
  );

  ok $result->{valid}, 'authoritative KICK is accepted';
  is $result->{event}{kind},    9001,             'authoritative KICK emits kind 9001';
  is $result->{event}{pubkey},  'a' x 64,         'authoritative KICK uses the actor pubkey';
  is $result->{event}{content}, 'rule violation', 'authoritative KICK carries the reason in content';
  is(
    $result->{event}{tags},
    [['h', 'overnet'], ['p', 'b' x 64],],
    'authoritative KICK targets the bound NIP-29 group member',
  );
  like $result->{event}{id}, qr/\A[0-9a-f]{64}\z/mx, 'authoritative KICK has a deterministic unsigned event id';
  is $result->{event}{sig}, undef, 'authoritative KICK remains unsigned';
};

subtest 'authoritative MODE +o maps to a NIP-29 put-user event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '+o',
    mode_args      => ['bob'],
    target_pubkey  => 'b' x 64,
    current_roles  => ['irc.voice'],
    created_at     => 1_744_301_001,
  );

  ok $result->{valid}, 'authoritative MODE +o is accepted';
  is $result->{event}{kind}, 9000, 'authoritative MODE +o emits kind 9000';
  is(
    $result->{event}{tags},
    [['h', 'overnet'], ['p', 'b' x 64, 'irc.operator', 'irc.voice'],],
    'authoritative MODE +o updates roles through the NIP-29 member tag',
  );
  is $result->{event}{content}, '', 'authoritative MODE +o uses empty content when no reason is supplied';
};

subtest 'authoritative MODE +m maps to a NIP-29 metadata edit with IRC profile mode tags' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '+m',
    group_metadata => {
      closed => 1,
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative MODE +m is accepted';
  is $result->{event}{kind}, 9002, 'authoritative MODE +m emits kind 9002';
  is(
    $result->{event}{tags},
    [['h', 'overnet'], ['closed'], ['mode', 'moderated'],],
    'authoritative MODE +m preserves existing metadata flags and adds the moderated mode tag',
  );
};

subtest 'authoritative MODE +b and -b map to NIP-29 metadata edits carrying the IRC ban list' => sub {
  my $add_result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '+b',
    ban_mask       => 'bob!bob@127.0.0.1',
    group_metadata => {
      closed    => 1,
      ban_masks => ['*!*@evil.example'],
    },
    created_at => 1_744_301_002,
  );

  ok $add_result->{valid}, 'authoritative MODE +b is accepted';
  is $add_result->{event}{kind}, 9002, 'authoritative MODE +b emits kind 9002';
  is(
    $add_result->{event}{tags},
    [['h', 'overnet'], ['closed'], ['ban', '*!*@evil.example'], ['ban', 'bob!bob@127.0.0.1'],],
    'authoritative MODE +b preserves existing bans and appends the new IRC ban mask',
  );

  my $remove_result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '-b',
    ban_mask       => 'bob!bob@127.0.0.1',
    group_metadata => {
      closed    => 1,
      ban_masks => ['bob!bob@127.0.0.1', '*!*@evil.example'],
    },
    created_at => 1_744_301_003,
  );

  ok $remove_result->{valid}, 'authoritative MODE -b is accepted';
  is $remove_result->{event}{kind}, 9002, 'authoritative MODE -b emits kind 9002';
  is(
    $remove_result->{event}{tags},
    [['h', 'overnet'], ['closed'], ['ban', '*!*@evil.example'],],
    'authoritative MODE -b removes only the targeted IRC ban mask',
  );
};

subtest 'authoritative TOPIC maps to a NIP-29 metadata edit with the IRC topic tag' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'TOPIC',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    text           => 'Authoritative topic',
    group_metadata => {
      closed           => 1,
      moderated        => 1,
      topic_restricted => 1,
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative TOPIC is accepted';
  is $result->{event}{kind}, 9002, 'authoritative TOPIC emits kind 9002';
  is(
    $result->{event}{tags},
    [
      ['h', 'overnet'],
      ['closed'],
      ['mode',  'moderated'],
      ['mode',  'topic-restricted'],
      ['topic', 'Authoritative topic'],
    ],
    'authoritative TOPIC preserves existing metadata flags and carries the IRC topic tag',
  );
};

subtest 'authoritative DELETE maps to a NIP-29 metadata edit with the tombstone status tag' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'DELETE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    group_metadata => {
      closed           => 1,
      moderated        => 1,
      topic_restricted => 1,
      ban_masks        => ['*!*@evil.example'],
      topic            => 'Authoritative topic',
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative DELETE is accepted';
  is $result->{event}{kind}, 9002, 'authoritative DELETE emits kind 9002';
  is(
    $result->{event}{tags},
    [
      ['h', 'overnet'],
      ['closed'],
      ['mode',   'moderated'],
      ['mode',   'topic-restricted'],
      ['ban',    '*!*@evil.example'],
      ['topic',  'Authoritative topic'],
      ['status', 'tombstoned'],
    ],
    'authoritative DELETE preserves existing metadata and appends the tombstone status tag',
  );
};

subtest 'authoritative UNDELETE maps to a NIP-29 metadata edit that removes the tombstone status tag' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'UNDELETE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    group_metadata => {
      closed           => 1,
      moderated        => 1,
      topic_restricted => 1,
      ban_masks        => ['*!*@evil.example'],
      topic            => 'Authoritative topic',
      tombstoned       => 1,
    },
    created_at => 1_744_301_002,
  );

  ok $result->{valid}, 'authoritative UNDELETE is accepted';
  is $result->{event}{kind}, 9002, 'authoritative UNDELETE emits kind 9002';
  is(
    $result->{event}{tags},
    [
      ['h', 'overnet'],
      ['closed'],
      ['mode',  'moderated'],
      ['mode',  'topic-restricted'],
      ['ban',   '*!*@evil.example'],
      ['topic', 'Authoritative topic'],
    ],
    'authoritative UNDELETE preserves retained metadata and omits the tombstone status tag',
  );
};

subtest 'authoritative INVITE maps to a NIP-29 create-invite event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'INVITE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    target_nick    => 'bob',
    target_pubkey  => 'b' x 64,
    invite_code    => 'invite-bob',
    created_at     => 1_744_301_003,
  );

  ok $result->{valid}, 'authoritative INVITE is accepted';
  is $result->{event}{kind}, 9009, 'authoritative INVITE emits kind 9009';
  is(
    $result->{event}{tags},
    [['h', 'overnet'], ['code', 'invite-bob'], ['p', 'b' x 64],],
    'authoritative INVITE targets the bound NIP-29 group with an invite code and invitee pubkey',
  );
  is $result->{event}{content}, '', 'authoritative INVITE uses empty content by default';
};

subtest 'authoritative JOIN can bootstrap a newly created hosted channel without static channel_groups' => sub {
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => 'irc.example.test',
    channel => '#Fresh',
  );
  my $result = $adapter->map_input(
    session_config     => _dynamic_authority_config(),
    command            => 'JOIN',
    network            => 'irc.example.test',
    target             => '#Fresh',
    nick               => 'alice',
    actor_pubkey       => 'a' x 64,
    signing_pubkey     => 'd' x 64,
    authority_event_id => 'e' x 64,
    authority_sequence => 11,
    create_channel     => 1,
    group_metadata     => {
      name => '#Fresh',
    },
    created_at => 1_744_301_003,
  );

  ok $result->{valid},                  'authoritative bootstrap JOIN is accepted';
  ok ref($result->{events}) eq 'ARRAY', 'authoritative bootstrap JOIN emits multiple event drafts';
  is scalar(@{$result->{events}}), 3,
    'authoritative bootstrap JOIN emits metadata, operator bootstrap, and join drafts';
  is(
    [map { $_->{kind} } @{$result->{events}}],
    [39000, 9000, 9021],
    'authoritative bootstrap JOIN emits the expected NIP-29 event kinds',
  );
  is(
    $result->{events}[0]{tags},
    [
      ['d',                 $group_id],
      ['name',              '#Fresh'],
      ['overnet_actor',     'a' x 64],
      ['overnet_authority', 'e' x 64],
      ['overnet_sequence',  11],
    ],
    'authoritative bootstrap metadata uses the deterministic binding and delegated authority tags',
  );
  is(
    $result->{events}[1]{tags},
    [
      ['h',                 $group_id],
      ['p',                 'a' x 64, 'irc.operator'],
      ['overnet_actor',     'a' x 64],
      ['overnet_authority', 'e' x 64],
      ['overnet_sequence',  11],
    ],
    'authoritative bootstrap role event seeds the creator as irc.operator',
  );
  is(
    $result->{events}[2]{tags},
    [['h', $group_id], ['overnet_actor', 'a' x 64], ['overnet_authority', 'e' x 64], ['overnet_sequence', 11],],
    'authoritative bootstrap join uses the deterministic binding and delegated actor tags',
  );
};

subtest 'authoritative JOIN can target a delegated signer while preserving the effective actor' => sub {
  my $result = $adapter->map_input(
    session_config     => _authority_config(),
    command            => 'JOIN',
    network            => 'irc.example.test',
    target             => '#overnet',
    nick               => 'bob',
    actor_pubkey       => 'b' x 64,
    signing_pubkey     => 'd' x 64,
    authority_event_id => 'e' x 64,
    authority_sequence => 7,
    invite_code        => 'invite-bob',
    created_at         => 1_744_301_004,
  );

  ok $result->{valid}, 'delegated authoritative JOIN is accepted';
  is $result->{event}{kind},   9021,     'delegated authoritative JOIN emits kind 9021';
  is $result->{event}{pubkey}, 'd' x 64, 'delegated authoritative JOIN uses the delegated signer pubkey';
  is(
    $result->{event}{tags},
    [
      ['h',                 'overnet'],
      ['code',              'invite-bob'],
      ['overnet_actor',     'b' x 64],
      ['overnet_authority', 'e' x 64],
      ['overnet_sequence',  7],
    ],
    'delegated authoritative JOIN preserves the effective actor, authority grant reference, and session sequence',
  );
};

subtest 'authoritative PART maps to a NIP-29 leave-request event draft' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'PART',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'bob',
    actor_pubkey   => 'b' x 64,
    text           => 'later',
    created_at     => 1_744_301_005,
  );

  ok $result->{valid}, 'authoritative PART is accepted';
  is $result->{event}{kind},    9022,     'authoritative PART emits kind 9022';
  is $result->{event}{pubkey},  'b' x 64, 'authoritative PART uses the actor pubkey';
  is $result->{event}{content}, 'later',  'authoritative PART carries the part reason in content';
  is(
    $result->{event}{tags},
    [['h', 'overnet'],],
    'authoritative PART targets the bound NIP-29 group without a member p tag',
  );
};

subtest 'derive authoritative channel state reconstructs IRC-facing state from NIP-29 events' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_010,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, ['mode', 'moderated'];

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_011,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_012,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $roles = Net::Nostr::Group->roles(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_013,
    roles      => [{name => 'irc.operator'}, {name => 'irc.voice'},],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $admins, $members, $roles,],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds';
  is(
    $result->{state}[0],
    {
      operation         => 'authoritative_channel_state',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      channel_modes     => '+imn',
      supported_roles   => ['irc.operator', 'irc.voice'],
      members           => [
        {
          pubkey                => 'a' x 64,
          roles                 => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey                => 'b' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
      ],
    },
    'authoritative state derivation returns IRC-facing NIP-29 channel state',
  );
};

subtest 'derive authoritative channel state accepts a matching invite code plus join request as local membership' =>
  sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_020,
    closed     => 1,
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_021,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_022,
    members    => ['a' x 64,],
  )->to_hash;

  my $roles = Net::Nostr::Group->roles(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_023,
    roles      => [{name => 'irc.operator'}, {name => 'irc.voice'},],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_024,
  )->to_hash;
  push @{$invite->{tags}}, ['p', 'b' x 64];

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'b' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_025,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $admins, $members, $roles, $invite, $join,],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds for invite-mediated admission';
  is $result->{state}[0]{channel_modes}, '+in', 'closed authoritative channel keeps +i and implicit +n';
  is(
    $result->{state}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'matching invite plus join request produces derived local membership for the invited pubkey',
  );
  };

subtest 'derive authoritative channel state does not treat 39002 membership snapshots as exhaustive by default' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_020,
    closed     => 1,
  )->to_hash;

  my $initial_members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_021,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $partial_members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_022,
    members    => ['a' x 64,],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $initial_members, $partial_members,],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds for partial 39002 snapshots';
  is(
    $result->{state}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'later partial 39002 snapshots do not silently delete earlier derived members',
  );
};

subtest 'derive authoritative channel state removes local membership after a leave request' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_026,
    closed     => 1,
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_027,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_028,
    members    => ['a' x 64,],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_029,
  )->to_hash;
  push @{$invite->{tags}}, ['p', 'b' x 64];

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'b' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_030,
  )->to_hash;

  my $leave = Net::Nostr::Group->leave_request(
    pubkey     => 'b' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
    reason     => 'later',
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $admins, $members, $invite, $join, $leave,],
    },
  );

  ok $result->{valid}, 'authoritative state derivation succeeds for leave requests';
  is(
    $result->{state}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
    ],
    'leave requests remove the local member from derived authoritative membership',
  );
};

subtest 'derive authoritative channel state uses overnet_actor for delegated join requests' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_030,
    closed     => 1,
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_032,
    members    => ['a' x 64,],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_033,
  )->to_hash;
  push @{$invite->{tags}}, ['p', 'b' x 64];

  my $delegated_join = Net::Nostr::Group->join_request(
    pubkey     => 'd' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_034,
  )->to_hash;
  push @{$delegated_join->{tags}}, ['overnet_actor', 'b' x 64], ['overnet_authority', 'e' x 64];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $admins, $members, $invite, $delegated_join,],
    },
  );

  ok $result->{valid}, 'delegated authoritative state derivation succeeds';
  is(
    $result->{state}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'delegated join requests admit the effective actor pubkey rather than the delegated signer',
  );
};

subtest 'authoritative_channel_view sorts authoritative events and exposes admission, invites, and presence' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_020,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, ['mode',  'moderated'],                   ['mode',          'topic-restricted'];
  push @{$metadata->{tags}}, ['topic', 'Current authoritative topic'], ['overnet_actor', 'a' x 64];

  my $roles = Net::Nostr::Group->roles(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_024,
    roles      => [{name => 'irc.operator'}, {name => 'irc.voice'},],
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_019,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_018,
    members    => ['a' x 64, 'c' x 64,],
  )->to_hash;

  my $invite_bob = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_021,
  )->to_hash;
  push @{$invite_bob->{tags}},
    ['p',                 'b' x 64],
    ['overnet_actor',     'a' x 64],
    ['overnet_authority', '1' x 64],
    ['overnet_sequence',  1];

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => 'd' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_021,
  )->to_hash;
  push @{$join_bob->{tags}}, ['overnet_actor', 'b' x 64], ['overnet_authority', '1' x 64], ['overnet_sequence', 2];

  my $invite_carol = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-carol',
    created_at => 1_744_301_025,
  )->to_hash;
  push @{$invite_carol->{tags}}, ['p', 'e' x 64];

  my $join_alice = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_026,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'e' x 64,
      authoritative_events =>
        [$join_bob, $roles, $metadata, $invite_carol, $join_alice, $members, $invite_bob, $admins,],
    },
  );

  ok $result->{valid}, 'authoritative channel view derivation succeeds';
  is(
    $result->{view}[0],
    {
      operation          => 'authoritative_channel_view',
      authority_profile  => 'nip29',
      object_type        => 'chat.channel',
      object_id          => 'irc:irc.example.test:#overnet',
      group_host         => 'groups.example.test',
      group_id           => 'overnet',
      group_ref          => _group_ref('f' x 64, 'overnet'),
      channel_modes      => '+imnt',
      topic              => 'Current authoritative topic',
      topic_actor_pubkey => 'a' x 64,
      supported_roles    => ['irc.operator', 'irc.voice'],
      members            => [
        {
          pubkey                => 'a' x 64,
          roles                 => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey                => 'b' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
        {
          pubkey                => 'c' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
      ],
      present_members => [
        {
          pubkey                => 'a' x 64,
          roles                 => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey                => 'b' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
      ],
      pending_invites => [
        {
          code          => 'invite-carol',
          target_pubkey => 'e' x 64,
        },
      ],
      pending_join_requests => [],
      admission             => {
        allowed     => JSON::true,
        member      => JSON::false,
        invite_code => 'invite-carol',
        reason      => '',
      },
    },
    'authoritative channel view exposes sorted state, pending invites, presence, and actor-specific admission',
  );
};

subtest 'authoritative_channel_view exposes ban masks and rejects banned joins by IRC mask' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_027,
  )->to_hash;
  push @{$metadata->{tags}}, ['ban', 'bob!bob@127.0.0.1'];

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_028,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'Bob!bob@127.0.0.1',
      authoritative_events => [$admins, $metadata,],
    },
  );

  ok $result->{valid}, 'authoritative channel view derivation succeeds for ban enforcement';
  is(
    $result->{view}[0]{ban_masks},
    ['bob!bob@127.0.0.1'], 'authoritative channel view exposes the current authoritative IRC ban list',
  );
  is(
    $result->{view}[0]{admission},
    {
      allowed => JSON::false,
      member  => JSON::false,
      reason  => '+b',
    },
    'authoritative admission rejects a join whose IRC mask matches the ban list',
  );
};

subtest 'authoritative_join_admission allows an authenticated first join to create an absent hosted channel' => sub {
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => 'irc.example.test',
    channel => '#fresh',
  );

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _dynamic_authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#fresh',
      authoritative_events => [],
      actor_pubkey         => 'a' x 64,
      actor_mask           => 'alice!alice@127.0.0.1',
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for an absent hosted channel';
  is(
    $result->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#fresh',
      group_host        => 'groups.example.test',
      group_id          => $group_id,
      group_ref         => _group_ref('a' x 64, $group_id),
      allowed           => JSON::true,
      member            => JSON::false,
      present           => JSON::false,
      create_channel    => JSON::true,
      auth_required     => JSON::false,
      reason            => '',
    },
    'authenticated first join may create an absent hosted authoritative channel',
  );
};

subtest 'authoritative_join_admission reports auth_required for an absent hosted channel without an actor binding' =>
  sub {
  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _dynamic_authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#fresh',
      authoritative_events => [],
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds without an actor binding';
  is(
    $result->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#fresh',
      group_host        => 'groups.example.test',
      group_id          => Overnet::Authority::HostedChannel::authoritative_group_id(
        network => 'irc.example.test',
        channel => '#fresh',
      ),
      group_ref => undef,
      allowed        => JSON::false,
      member         => JSON::false,
      present        => JSON::false,
      create_channel => JSON::false,
      auth_required  => JSON::true,
      reason         => 'auth_required',
    },
    'absent hosted channels require authenticated actor binding before creation',
  );
  };

subtest 'authoritative_join_admission returns invite-mediated admission for a closed channel' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
    closed     => 1,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_032,
    members    => ['a' x 64,],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_033,
  )->to_hash;
  push @{$invite->{tags}}, ['p', 'b' x 64];

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $invite,],
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'bob!bob@127.0.0.1',
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for a closed invited channel';
  is(
    $result->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      allowed           => JSON::true,
      member            => JSON::false,
      present           => JSON::false,
      create_channel    => JSON::false,
      auth_required     => JSON::false,
      invite_code       => 'invite-bob',
      reason            => '',
    },
    'closed authoritative channels surface invite-mediated join admission symbolically',
  );
};

subtest 'authoritative_join_admission returns symbolic banned and deleted denials' => sub {
  my $banned_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_034,
    closed     => 1,
  )->to_hash;
  push @{$banned_metadata->{tags}}, ['ban', 'bob!bob@127.0.0.1'];

  my $banned = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$banned_metadata],
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'bob!bob@127.0.0.1',
    },
  );

  ok $banned->{valid}, 'join admission derivation succeeds for a banned actor';
  is(
    $banned->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      allowed           => JSON::false,
      member            => JSON::false,
      present           => JSON::false,
      create_channel    => JSON::false,
      auth_required     => JSON::false,
      reason            => '+b',
    },
    'banned joins are denied with a symbolic +b reason',
  );

  my $deleted_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_035,
    closed     => 1,
  )->to_hash;
  push @{$deleted_metadata->{tags}}, ['status', 'tombstoned'];

  my $deleted = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$deleted_metadata],
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'bob!bob@127.0.0.1',
    },
  );

  ok $deleted->{valid}, 'join admission derivation succeeds for a tombstoned channel';
  is(
    $deleted->{admission}[0],
    {
      operation         => 'authoritative_join_admission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      allowed           => JSON::false,
      member            => JSON::false,
      present           => JSON::false,
      create_channel    => JSON::false,
      auth_required     => JSON::false,
      deleted           => JSON::true,
      reason            => 'deleted',
    },
    'tombstoned channels are denied with a symbolic deleted reason',
  );
};

subtest 'authoritative_speak_permission enforces moderated channel voice and operator exemptions' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_040,
  )->to_hash;
  push @{$metadata->{tags}}, ['mode', 'moderated'];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_041,
    members    => ['a' x 64, 'b' x 64, 'c' x 64,],
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_042,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $voice = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_043,
    target     => 'b' x 64,
    roles      => ['irc.voice'],
  )->to_hash;

  my $voiced = $adapter->derive(
    operation      => 'authoritative_speak_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $ops, $voice],
      actor_pubkey         => 'b' x 64,
    },
  );

  ok $voiced->{valid}, 'speak permission derivation succeeds for voiced members';
  is(
    $voiced->{permission}[0],
    {
      operation             => 'authoritative_speak_permission',
      authority_profile     => 'nip29',
      object_type           => 'chat.channel',
      object_id             => 'irc:irc.example.test:#overnet',
      group_host            => 'groups.example.test',
      group_id              => 'overnet',
      group_ref             => _group_ref('f' x 64, 'overnet'),
      allowed               => JSON::true,
      roles                 => ['irc.voice'],
      presentational_prefix => '+',
      reason                => '',
    },
    'voiced members may speak in moderated authoritative channels',
  );

  my $unvoiced = $adapter->derive(
    operation      => 'authoritative_speak_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $ops, $voice],
      actor_pubkey         => 'c' x 64,
    },
  );

  ok $unvoiced->{valid}, 'speak permission derivation succeeds for unvoiced members';
  is(
    $unvoiced->{permission}[0],
    {
      operation             => 'authoritative_speak_permission',
      authority_profile     => 'nip29',
      object_type           => 'chat.channel',
      object_id             => 'irc:irc.example.test:#overnet',
      group_host            => 'groups.example.test',
      group_id              => 'overnet',
      group_ref             => _group_ref('f' x 64, 'overnet'),
      allowed               => JSON::false,
      roles                 => [],
      presentational_prefix => '',
      reason                => '+m',
    },
    'unvoiced non-operators are denied speak permission in moderated authoritative channels',
  );
};

subtest 'authoritative_topic_permission enforces topic-restricted operator rules' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_044,
  )->to_hash;
  push @{$metadata->{tags}}, ['mode', 'topic-restricted'];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_045,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_046,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $operator = $adapter->derive(
    operation      => 'authoritative_topic_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $ops],
      actor_pubkey         => 'a' x 64,
    },
  );

  ok $operator->{valid}, 'topic permission derivation succeeds for operators';
  is(
    $operator->{permission}[0],
    {
      operation         => 'authoritative_topic_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      allowed           => JSON::true,
      reason            => '',
    },
    'operators may change topic on topic-restricted authoritative channels',
  );

  my $member = $adapter->derive(
    operation      => 'authoritative_topic_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $ops],
      actor_pubkey         => 'b' x 64,
    },
  );

  ok $member->{valid}, 'topic permission derivation succeeds for non-operators';
  is(
    $member->{permission}[0],
    {
      operation         => 'authoritative_topic_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      allowed           => JSON::false,
      reason            => '+t',
    },
    'non-operators are denied topic permission on topic-restricted authoritative channels',
  );
};

subtest 'authoritative_mode_write_permission resolves operator mode and ban context' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_047,
  )->to_hash;
  push @{$metadata->{tags}}, ['closed'];
  push @{$metadata->{tags}}, ['mode', 'moderated'];
  push @{$metadata->{tags}}, ['mode', 'topic-restricted'];
  push @{$metadata->{tags}}, ['ban',  '*!*@banned.example'];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_048,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_049,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $voice = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_050,
    target     => 'b' x 64,
    roles      => ['irc.voice'],
  )->to_hash;

  my $grant_voice = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $ops, $voice],
      actor_pubkey         => 'a' x 64,
      mode                 => '+v',
      mode_args            => ['b' x 64],
    },
  );

  ok $grant_voice->{valid}, 'mode permission derivation succeeds for operators';
  is(
    $grant_voice->{permission}[0],
    {
      operation         => 'authoritative_mode_write_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      allowed           => JSON::true,
      mode              => '+v',
      target_pubkey     => 'b' x 64,
      current_roles     => ['irc.voice'],
      reason            => '',
    },
    'operator mode writes expose the current target pubkey and roles',
  );

  my $set_ban = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $ops, $voice],
      actor_pubkey         => 'a' x 64,
      mode                 => '+b',
      mode_args            => ['*!*@new.example'],
    },
  );

  ok $set_ban->{valid}, 'ban mode permission derivation succeeds for operators';
  is(
    $set_ban->{permission}[0],
    {
      operation           => 'authoritative_mode_write_permission',
      authority_profile   => 'nip29',
      object_type         => 'chat.channel',
      object_id           => 'irc:irc.example.test:#overnet',
      group_host          => 'groups.example.test',
      group_id            => 'overnet',
      group_ref           => _group_ref('f' x 64, 'overnet'),
      allowed             => JSON::true,
      mode                => '+b',
      normalized_ban_mask => '*!*@new.example',
      group_metadata      => {
        closed           => 1,
        moderated        => 1,
        topic_restricted => 1,
        private          => 0,
        hidden           => 0,
        restricted       => 0,
        ban_masks        => ['*!*@banned.example'],
        tombstoned       => 0,
      },
      reason => '',
    },
    'ban mode writes expose current authoritative metadata for subsequent mapping',
  );

  my $non_operator = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $ops, $voice],
      actor_pubkey         => 'b' x 64,
      mode                 => '+m',
      mode_args            => [],
    },
  );

  ok $non_operator->{valid}, 'mode permission derivation still succeeds for non-operators';
  is(
    $non_operator->{permission}[0],
    {
      operation         => 'authoritative_mode_write_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      allowed           => JSON::false,
      mode              => '+m',
      reason            => 'not_operator',
    },
    'non-operators are denied authoritative mode writes with a symbolic reason',
  );
};

subtest 'authoritative_channel_action_permission resolves kick, delete, and undelete rules' => sub {
  my $live_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_051,
  )->to_hash;

  my $live_members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_052,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $live_ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_053,
    target     => 'a' x 64,
    roles      => ['irc.operator'],
  )->to_hash;

  my $kick = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$live_metadata, $live_members, $live_ops],
      actor_pubkey         => 'a' x 64,
      action               => 'kick',
      target_pubkey        => 'b' x 64,
    },
  );

  ok $kick->{valid}, 'action permission derivation succeeds for kick';
  is(
    $kick->{permission}[0],
    {
      operation         => 'authoritative_channel_action_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      action            => 'kick',
      allowed           => JSON::true,
      target_pubkey     => 'b' x 64,
      reason            => '',
    },
    'kick permission returns the resolved target context for operators',
  );

  my $delete = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$live_metadata, $live_members, $live_ops],
      actor_pubkey         => 'b' x 64,
      action               => 'delete',
    },
  );

  ok $delete->{valid}, 'action permission derivation still succeeds for rejected delete';
  is(
    $delete->{permission}[0],
    {
      operation         => 'authoritative_channel_action_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      action            => 'delete',
      allowed           => JSON::false,
      reason            => 'not_operator',
    },
    'non-operators are denied authoritative channel actions with a symbolic reason',
  );

  my $tombstoned = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_054,
  )->to_hash;
  push @{$tombstoned->{tags}}, ['status', 'tombstoned'];
  push @{$tombstoned->{tags}}, ['topic',  'retained topic'];

  my $undelete = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$live_members, $live_ops, $tombstoned],
      actor_pubkey         => 'a' x 64,
      action               => 'undelete',
    },
  );

  ok $undelete->{valid}, 'action permission derivation succeeds for undelete';
  is(
    $undelete->{permission}[0],
    {
      operation         => 'authoritative_channel_action_permission',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      action            => 'undelete',
      allowed           => JSON::true,
      group_metadata    => {
        closed           => 0,
        moderated        => 0,
        topic_restricted => 0,
        private          => 0,
        hidden           => 0,
        restricted       => 0,
        ban_masks        => [],
        tombstoned       => 1,
        topic            => 'retained topic',
      },
      reason => '',
    },
    'retained operators may undelete and receive the retained metadata context',
  );
};

subtest 'authoritative_ban_list_view returns stable normalized authoritative ban masks' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_055,
  )->to_hash;
  push @{$metadata->{tags}}, ['ban', '*!*@z.example'];
  push @{$metadata->{tags}}, ['ban', '*!*@a.example'];
  push @{$metadata->{tags}}, ['ban', '*!*@a.example'];

  my $result = $adapter->derive(
    operation      => 'authoritative_ban_list_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata],
    },
  );

  ok $result->{valid}, 'ban-list view derivation succeeds';
  is(
    $result->{view}[0],
    {
      operation         => 'authoritative_ban_list_view',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      ban_masks         => ['*!*@a.example', '*!*@z.example',],
    },
    'ban-list view exposes stable normalized authoritative ban masks',
  );
};

subtest 'authoritative_list_entry_view reports list visibility and presentational state' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_056,
  )->to_hash;
  push @{$metadata->{tags}}, ['topic', 'Authoritative topic'];
  push @{$metadata->{tags}}, ['mode',  'moderated'];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_057,
    members    => ['a' x 64,],
  )->to_hash;

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_058,
  )->to_hash;

  my $visible = $adapter->derive(
    operation      => 'authoritative_list_entry_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $join],
    },
  );

  ok $visible->{valid}, 'list-entry view derivation succeeds';
  is(
    $visible->{view}[0],
    {
      operation         => 'authoritative_list_entry_view',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      channel           => '#overnet',
      visible_in_list   => JSON::true,
      channel_modes     => '+mn',
      visible_users     => 1,
      topic             => 'Authoritative topic',
    },
    'list-entry view exposes canonical list presentation for visible hosted channels',
  );

  my $tombstoned = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_059,
  )->to_hash;
  push @{$tombstoned->{tags}}, ['status', 'tombstoned'];

  my $hidden = $adapter->derive(
    operation      => 'authoritative_list_entry_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members, $join, $tombstoned],
    },
  );

  ok $hidden->{valid}, 'list-entry view derivation succeeds for tombstoned channels';
  is(
    $hidden->{view}[0],
    {
      operation         => 'authoritative_list_entry_view',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      channel           => '#overnet',
      visible_in_list   => JSON::false,
      reason            => 'deleted',
    },
    'tombstoned hosted channels are suppressed from authoritative LIST output',
  );
};

subtest 'authoritative_channel_state remains a projection of authoritative_channel_view' => sub {
  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_030,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $admins = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_031,
    members    => [
      {
        pubkey => 'a' x 64,
        roles  => ['irc.operator'],
      },
    ],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$members, $admins,],
    },
  );

  ok $result->{valid}, 'compatibility projection succeeds';
  is(
    $result->{state}[0],
    {
      operation         => 'authoritative_channel_state',
      authority_profile => 'nip29',
      object_type       => 'chat.channel',
      object_id         => 'irc:irc.example.test:#overnet',
      group_host        => 'groups.example.test',
      group_id          => 'overnet',
      group_ref         => _group_ref('f' x 64, 'overnet'),
      channel_modes     => '+n',
      supported_roles   => [],
      members           => [
        {
          pubkey                => 'a' x 64,
          roles                 => ['irc.operator'],
          presentational_prefix => '@',
        },
        {
          pubkey                => 'b' x 64,
          roles                 => [],
          presentational_prefix => '',
        },
      ],
    },
    'authoritative_channel_state still returns the legacy projection',
  );
};

subtest 'authoritative_channel_view orders same-second invite and join causally across authorities' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_040,
    closed     => 1,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_041,
    members    => ['a' x 64,],
  )->to_hash;

  my $invite_bob = Net::Nostr::Group->create_invite(
    pubkey     => '1' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_042,
  )->to_hash;
  push @{$invite_bob->{tags}},
    ['p',                 'b' x 64],
    ['overnet_actor',     'a' x 64],
    ['overnet_authority', '1' x 64],
    ['overnet_sequence',  5];

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => '2' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_042,
  )->to_hash;
  push @{$join_bob->{tags}}, ['overnet_actor', 'b' x 64], ['overnet_authority', '2' x 64], ['overnet_sequence', 1];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$join_bob, $metadata, $members, $invite_bob,],
    },
  );

  ok $result->{valid}, 'derivation succeeds when same-second invite and join come from different authorities';
  is(
    $result->{view}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'semantic ordering still applies the invite before the join across authorities',
  );
  is(
    $result->{view}[0]{present_members},
    [
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'same-second cross-authority join produces presence after the invite is applied',
  );
};

subtest 'authoritative_channel_view applies same-second invite before join regardless of authority tag ordering' =>
  sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_043,
    closed     => 1,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_044,
    members    => ['a' x 64,],
  )->to_hash;

  my $invite_bob = Net::Nostr::Group->create_invite(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_045,
  )->to_hash;
  push @{$invite_bob->{tags}},
    ['p',                 'b' x 64],
    ['overnet_actor',     'a' x 64],
    ['overnet_authority', 'f' x 64],
    ['overnet_sequence',  1];

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => '1' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_045,
  )->to_hash;
  push @{$join_bob->{tags}}, ['overnet_actor', 'b' x 64], ['overnet_authority', '1' x 64], ['overnet_sequence', 1];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$join_bob, $metadata, $members, $invite_bob,],
    },
  );

  ok $result->{valid}, 'derivation succeeds when same-second invite and join use conflicting authority sort order';
  is(
    $result->{view}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'invite admission still applies before the same-second join even when authority tags sort the other way',
  );
  is(
    $result->{view}[0]{present_members},
    [
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'same-second invite-plus-join still yields present membership after the semantic invite phase',
  );
  };

subtest 'authoritative_channel_view applies same-second removal after join regardless of authority tag ordering' =>
  sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_046,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_047,
    members    => ['a' x 64,],
  )->to_hash;

  my $join_bob = Net::Nostr::Group->join_request(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_048,
  )->to_hash;
  push @{$join_bob->{tags}}, ['overnet_actor', 'b' x 64], ['overnet_authority', 'f' x 64], ['overnet_sequence', 1];

  my $remove_bob = Net::Nostr::Group->remove_user(
    pubkey     => '1' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => 1_744_301_048,
  )->to_hash;
  push @{$remove_bob->{tags}}, ['overnet_actor', 'a' x 64], ['overnet_authority', '1' x 64], ['overnet_sequence', 1];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$join_bob, $metadata, $members, $remove_bob,],
    },
  );

  ok $result->{valid}, 'derivation succeeds when same-second join and removal use conflicting authority sort order';
  is(
    $result->{view}[0]{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'same-second removal still applies after the join and removes the member even when authority tags sort first',
  );
  is(
    $result->{view}[0]{present_members},
    [], 'same-second removal clears present membership after the semantic removal phase',
  );
  };

subtest 'derive authoritative channel view treats a tombstoned hosted channel as deleted and non-admissible' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_010,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, ['status', 'tombstoned'];

  my $operator = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_301_011,
    roles      => ['irc.operator'],
  )->to_hash;

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_012,
  )->to_hash;
  push @{$join->{tags}}, ['overnet_actor', 'a' x 64];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'a' x 64,
      authoritative_events => [$metadata, $operator, $join,],
    },
  );

  ok $result->{valid},               'tombstoned authoritative channel view derives successfully';
  ok $result->{view}[0]{tombstoned}, 'the derived authoritative channel view is marked tombstoned';
  is $result->{view}[0]{members},         [], 'tombstoned authoritative channels do not expose current members';
  is $result->{view}[0]{present_members}, [], 'tombstoned authoritative channels do not expose present members';
  ok $result->{view}[0]{admission}{deleted},  'tombstoned authoritative channels report a deleted admission result';
  ok !$result->{view}[0]{admission}{allowed}, 'tombstoned authoritative channels reject JOIN admission';
  is $result->{view}[0]{admission}{reason}, 'deleted',
    'tombstoned authoritative channels expose a deleted admission reason';
};

subtest
'derive authoritative channel view restores retained metadata and durable membership after UNDELETE while clearing presence and invites'
  => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_010,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}}, ['topic', 'Retained topic'];

  my $operator = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_301_011,
    roles      => ['irc.operator'],
  )->to_hash;

  my $member = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => 1_744_301_012,
    roles      => [],
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    code       => 'invite-carol',
    created_at => 1_744_301_013,
  )->to_hash;
  push @{$invite->{tags}}, ['p', 'c' x 64];

  my $join = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_014,
  )->to_hash;
  push @{$join->{tags}}, ['overnet_actor', 'a' x 64];

  my $tombstone = Net::Nostr::Group->edit_metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_015,
    closed     => 1,
  )->to_hash;
  push @{$tombstone->{tags}}, ['topic',  'Retained topic'];
  push @{$tombstone->{tags}}, ['status', 'tombstoned'];

  my $undelete = Net::Nostr::Group->edit_metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_016,
    closed     => 1,
  )->to_hash;
  push @{$undelete->{tags}}, ['topic', 'Retained topic'];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'b' x 64,
      authoritative_events => [$metadata, $operator, $member, $invite, $join, $tombstone, $undelete,],
    },
  );

  ok $result->{valid},                'reactivated authoritative channel view derives successfully';
  ok !$result->{view}[0]{tombstoned}, 'the reactivated authoritative channel view is no longer marked tombstoned';
  is $result->{view}[0]{channel_modes}, '+in', 'reactivated authoritative channels retain the pre-delete closed mode';
  is $result->{view}[0]{topic}, 'Retained topic', 'reactivated authoritative channels retain the prior topic metadata';
  is $result->{view}[0]{members},
    [
    {
      pubkey                => 'a' x 64,
      roles                 => ['irc.operator'],
      presentational_prefix => '@',
    },
    {
      pubkey                => 'b' x 64,
      roles                 => [],
      presentational_prefix => '',
    },
    ],
    'reactivated authoritative channels restore retained durable membership';
  is $result->{view}[0]{present_members}, [],
    'reactivated authoritative channels clear pre-delete present-member state';
  is $result->{view}[0]{pending_invites}, [],
    'reactivated authoritative channels clear pre-delete pending invites';
  ok $result->{view}[0]{admission}{member},  'retained members remain authoritative members after UNDELETE';
  ok $result->{view}[0]{admission}{allowed}, 'retained members may JOIN again after UNDELETE';
  is $result->{view}[0]{admission}{reason}, '',
    'reactivated authoritative channels do not report a join denial reason for retained members';
  };

subtest 'authoritative MODE list modes map exception, invite-exception, key, and limit metadata edits' => sub {
  my %mode_input = (
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    created_at     => 1_744_302_000,
  );

  my $add_exception = $adapter->map_input(%mode_input, mode => '+e', exception_mask => '*!*@good.example',);
  ok $add_exception->{valid}, 'authoritative MODE +e is accepted';
  is $add_exception->{event}{kind}, 9002, 'authoritative MODE +e emits kind 9002';
  is(
    $add_exception->{event}{tags},
    [['h', 'overnet'], ['except', '*!*@good.example'],],
    'authoritative MODE +e appends the IRC ban-exception mask',
  );

  my $remove_exception = $adapter->map_input(
    %mode_input,
    mode           => '-e',
    exception_mask => '*!*@good.example',
    group_metadata => {exception_masks => ['*!*@good.example', '*!*@kept.example'],},
  );
  ok $remove_exception->{valid}, 'authoritative MODE -e is accepted';
  is(
    $remove_exception->{event}{tags},
    [['h', 'overnet'], ['except', '*!*@kept.example'],],
    'authoritative MODE -e removes only the targeted IRC ban-exception mask',
  );

  my $add_invite_exception =
    $adapter->map_input(%mode_input, mode => '+I', invite_exception_mask => '*!*@vip.example',);
  ok $add_invite_exception->{valid}, 'authoritative MODE +I is accepted';
  is(
    $add_invite_exception->{event}{tags},
    [['h', 'overnet'], ['invite-except', '*!*@vip.example'],],
    'authoritative MODE +I appends the IRC invite-exception mask',
  );

  my $set_key = $adapter->map_input(%mode_input, mode => '+k', channel_key => 'sekrit',);
  ok $set_key->{valid}, 'authoritative MODE +k is accepted';
  is(
    $set_key->{event}{tags},
    [['h', 'overnet'], ['key', 'sekrit'],],
    'authoritative MODE +k records the channel key metadata tag',
  );

  my $clear_key = $adapter->map_input(%mode_input, mode => '-k', group_metadata => {channel_key => 'sekrit',},);
  ok $clear_key->{valid}, 'authoritative MODE -k is accepted';
  is(
    $clear_key->{event}{tags},
    [['h', 'overnet'],],
    'authoritative MODE -k drops the channel key metadata tag',
  );

  my $set_limit = $adapter->map_input(%mode_input, mode => '+l', user_limit => '25',);
  ok $set_limit->{valid}, 'authoritative MODE +l is accepted';
  is(
    $set_limit->{event}{tags},
    [['h', 'overnet'], ['limit', 25],],
    'authoritative MODE +l records the numeric user limit metadata tag',
  );

  my $clear_limit = $adapter->map_input(%mode_input, mode => '-l', group_metadata => {user_limit => 25,},);
  ok $clear_limit->{valid}, 'authoritative MODE -l is accepted';
  is(
    $clear_limit->{event}{tags},
    [['h', 'overnet'],],
    'authoritative MODE -l drops the user limit metadata tag',
  );
};

subtest 'authoritative MODE closed and topic-restricted toggles map to NIP-29 metadata flags' => sub {
  my %mode_input = (
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    created_at     => 1_744_302_010,
  );

  my $set_closed = $adapter->map_input(%mode_input, mode => '+i',);
  ok $set_closed->{valid}, 'authoritative MODE +i is accepted';
  is(
    $set_closed->{event}{tags},
    [['h', 'overnet'], ['closed'],],
    'authoritative MODE +i sets the NIP-29 closed metadata flag',
  );

  my $clear_closed = $adapter->map_input(
    %mode_input,
    mode           => '-i',
    group_metadata => {
      closed => 1,
      topic  => undef,
    },
  );
  ok $clear_closed->{valid}, 'authoritative MODE -i is accepted';
  is(
    $clear_closed->{event}{tags},
    [['h', 'overnet'],],
    'authoritative MODE -i clears the closed flag without inventing topic metadata',
  );

  my $set_topic_restricted = $adapter->map_input(%mode_input, mode => '+t',);
  ok $set_topic_restricted->{valid}, 'authoritative MODE +t is accepted';
  is(
    $set_topic_restricted->{event}{tags},
    [['h', 'overnet'], ['mode', 'topic-restricted'],],
    'authoritative MODE +t adds the topic-restricted mode tag',
  );

  my $clear_topic_restricted =
    $adapter->map_input(%mode_input, mode => '-t', group_metadata => {topic_restricted => 1,},);
  ok $clear_topic_restricted->{valid}, 'authoritative MODE -t is accepted';
  is(
    $clear_topic_restricted->{event}{tags},
    [['h', 'overnet'],],
    'authoritative MODE -t removes the topic-restricted mode tag',
  );

  my $clear_moderated = $adapter->map_input(%mode_input, mode => '-m', group_metadata => {moderated => 1,},);
  ok $clear_moderated->{valid}, 'authoritative MODE -m is accepted';
  is(
    $clear_moderated->{event}{tags},
    [['h', 'overnet'],],
    'authoritative MODE -m removes the moderated mode tag',
  );
};

subtest 'authoritative MODE -v removes the voice role through the NIP-29 member surface' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '-v',
    target_pubkey  => 'b' x 64,
    current_roles  => ['irc.operator', 'irc.voice'],
    created_at     => 1_744_302_020,
  );

  ok $result->{valid}, 'authoritative MODE -v is accepted';
  is $result->{event}{kind}, 9000, 'authoritative MODE -v emits kind 9000';
  is(
    $result->{event}{tags},
    [['h', 'overnet'], ['p', 'b' x 64, 'irc.operator'],],
    'authoritative MODE -v removes only the voice role from the NIP-29 member tag',
  );
};

subtest 'authoritative KICK, PART, and INVITE reasons are optional or carried faithfully' => sub {
  my %base_input = (
    session_config => _authority_config(),
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    created_at     => 1_744_302_030,
  );

  my $kick = $adapter->map_input(%base_input, command => 'KICK', target_nick => 'bob', target_pubkey => 'b' x 64,);
  ok $kick->{valid}, 'authoritative KICK without a reason is accepted';
  is $kick->{event}{content}, '', 'authoritative KICK without a reason uses empty content';

  my $part = $adapter->map_input(%base_input, command => 'PART',);
  ok $part->{valid}, 'authoritative PART without a reason is accepted';
  is $part->{event}{content}, '', 'authoritative PART without a reason uses empty content';

  my $invite = $adapter->map_input(
    %base_input,
    command       => 'INVITE',
    target_pubkey => 'b' x 64,
    invite_code   => 'invite-bob',
    text          => 'welcome aboard',
  );
  ok $invite->{valid}, 'authoritative INVITE with a reason is accepted';
  is $invite->{event}{content}, 'welcome aboard', 'authoritative INVITE carries the reason in content';
};

subtest 'authoritative JOIN carries the observed IRC mask and join reason' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'JOIN',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    actor_mask     => 'alice!a@127.0.0.1',
    invite_code    => 'invite-alice',
    text           => 'requesting entry',
    created_at     => 1_744_302_040,
  );

  ok $result->{valid}, 'authoritative JOIN with mask and reason is accepted';
  is $result->{event}{kind},    9021,               'authoritative JOIN emits a NIP-29 join request';
  is $result->{event}{content}, 'requesting entry', 'authoritative JOIN carries the reason in content';
  is(
    $result->{event}{tags},
    [['h', 'overnet'], ['code', 'invite-alice'], ['overnet_irc_mask', 'alice!a@127.0.0.1'],],
    'authoritative JOIN discloses the adapter-observed IRC mask for ban evaluation',
  );
};

subtest 'authoritative JOIN with create_channel bootstraps group metadata and operator membership' => sub {
  my $defaulted = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'JOIN',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    create_channel => 1,
    created_at     => 1_744_302_050,
  );

  ok $defaulted->{valid}, 'authoritative channel-creating JOIN is accepted without group_metadata';
  is scalar @{$defaulted->{events}}, 3, 'channel-creating JOIN emits metadata, membership, and join events';
  is $defaulted->{events}[0]{kind}, 39_000, 'the bootstrap metadata event is kind 39000';
  is(
    $defaulted->{events}[0]{tags},
    [['d', 'overnet'], ['name', '#overnet'],],
    'the bootstrap metadata name defaults to the IRC channel target',
  );
  is $defaulted->{events}[1]{kind}, 9000, 'the bootstrap membership event is kind 9000';
  is(
    $defaulted->{events}[1]{tags},
    [['h', 'overnet'], ['p', 'a' x 64, 'irc.operator'],],
    'the creating actor is granted irc.operator on the new channel',
  );
  is $defaulted->{events}[2]{kind}, 9021, 'the trailing event remains the join request';

  my $described = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'JOIN',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    create_channel => 1,
    group_metadata => {
      name       => 'Overnet HQ',
      picture    => 'https://pic.example/overnet.png',
      about      => 'Overnet coordination channel',
      private    => 1,
      closed     => 1,
      restricted => 1,
      hidden     => 1,
    },
    created_at => 1_744_302_051,
  );

  ok $described->{valid}, 'authoritative channel-creating JOIN accepts caller-supplied group metadata';
  is(
    $described->{events}[0]{tags},
    [
      ['d',       'overnet'],
      ['name',    'Overnet HQ'],
      ['picture', 'https://pic.example/overnet.png'],
      ['about',   'Overnet coordination channel'],
      ['private'], ['restricted'], ['hidden'], ['closed'],
    ],
    'caller-supplied metadata descriptors and flags are preserved on the bootstrap event',
  );
};

subtest 'authoritative channel state projects full IRC-facing metadata from a NIP-29 snapshot' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_000,
    name       => 'Overnet',
    picture    => 'https://pic.example/overnet.png',
    about      => 'Overnet coordination channel',
    private    => 1,
    restricted => 1,
    hidden     => 1,
    closed     => 1,
  )->to_hash;
  push @{$metadata->{tags}},
    ['mode'],
    ['topic'],
    ['ban'],
    ['except'],
    ['invite-except'],
    ['key'],
    ['limit'],
    ['status', 'active'],
    ['ban',    ''],
    ['ban',    '*!*@evil.example'],
    ['except',        '*!*@good.example'],
    ['invite-except', '*!*@vip.example'],
    ['key',           'sekrit'],
    ['limit',         '2'],
    ['mode',          'topic-restricted'],
    ['topic',         'Welcome to Overnet'];

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_303_001,
    roles      => ['irc.operator'],
  )->to_hash;

  my $messy_roles = {
    kind       => 9000,
    pubkey     => 'f' x 64,
    created_at => 1_744_303_002,
    content    => '',
    tags       => [['h', 'overnet'], ['p', 'b' x 64, 'irc.operator', 'irc.operator', '', 'zeta.role', 'alpha.role'],],
  };

  my $chatter = {
    kind       => 1,
    pubkey     => 'f' x 64,
    created_at => 1_744_303_003,
    content    => 'non-authoritative chatter',
    tags       => [['h', 'overnet'],],
  };

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => {%{_authority_config()}, group_pubkey => 'c' x 64,},
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $ops, $messy_roles, $chatter,],
    },
  );

  ok $result->{valid}, 'rich authoritative state derivation succeeds';
  my $state = $result->{state}[0];
  is $state->{group_ref}, _group_ref('c' x 64, 'overnet'),
    'a configured group_pubkey pins the authoritative group ref';
  is $state->{channel_modes}, '+iklnt', 'metadata flags and tags surface as IRC channel modes';
  is $state->{ban_masks},              ['*!*@evil.example'], 'empty ban masks are normalized away';
  is $state->{exception_masks},        ['*!*@good.example'], 'exception masks surface in channel state';
  is $state->{invite_exception_masks}, ['*!*@vip.example'],  'invite-exception masks surface in channel state';
  is $state->{channel_key},        'sekrit',            'the channel key surfaces in channel state';
  is $state->{user_limit},         2,                   'the user limit surfaces as a number';
  is $state->{topic},              'Welcome to Overnet', 'the last topic tag wins';
  is $state->{topic_actor_pubkey}, 'f' x 64,            'the topic actor is the metadata event pubkey';
  is(
    $state->{members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => ['irc.operator', 'alpha.role', 'zeta.role'],
        presentational_prefix => '@',
      },
    ],
    'duplicate and empty role labels are normalized while unknown roles sort after IRC roles',
  );
};

subtest 'authoritative channel state retains membership context for tombstoned channels' => sub {
  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_010,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_303_011,
    roles      => ['irc.operator'],
  )->to_hash;

  my $tombstoned = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_012,
  )->to_hash;
  push @{$tombstoned->{tags}}, ['status', 'tombstoned'];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$members, $ops, $tombstoned,],
    },
  );

  ok $result->{valid}, 'tombstoned authoritative state derivation succeeds';
  my $state = $result->{state}[0];
  is $state->{tombstoned}, JSON::true, 'the tombstoned flag surfaces in channel state';
  is $state->{members}, [], 'tombstoned channels expose no live members';
  is(
    $state->{retained_members},
    [
      {
        pubkey                => 'a' x 64,
        roles                 => ['irc.operator'],
        presentational_prefix => '@',
      },
      {
        pubkey                => 'b' x 64,
        roles                 => [],
        presentational_prefix => '',
      },
    ],
    'tombstoned channels retain durable membership for potential UNDELETE',
  );
};

subtest 'a 9002 metadata edit acts as an authoritative snapshot input' => sub {
  my $edit = Net::Nostr::Group->edit_metadata(
    pubkey     => 'e' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_020,
    closed     => 1,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$edit,],
    },
  );

  ok $result->{valid}, 'a 9002 edit-metadata snapshot derives a view';
  is $result->{view}[0]{group_ref}, _group_ref('e' x 64, 'overnet'),
    'the group ref is recovered from the h-tagged 9002 event pubkey';
  is $result->{view}[0]{channel_modes}, '+in', 'the 9002 closed flag maps to IRC +i';
};

subtest 'authoritative join admission without an authenticated actor reflects channel-level state' => sub {
  my $open_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_030,
  )->to_hash;

  my $open = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$open_metadata,],
    },
  );
  ok $open->{valid}, 'anonymous admission against an open channel derives';
  is $open->{admission}[0]{allowed}, JSON::true, 'open channels admit anonymous joins';
  is $open->{admission}[0]{reason},  '',         'open channel admission carries no denial reason';

  my $closed_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_031,
    closed     => 1,
  )->to_hash;

  my $closed = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$closed_metadata,],
    },
  );
  ok $closed->{valid}, 'anonymous admission against a closed channel derives';
  is $closed->{admission}[0]{allowed}, JSON::false, 'closed channels deny anonymous joins';
  is $closed->{admission}[0]{reason},  '+i',        'closed channel denial uses the symbolic +i reason';

  my $tombstoned_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_032,
  )->to_hash;
  push @{$tombstoned_metadata->{tags}}, ['status', 'tombstoned'];

  my $deleted = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$tombstoned_metadata,],
    },
  );
  ok $deleted->{valid}, 'anonymous admission against a tombstoned channel derives';
  is $deleted->{admission}[0]{allowed}, JSON::false, 'tombstoned channels deny anonymous joins';
  is $deleted->{admission}[0]{reason},  'deleted',   'tombstoned channel denial reports deletion';
  is $deleted->{admission}[0]{deleted}, JSON::true,  'tombstoned channel admission marks the channel deleted';
};

subtest 'authoritative join admission reflects membership, pending requests, and invite targeting' => sub {
  my $open_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_040,
  )->to_hash;
  push @{$open_metadata->{tags}}, ['ban', '*!*@evil.example'];

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_041,
    members    => ['a' x 64,],
  )->to_hash;

  my $member_join = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_042,
  )->to_hash;

  my $stranger_join = Net::Nostr::Group->join_request(
    pubkey     => 'd' x 64,
    group_id   => 'overnet',
    code       => 'no-such-code',
    created_at => 1_744_303_043,
  )->to_hash;

  my @open_events = ($open_metadata, $members, $member_join, $stranger_join,);

  my $member_admission = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [@open_events],
      actor_pubkey         => 'a' x 64,
    },
  );
  ok $member_admission->{valid}, 'member admission derives';
  is $member_admission->{admission}[0]{allowed}, JSON::true, 'current members are admitted';
  is $member_admission->{admission}[0]{member},  JSON::true, 'current members are reported as members';
  is $member_admission->{admission}[0]{present}, JSON::true, 'joined members are reported as present';

  my $stranger_view = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [@open_events],
    },
  );
  ok $stranger_view->{valid}, 'open channel view derives';
  is [map { $_->{pubkey} } @{$stranger_view->{view}[0]{members}}], ['a' x 64, 'd' x 64,],
    'an unknown invite code still admits joiners to an open channel';

  my $unbanned_admission = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [@open_events],
      actor_pubkey         => '1' x 64,
      actor_mask           => 'good!g@friendly.example',
    },
  );
  ok $unbanned_admission->{valid}, 'non-matching ban mask admission derives';
  is $unbanned_admission->{admission}[0]{allowed}, JSON::true, 'a non-matching mask is not treated as banned';
  is $unbanned_admission->{admission}[0]{reason},  '',         'non-matching masks carry no denial reason';

  my $keyed_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_050,
  )->to_hash;
  push @{$keyed_metadata->{tags}}, ['key', 'sekrit'];

  my $keyed_admission = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$keyed_metadata,],
      actor_pubkey         => '2' x 64,
      join_key             => 'sekrit',
    },
  );
  ok $keyed_admission->{valid}, 'matching join key admission derives';
  is $keyed_admission->{admission}[0]{allowed}, JSON::true, 'a matching join key satisfies +k';
  is $keyed_admission->{admission}[0]{reason},  '',         'matching join keys carry no denial reason';

  my $restricted_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_060,
    closed     => 1,
    restricted => 1,
  )->to_hash;

  my $pending_join = Net::Nostr::Group->join_request(
    pubkey     => '3' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_061,
  )->to_hash;

  my $pending_admission = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$restricted_metadata, $pending_join,],
      actor_pubkey         => '3' x 64,
    },
  );
  ok $pending_admission->{valid}, 'pending join request admission derives';
  is $pending_admission->{admission}[0]{allowed}, JSON::false, 'pending requesters are not yet admitted';
  is $pending_admission->{admission}[0]{reason}, 'join_request_pending',
    'pending requesters see the pending symbolic reason';
  is $pending_admission->{admission}[0]{pending_request}, JSON::true,
    'pending requesters see their request-in-flight marker';

  my $fresh_admission = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$restricted_metadata, $pending_join,],
      actor_pubkey         => '4' x 64,
    },
  );
  ok $fresh_admission->{valid}, 'request-mediated admission derives';
  is $fresh_admission->{admission}[0]{reason}, 'join_request',
    'closed restricted channels steer new actors to a join request';
  is $fresh_admission->{admission}[0]{request_join}, JSON::true,
    'closed restricted channels mark JOIN as request-mediated';

  my $closed_metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_070,
    closed     => 1,
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_303_071,
  )->to_hash;
  push @{$invite->{tags}}, ['p', 'b' x 64];

  my $mismatched_join = Net::Nostr::Group->join_request(
    pubkey     => '5' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_303_072,
  )->to_hash;

  my $mismatch_view = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$closed_metadata, $invite, $mismatched_join,],
    },
  );
  ok $mismatch_view->{valid}, 'targeted invite mismatch view derives';
  is $mismatch_view->{view}[0]{members}, [],
    'a join request cannot consume an invite targeted at a different pubkey';

  my $mismatch_admission = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$closed_metadata, $invite, $mismatched_join,],
      actor_pubkey         => '5' x 64,
    },
  );
  ok $mismatch_admission->{valid}, 'targeted invite mismatch admission derives';
  is $mismatch_admission->{admission}[0]{allowed}, JSON::false,
    'an invite targeted at another pubkey does not admit the requester';
  is $mismatch_admission->{admission}[0]{reason}, '+i', 'the mismatched requester still sees the +i denial';
};

subtest 'authoritative permissions deny actions on tombstoned channels with symbolic reasons' => sub {
  my $live_members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_080,
    members    => ['a' x 64, 'b' x 64,],
  )->to_hash;

  my $live_ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_303_081,
    roles      => ['irc.operator'],
  )->to_hash;

  my $tombstoned = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_082,
  )->to_hash;
  push @{$tombstoned->{tags}}, ['status', 'tombstoned'];

  my %deleted_input = (
    network              => 'irc.example.test',
    target               => '#overnet',
    authoritative_events => [$live_members, $live_ops, $tombstoned,],
    actor_pubkey         => 'a' x 64,
  );

  my $speak = $adapter->derive(
    operation      => 'authoritative_speak_permission',
    session_config => _authority_config(),
    input          => {%deleted_input},
  );
  ok $speak->{valid}, 'speak permission derivation succeeds for tombstoned channels';
  is $speak->{permission}[0]{allowed}, JSON::false, 'tombstoned channels deny speaking';
  is $speak->{permission}[0]{reason},  'deleted',   'tombstoned speak denial reports deletion';

  my $topic = $adapter->derive(
    operation      => 'authoritative_topic_permission',
    session_config => _authority_config(),
    input          => {%deleted_input},
  );
  ok $topic->{valid}, 'topic permission derivation succeeds for tombstoned channels';
  is $topic->{permission}[0]{allowed}, JSON::false, 'tombstoned channels deny topic changes';
  is $topic->{permission}[0]{reason},  'deleted',   'tombstoned topic denial reports deletion';

  my $mode_write = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {%deleted_input, mode => '+m', mode_args => [],},
  );
  ok $mode_write->{valid}, 'mode write permission derivation succeeds for tombstoned channels';
  is $mode_write->{permission}[0]{allowed}, JSON::false, 'tombstoned channels deny mode writes';
  is $mode_write->{permission}[0]{reason},  'deleted',   'tombstoned mode write denial reports deletion';

  my $action = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {%deleted_input, action => 'kick', target_pubkey => 'b' x 64,},
  );
  ok $action->{valid}, 'channel action permission derivation succeeds for tombstoned channels';
  is $action->{permission}[0]{allowed}, JSON::false, 'tombstoned channels deny live channel actions';
  is $action->{permission}[0]{reason},  'deleted',   'tombstoned action denial reports deletion';

  my $retained_non_operator = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {%deleted_input, actor_pubkey => 'b' x 64, action => 'undelete',},
  );
  ok $retained_non_operator->{valid}, 'undelete permission derivation succeeds for retained non-operators';
  is $retained_non_operator->{permission}[0]{allowed}, JSON::false,
    'retained non-operators may not undelete the channel';
  is $retained_non_operator->{permission}[0]{reason}, 'not_operator',
    'the undelete denial reports the missing operator role';

  my %live_input = (
    network              => 'irc.example.test',
    target               => '#overnet',
    authoritative_events => [$live_members, $live_ops,],
    actor_pubkey         => 'a' x 64,
  );

  my $not_deleted = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {%live_input, action => 'undelete',},
  );
  ok $not_deleted->{valid}, 'undelete permission derivation succeeds for live channels';
  is $not_deleted->{permission}[0]{allowed}, JSON::false, 'live channels cannot be undeleted';
  is $not_deleted->{permission}[0]{reason},  'not_deleted', 'the live undelete denial reports not_deleted';

  my $delete = $adapter->derive(
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
    input          => {%live_input, action => 'delete',},
  );
  ok $delete->{valid}, 'delete permission derivation succeeds for live operators';
  is $delete->{permission}[0]{allowed}, JSON::true, 'live operators may delete the channel';
  is ref($delete->{permission}[0]{group_metadata}), 'HASH',
    'delete permission exposes the retained metadata context for the tombstone edit';
};

subtest 'authoritative mode write permission exposes rich group metadata context' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_303_090,
    private    => 1,
    restricted => 1,
    hidden     => 1,
  )->to_hash;
  push @{$metadata->{tags}},
    ['except',        '*!*@good.example'],
    ['invite-except', '*!*@vip.example'],
    ['key',           'sekrit'],
    ['limit',         '25'],
    ['topic',         'Welcome to Overnet'];

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_303_091,
    roles      => ['irc.operator'],
  )->to_hash;

  my $moderated = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $ops,],
      actor_pubkey         => 'a' x 64,
      mode                 => '+m',
      mode_args            => [],
    },
  );

  ok $moderated->{valid}, 'state mode write permission derivation succeeds for operators';
  is $moderated->{permission}[0]{allowed}, JSON::true, 'operators may write +m';
  is(
    $moderated->{permission}[0]{group_metadata},
    {
      closed                 => 0,
      moderated              => 0,
      topic_restricted       => 0,
      private                => 1,
      restricted             => 1,
      hidden                 => 1,
      ban_masks              => [],
      exception_masks        => ['*!*@good.example'],
      invite_exception_masks => ['*!*@vip.example'],
      channel_key            => 'sekrit',
      user_limit             => 25,
      topic                  => 'Welcome to Overnet',
      tombstoned             => 0,
    },
    'the mode write context carries the complete current authoritative metadata',
  );

  my $unknown_target = $adapter->derive(
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $ops,],
      actor_pubkey         => 'a' x 64,
      mode                 => '+o',
      mode_args            => ['6' x 64,],
    },
  );

  ok $unknown_target->{valid}, 'role mode write permission derivation succeeds for unknown targets';
  is $unknown_target->{permission}[0]{allowed},       JSON::true, 'operators may write role modes';
  is $unknown_target->{permission}[0]{current_roles}, [],
    'role mode writes report empty current roles for non-members';
};

subtest 'authoritative group ref is derived from a lone kind 39002 members snapshot' => sub {
  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_700_000,
    members    => ['a' x 64],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$members],
    },
  );

  ok $result->{valid}, 'a lone members snapshot yields a valid channel view';
  is $result->{view}[0]{group_ref}, _group_ref('f' x 64, 'overnet'),
    'a kind 39002 members event supplies the authoritative group ref pubkey';
};

subtest 'authoritative admission does not mark an absent member as present' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_700_010,
  )->to_hash;
  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_700_011,
    members    => ['a' x 64, 'c' x 64],
  )->to_hash;
  my $join_a = Net::Nostr::Group->join_request(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    created_at => 1_744_700_012,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'c' x 64,
      authoritative_events => [$metadata, $members, $join_a],
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds';
  ok $result->{admission}[0]{member},   'actor c is a known member';
  ok !$result->{admission}[0]{present}, 'actor c is absent even though another member is present';
};

subtest 'a banned actor in a closed restricted channel is not offered a join request' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_700_020,
    closed     => 1,
    restricted => 1,
  )->to_hash;
  push @{$metadata->{tags}}, ['ban', 'evil!evil@bad'];

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'd' x 64,
      actor_mask           => 'evil!evil@bad',
      authoritative_events => [$metadata],
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for a banned actor';
  is $result->{admission}[0]{reason}, '+b', 'the banned actor is denied with the ban reason';
  ok !$result->{admission}[0]{request_join},
    'a banned actor is not additionally offered a join request';
};

subtest 'an existing member is not offered a redundant join request' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_700_030,
    closed     => 1,
    restricted => 1,
  )->to_hash;
  my $put = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_700_031,
    roles      => [],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'a' x 64,
      authoritative_events => [$metadata, $put],
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for an existing member';
  ok $result->{admission}[0]{member}, 'the actor is recognised as a member';
  ok !$result->{admission}[0]{request_join},
    'an existing member is not additionally offered a join request';
};

subtest 'a create-invite event without a p tag records no invite target' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_700_040,
    closed     => 1,
  )->to_hash;
  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'a' x 64,
    group_id   => 'overnet',
    code       => 'invite-nop',
    created_at => 1_744_700_041,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $invite],
    },
  );

  ok $result->{valid}, 'channel view derivation succeeds';
  is $result->{view}[0]{pending_invites}, [{code => 'invite-nop'}],
    'an invite without a p tag exposes only the code, never a synthetic target pubkey';
};

subtest 'irc.voice sorts ahead of custom roles by role rank, not by name' => sub {
  my $put = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => 1_744_700_050,
    roles      => ['irc.voice', 'zzz.role'],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$put],
    },
  );

  ok $result->{valid}, 'channel state derivation succeeds';
  my ($member) = grep { $_->{pubkey} eq 'b' x 64 } @{$result->{state}[0]{members}};
  is $member->{roles}, ['irc.voice', 'zzz.role'],
    'irc.voice (rank 1) precedes an unranked custom role (rank 2)';
};

# Authoritative-ordering fixtures: two conflicting role writes for member b, same
# created_at, resolved by authority sequence / semantic phase.
sub _ordering_put_user {
  my (%o) = @_;
  my $event = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => $o{created_at},
    roles      => ['irc.operator'],
  )->to_hash;
  push @{$event->{tags}}, @{$o{extra} || []};
  return $event;
}

sub _ordering_admins {
  my (%o) = @_;
  my $event = Net::Nostr::Group->admins(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => $o{created_at},
    members    => [{pubkey => 'b' x 64, roles => ['irc.voice']}],
  )->to_hash;
  push @{$event->{tags}}, @{$o{extra} || []};
  return $event;
}

sub _ordering_roles_for_b {
  my (@events) = @_;
  my $result = $adapter->derive(
    operation      => 'authoritative_channel_state',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => \@events,
    },
  );
  return (undef, $result->{reason}) unless $result->{valid};
  my ($member) = grep { $_->{pubkey} eq 'b' x 64 } @{$result->{state}[0]{members}};
  return ($member ? $member->{roles} : undef, undef);
}

subtest 'authority sequence tiebreak orders same-second role writes by sequence' => sub {
  my $auth = '1' x 64;
  my $put  = _ordering_put_user(
    created_at => 1_744_700_100,
    extra      => [['overnet_authority', $auth], ['overnet_sequence', '2']],
  );
  my $admins = _ordering_admins(
    created_at => 1_744_700_100,
    extra      => [['overnet_authority', $auth], ['overnet_sequence', '1']],
  );

  my ($roles, $reason) = _ordering_roles_for_b($put, $admins);
  ok defined($roles), 'sequence-ordered derivation succeeds' or diag($reason);
  is $roles, ['irc.operator'],
    'the higher overnet_sequence write (put-user) is applied last within the same authority';
};

subtest 'semantic phase orders same-second role writes when no authority sequence applies' => sub {
  my $put    = _ordering_put_user(created_at => 1_744_700_110);
  my $admins = _ordering_admins(created_at => 1_744_700_110);

  my ($roles, $reason) = _ordering_roles_for_b($put, $admins);
  ok defined($roles), 'phase-ordered derivation succeeds' or diag($reason);
  is $roles, ['irc.voice'],
    'without an authority sequence the later semantic phase (admins) is applied last';
};

subtest 'overnet_sequence is read only from overnet_sequence tags with digit values' => sub {
  my $auth = '1' x 64;
  my $put  = _ordering_put_user(
    created_at => 1_744_700_120,
    extra      => [['overnet_authority', $auth], ['note', '9']],
  );
  my $admins = _ordering_admins(
    created_at => 1_744_700_120,
    extra      => [['overnet_authority', $auth], ['note', '5']],
  );

  my ($roles, $reason) = _ordering_roles_for_b($put, $admins);
  ok defined($roles), 'derivation succeeds when no overnet_sequence tag is present' or diag($reason);
  is $roles, ['irc.voice'],
    'a non-overnet_sequence digit tag must not act as an authority sequence';
};

subtest 'a non-digit overnet_sequence value does not enable the sequence tiebreak' => sub {
  my $auth = '1' x 64;
  my $put  = _ordering_put_user(
    created_at => 1_744_700_130,
    extra      => [['overnet_authority', $auth], ['overnet_sequence', '9']],
  );
  my $admins = _ordering_admins(
    created_at => 1_744_700_130,
    extra      => [['overnet_authority', $auth], ['overnet_sequence', '2xyz']],
  );

  my ($roles, $reason) = _ordering_roles_for_b($put, $admins);
  ok defined($roles), 'derivation succeeds despite a malformed sequence value' or diag($reason);
  is $roles, ['irc.voice'],
    'a malformed sequence value is treated as zero so the tiebreak stays disabled';
};

subtest 'fully-tied authoritative events fall back to a deterministic id order' => sub {
  my $auth  = '1' x 64;
  my $pu_op = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => 1_744_700_140,
    roles      => ['irc.operator'],
  )->to_hash;
  push @{$pu_op->{tags}}, ['overnet_authority', $auth], ['overnet_sequence', '5'];

  my $pu_vo = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'b' x 64,
    created_at => 1_744_700_140,
    roles      => ['irc.voice'],
  )->to_hash;
  push @{$pu_vo->{tags}}, ['overnet_authority', $auth], ['overnet_sequence', '5'];

  # Input order [operator, voice] but id(voice) < id(operator); the id tiebreak
  # must order [voice, operator] so the operator write is applied last.
  my ($roles, $reason) = _ordering_roles_for_b($pu_op, $pu_vo);
  ok defined($roles), 'fully-tied derivation succeeds' or diag($reason);
  is $roles, ['irc.operator'],
    'events tied on created_at, sequence, and phase are ordered by lower-cased event id';
};

# --- batch-2 mutation kills ---------------------------------------------------

# Derive a channel view for a set of raw authoritative events and return the
# derived member/present pubkey initials (first character) as sorted strings.
sub _view_member_initials {
  my (@events) = @_;
  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => \@events,
    },
  );
  return (undef, undef, $result->{reason}) unless $result->{valid};
  my $members = join(q{}, sort map { substr($_->{pubkey}, 0, 1) } @{$result->{view}[0]{members}});
  my $present = join(q{}, sort map { substr($_->{pubkey}, 0, 1) } @{$result->{view}[0]{present_members}});
  return ($members, $present, undef);
}

subtest 'a same-second members snapshot re-adds a member removed by a lower-phase removal' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_000,
  )->to_hash;
  my $members = Net::Nostr::Group->members(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_001, members => ['b' x 64],
  )->to_hash;
  my $remove = Net::Nostr::Group->remove_user(
    pubkey => '1' x 64, group_id => 'overnet', target => 'b' x 64, created_at => 1_744_800_001,
  )->to_hash;

  my ($mem, undef, $reason) = _view_member_initials($metadata, $members, $remove);
  ok defined($mem), 'derivation succeeds for same-second remove and members snapshot' or diag($reason);
  is $mem, 'b',
    'the phase-2 remove-user applies before the phase-3 members snapshot, so the snapshot re-adds b';
};

subtest 'a same-second members snapshot re-adds a member cleared by a lower-phase leave' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_010,
  )->to_hash;
  my $members = Net::Nostr::Group->members(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_011, members => ['b' x 64],
  )->to_hash;
  my $leave = Net::Nostr::Group->leave_request(
    pubkey => 'b' x 64, group_id => 'overnet', created_at => 1_744_800_011,
  )->to_hash;

  my ($mem, undef, $reason) = _view_member_initials($metadata, $members, $leave);
  ok defined($mem), 'derivation succeeds for same-second leave and members snapshot' or diag($reason);
  is $mem, 'b',
    'the phase-2 leave-request applies before the phase-3 members snapshot, so the snapshot re-adds b';
};

subtest 'a same-second metadata close applies before a join request in semantic phase order' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_020,
  )->to_hash;
  my $close = Net::Nostr::Group->edit_metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_021, closed => 1,
  )->to_hash;
  is $close->{kind}, 9002, 'edit_metadata produces a kind 9002 metadata edit';
  my $join = Net::Nostr::Group->join_request(
    pubkey => 'b' x 64, group_id => 'overnet', created_at => 1_744_800_021,
  )->to_hash;

  my ($mem, $present, $reason) = _view_member_initials($metadata, $close, $join);
  ok defined($mem), 'derivation succeeds for same-second close and join' or diag($reason);
  is $mem, q{},
    'the phase-0 metadata close applies before the phase-1 join, so the join into the closed channel is dropped';
  is $present, q{}, 'no presence results from a join dropped by the earlier close';
};

subtest 'same-second put and remove without authority tags order by semantic phase, not the h tag' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_030,
  )->to_hash;
  my $put = Net::Nostr::Group->put_user(
    pubkey => 'f' x 64, group_id => 'overnet', target => 'b' x 64, created_at => 1_744_800_031, roles => [],
  )->to_hash;
  push @{$put->{tags}}, ['overnet_sequence', 5];
  my $remove = Net::Nostr::Group->remove_user(
    pubkey => 'f' x 64, group_id => 'overnet', target => 'b' x 64, created_at => 1_744_800_031,
  )->to_hash;
  push @{$remove->{tags}}, ['overnet_sequence', 2];

  # Neither event carries an overnet_authority tag, so no authority sequence
  # tiebreak applies and semantic phase decides: put-user (9000, phase 0) before
  # remove-user (9001, phase 2). The h tag value must NOT be treated as the
  # authority string, which would (wrongly) enable the sequence tiebreak.
  my ($mem, undef, $reason) = _view_member_initials($metadata, $put, $remove);
  ok defined($mem), 'derivation succeeds for same-second put and remove without authority tags' or diag($reason);
  is $mem, q{},
    'without an overnet_authority tag the remove (phase 2) still applies after the put (phase 0)';
};

subtest 'a closed but unrestricted channel records no pending join request' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_040, closed => 1,
  )->to_hash;
  my $join = Net::Nostr::Group->join_request(
    pubkey => 'b' x 64, group_id => 'overnet', created_at => 1_744_800_041,
  )->to_hash;
  push @{$join->{tags}}, ['overnet_actor', 'b' x 64];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $join],
    },
  );
  ok $result->{valid}, 'derivation succeeds for a closed unrestricted channel join';
  is $result->{view}[0]{pending_join_requests}, [],
    'a join into a closed but unrestricted channel is dropped without recording a pending request';
};

subtest 'a banned member is denied admission despite membership' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_050, closed => 1,
  )->to_hash;
  push @{$metadata->{tags}}, ['ban', 'bob!bob@127.0.0.1'];
  my $members = Net::Nostr::Group->members(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_051, members => ['b' x 64],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'bob!bob@127.0.0.1',
      authoritative_events => [$metadata, $members],
    },
  );
  ok $result->{valid}, 'join admission derivation succeeds for a banned member';
  ok $result->{admission}[0]{allowed}, 'membership admits the actor even though a ban mask matches (ban is only checked for non-members)';
  is $result->{admission}[0]{reason}, q{}, 'the admitted member is given an empty admission reason';
};

subtest 'a closed unrestricted channel offers no symbolic join request' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_060, closed => 1,
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      actor_pubkey         => 'b' x 64,
      actor_mask           => 'bob!bob@10.0.0.1',
      authoritative_events => [$metadata],
    },
  );
  ok $result->{valid}, 'join admission derivation succeeds for a closed unrestricted channel';
  is $result->{admission}[0]{reason}, '+i', 'a closed unrestricted channel denies with the +i reason';
  ok !$result->{admission}[0]{request_join},
    'a closed but unrestricted channel offers no join request (a request needs closed AND restricted)';
};

subtest 'a channel key metadata edit with an empty value does not set +k' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_070,
  )->to_hash;
  push @{$metadata->{tags}}, ['key', ''];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata],
    },
  );
  ok $result->{valid}, 'derivation succeeds for an empty channel key edit';
  is $result->{view}[0]{channel_modes}, '+n',
    'an empty channel_key value must not enable +k (the key must be defined AND non-empty)';
};

subtest 'a limit metadata edit with a non-integer value does not set +l' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey => 'f' x 64, group_id => 'overnet', created_at => 1_744_800_080,
  )->to_hash;
  push @{$metadata->{tags}}, ['limit', 'abc'];

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata],
    },
  );
  ok $result->{valid}, 'derivation succeeds for a non-integer limit edit';
  is $result->{view}[0]{channel_modes}, '+n',
    'a non-positive-integer limit value must not enable +l (the value must be a positive integer)';
};

subtest 'a duplicated d tag resolves the group id from the first d tag, not a later one' => sub {
  my $config = {
    authority_profile => 'nip29',
    group_host        => 'groups.example.test',
    channel_groups    => {'#zero' => '0'},
  };
  # Raw kind 39000 metadata event carrying two d tags; the first ('0') is the
  # bound group id. group id resolution must keep the FIRST d tag (//=), so this
  # event supplies the group ref pubkey. A later d tag must not override it.
  my $metadata = {
    kind       => 39_000,
    pubkey     => 'f' x 64,
    created_at => 1_744_800_090,
    content    => '{}',
    tags       => [['d', '0'], ['d', 'other-group'], ['name', '#zero']],
  };

  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => $config,
    input          => {
      network              => 'irc.example.test',
      target               => '#zero',
      authoritative_events => [$metadata],
    },
  );
  ok $result->{valid}, 'derivation succeeds when the metadata event has duplicate d tags';
  is $result->{view}[0]{group_ref}, _group_ref('f' x 64, '0'),
    'the first d tag (group id "0") resolves the group ref pubkey; a later d tag does not replace it';
};

subtest 'group ref resolution skips malformed single-element h tags' => sub {
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => 'irc.example.test',
    channel => '#fresh',
  );

  my $metadata = {
    kind       => 39_000,
    pubkey     => 'a' x 64,
    created_at => 1_744_301_000,
    content    => q{},
    id         => '0' x 64,
    sig        => '0' x 128,
    tags       => [['h'], ['h', $group_id], ['d', $group_id]],
  };

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _dynamic_authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#fresh',
      authoritative_events => [$metadata],
    },
  );

  ok $result->{valid}, 'derivation succeeds despite a malformed leading h tag';
  is $result->{admission}[0]{group_ref}, _group_ref('a' x 64, $group_id),
    'a malformed single-element h tag is skipped so the real h tag still resolves the group ref';
};

subtest 'authoritative_speak_permission allows unprivileged members in unmoderated channels' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_040,
  )->to_hash;

  my $members = Net::Nostr::Group->members(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_041,
    members    => ['c' x 64,],
  )->to_hash;

  my $result = $adapter->derive(
    operation      => 'authoritative_speak_permission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $members],
      actor_pubkey         => 'c' x 64,
    },
  );

  ok $result->{valid}, 'speak permission derivation succeeds for an unmoderated channel';
  is $result->{permission}[0]{allowed}, JSON::true,
    'an unprivileged member may speak when the channel is not moderated';
  is $result->{permission}[0]{reason}, q{},
    'an unmoderated allow carries no +m denial reason';
};

subtest 'authoritative_join_admission does not offer request_join when the join key is wrong' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_040,
    closed     => 1,
    restricted => 1,
  )->to_hash;
  push @{$metadata->{tags}}, ['key', 'sekret'];

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata],
      actor_pubkey         => 'b' x 64,
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for a bad-key actor';
  is $result->{admission}[0]{reason}, '+k', 'a wrong/missing join key denies with a symbolic +k reason';
  ok !exists $result->{admission}[0]{request_join},
    'a bad key blocks the request_join affordance even in a closed restricted channel';
};

subtest 'authoritative_join_admission does not offer request_join to an already-invited actor' => sub {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_040,
    closed     => 1,
    restricted => 1,
  )->to_hash;

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_050,
  )->to_hash;
  push @{$invite->{tags}}, ['p', 'b' x 64];

  my $result = $adapter->derive(
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [$metadata, $invite],
      actor_pubkey         => 'b' x 64,
    },
  );

  ok $result->{valid}, 'join admission derivation succeeds for an invited actor';
  is $result->{admission}[0]{reason}, q{},
    'a pending invite admits the actor without a symbolic denial reason';
  ok !exists $result->{admission}[0]{request_join},
    'an already-invited actor is not offered the request_join affordance (invite alone suffices)';
};

subtest 'authoritative metadata edit omits the key tag for an empty channel_key' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'MODE',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    mode           => '+m',
    group_metadata => {channel_key => q{},},
    created_at     => 1_744_301_002,
  );

  ok $result->{valid}, 'MODE edit carrying an empty channel_key is accepted';
  my @key_tags = grep { $_->[0] eq 'key' } @{$result->{event}{tags}};
  is scalar(@key_tags), 0,
    'a defined but empty channel_key emits no key tag (defined-and-length guard, not defined-or-length)';
};

done_testing;
