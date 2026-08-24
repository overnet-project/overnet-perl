use strictures 2;

use JSON ();
use Test2::V0;

use Net::Nostr::Group;
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

sub _operator_events {
  my $metadata = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    created_at => 1_744_301_100,
  )->to_hash;

  my $ops = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_301_101,
    roles      => ['irc.operator'],
  )->to_hash;

  return [$metadata, $ops,];
}

sub _authoritative_kick_args {
  return (
    session_config => _authority_config(),
    command        => 'KICK',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    actor_pubkey   => 'a' x 64,
    target_nick    => 'bob',
    target_pubkey  => 'b' x 64,
    created_at     => 1_744_301_000,
  );
}

subtest 'constructor rejects non-hash argument lists' => sub {
  like(
    dies { Overnet::Adapter::IRC->new('lonely-argument') },
    qr/constructor\sarguments\smust\sbe\sa\shash\sor\shash\sreference/msx,
    'odd argument lists are rejected',
  );
};

subtest 'open_session rejects invalid session API usage' => sub {
  like(
    dies { $adapter->open_session },
    qr/adapter_session_id\sis\srequired/msx,
    'open_session requires adapter_session_id',
  );
  like(
    dies { $adapter->open_session(adapter_session_id => 'session-1', session_config => [],) },
    qr/session_config\smust\sbe\san\sobject/msx,
    'open_session rejects non-object session_config',
  );
  like(
    dies { $adapter->open_session(adapter_session_id => 'session-1', secret_values => [],) },
    qr/secret_values\smust\sbe\san\sobject/msx,
    'open_session rejects non-object secret_values',
  );
  like(
    dies {
      $adapter->open_session(
        adapter_session_id => 'session-1',
        secret_values      => {sasl_password => undef,},
      )
    },
    qr/IRC\ssecret\sslot\ssasl_password\smust\sbe\sa\sstring/msx,
    'open_session rejects undefined secret slot values',
  );
  like(
    dies {
      $adapter->open_session(
        adapter_session_id => 'session-1',
        secret_values      => {sasl_password => ['not-a-string'],},
      )
    },
    qr/IRC\ssecret\sslot\ssasl_password\smust\sbe\sa\sstring/msx,
    'open_session rejects reference secret slot values',
  );
};

subtest 'close_session rejects invalid session API usage' => sub {
  like(
    dies { $adapter->close_session },
    qr/adapter_session_id\sis\srequired/msx,
    'close_session requires adapter_session_id',
  );
};

subtest 'standard mapping rejects missing or unsupported commands' => sub {
  my $missing = $adapter->map_input(
    network    => 'irc.example.test',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'hello',
    created_at => 1_744_301_000,
  );

  ok !$missing->{valid}, 'mapping without a command is rejected';
  is $missing->{reason}, 'IRC command is required', 'reason identifies the missing command';

  my $unsupported = $adapter->map_input(
    command    => 'WHOIS',
    network    => 'irc.example.test',
    target     => 'bob',
    nick       => 'alice',
    created_at => 1_744_301_000,
  );

  ok !$unsupported->{valid}, 'unsupported commands are rejected';
  is $unsupported->{reason}, 'Unsupported IRC command: WHOIS', 'reason identifies the unsupported command';
};

subtest 'standard mapping rejects reference argument values' => sub {
  my $result = $adapter->map_input(
    command    => 'PRIVMSG',
    network    => ['irc.example.test'],
    target     => '#overnet',
    nick       => 'alice',
    text       => 'hello',
    created_at => 1_744_301_000,
  );

  ok !$result->{valid}, 'reference network values are rejected';
  is $result->{reason}, 'IRC network is required', 'reason identifies the invalid network';
};

subtest 'standard mapping rejects invalid MODE mode_args' => sub {
  my %mode_args = (
    command    => 'MODE',
    network    => 'irc.example.test',
    target     => '#overnet',
    nick       => 'alice',
    mode       => '+b',
    created_at => 1_744_301_000,
  );

  my $not_array = $adapter->map_input(%mode_args, mode_args => 'bob!bob@127.0.0.1',);
  ok !$not_array->{valid}, 'non-array mode_args is rejected';
  is $not_array->{reason}, 'MODE mode_args must be an array of non-empty strings',
    'reason identifies non-array mode_args';

  my $empty_entry = $adapter->map_input(%mode_args, mode_args => [q{}],);
  ok !$empty_entry->{valid}, 'empty mode_args entries are rejected';
  is $empty_entry->{reason}, 'MODE mode_args must be an array of non-empty strings',
    'reason identifies empty mode_args entries',;
};

subtest 'nip29 session config only routes channel-scoped authoritative commands' => sub {
  my $non_channel = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'KICK',
    network        => 'irc.example.test',
    target         => 'bob',
    nick           => 'alice',
    target_nick    => 'bob',
    created_at     => 1_744_301_000,
  );

  ok !$non_channel->{valid}, 'non-channel authoritative commands fall back to standard mapping';
  is $non_channel->{reason}, 'KICK target must be a channel', 'reason reflects the standard KICK channel rule';

  my $message = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'PRIVMSG',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'alice',
    text           => 'hello',
    created_at     => 1_744_301_000,
  );

  ok $message->{valid}, 'non-authoritative commands still map under a nip29 session config';
  is $message->{event}{kind}, 7800, 'channel PRIVMSG maps to a standard adapted event';
};

subtest 'standard mapping rejects non-numeric created_at' => sub {
  my $result = $adapter->map_input(
    command    => 'PRIVMSG',
    network    => 'irc.example.test',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'hello',
    created_at => 'not-a-timestamp',
  );

  ok !$result->{valid}, 'mapping is rejected';
  is $result->{reason}, 'created_at must be a non-negative integer', 'reason identifies invalid timestamp';
};

subtest 'authoritative mapping rejects non-numeric created_at' => sub {
  my $result = $adapter->map_input(
    session_config => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
      channel_groups    => {
        '#overnet' => 'overnet',
      },
    },
    command       => 'KICK',
    network       => 'irc.example.test',
    target        => '#overnet',
    nick          => 'alice',
    actor_pubkey  => 'a' x 64,
    target_nick   => 'bob',
    target_pubkey => 'b' x 64,
    created_at    => 'not-a-timestamp',
  );

  ok !$result->{valid}, 'authoritative mapping is rejected';
  is $result->{reason}, 'created_at must be a non-negative integer', 'reason identifies invalid timestamp';
};

subtest 'authoritative mapping rejects broken session bindings' => sub {
  my %args = _authoritative_kick_args();

  my $no_group_host = $adapter->map_input(%args, session_config => {authority_profile => 'nip29',},);
  ok !$no_group_host->{valid}, 'authoritative mapping without group_host is rejected';
  is $no_group_host->{reason}, 'authoritative NIP-29 mapping requires session_config.group_host',
    'reason identifies the missing group host';

  my %no_actor = %args;
  delete $no_actor{actor_pubkey};
  my $missing_actor = $adapter->map_input(%no_actor);
  ok !$missing_actor->{valid}, 'authoritative mapping without actor_pubkey is rejected';
  is $missing_actor->{reason}, 'authoritative NIP-29 mapping requires actor_pubkey',
    'reason identifies the missing actor pubkey';
};

subtest 'authoritative mapping rejects incomplete delegated signing metadata' => sub {
  my %args = _authoritative_kick_args();

  my $bad_signer = $adapter->map_input(%args, signing_pubkey => 'not-hex',);
  ok !$bad_signer->{valid}, 'invalid signing_pubkey is rejected';
  is $bad_signer->{reason}, 'authoritative NIP-29 delegated signing requires signing_pubkey',
    'reason identifies the invalid signing pubkey';

  my $no_authority = $adapter->map_input(%args, signing_pubkey => 'd' x 64,);
  ok !$no_authority->{valid}, 'delegated signing without authority_event_id is rejected';
  is $no_authority->{reason}, 'authoritative NIP-29 delegated signing requires authority_event_id',
    'reason identifies the missing authority event';

  my $bad_sequence = $adapter->map_input(
    %args,
    signing_pubkey     => 'd' x 64,
    authority_event_id => 'e' x 64,
    authority_sequence => 0,
  );
  ok !$bad_sequence->{valid}, 'delegated signing without a positive sequence is rejected';
  is $bad_sequence->{reason}, 'authoritative NIP-29 delegated signing requires authority_sequence',
    'reason identifies the invalid sequence';
};

subtest 'authoritative KICK and INVITE reject missing member context' => sub {
  my %kick_args = _authoritative_kick_args();
  delete $kick_args{target_pubkey};
  my $kick = $adapter->map_input(%kick_args);
  ok !$kick->{valid}, 'authoritative KICK without target_pubkey is rejected';
  is $kick->{reason}, 'authoritative NIP-29 KICK requires target_pubkey', 'reason identifies the missing kick target';

  my %invite_args = (_authoritative_kick_args(), command => 'INVITE',);
  delete $invite_args{target_pubkey};
  my $invite_no_target = $adapter->map_input(%invite_args, invite_code => 'invite-bob',);
  ok !$invite_no_target->{valid}, 'authoritative INVITE without target_pubkey is rejected';
  is $invite_no_target->{reason}, 'authoritative NIP-29 INVITE requires target_pubkey',
    'reason identifies the missing invite target';

  my $invite_no_code = $adapter->map_input(%invite_args, target_pubkey => 'b' x 64,);
  ok !$invite_no_code->{valid}, 'authoritative INVITE without invite_code is rejected';
  is $invite_no_code->{reason}, 'authoritative NIP-29 INVITE requires invite_code',
    'reason identifies the missing invite code';
};

subtest 'authoritative JOIN rejects an empty invite_code' => sub {
  my $result = $adapter->map_input(
    session_config => _authority_config(),
    command        => 'JOIN',
    network        => 'irc.example.test',
    target         => '#overnet',
    nick           => 'bob',
    actor_pubkey   => 'b' x 64,
    invite_code    => q{},
    created_at     => 1_744_301_000,
  );

  ok !$result->{valid}, 'authoritative JOIN with an empty invite_code is rejected';
  is $result->{reason}, 'authoritative NIP-29 JOIN invite_code must be a non-empty string when supplied',
    'reason identifies the empty invite code';
};

subtest 'authoritative TOPIC, DELETE, and UNDELETE reject invalid metadata input' => sub {
  my %topic_args = (_authoritative_kick_args(), command => 'TOPIC',);
  delete @topic_args{qw(target_nick target_pubkey)};

  my $no_text = $adapter->map_input(%topic_args);
  ok !$no_text->{valid}, 'authoritative TOPIC without text is rejected';
  is $no_text->{reason}, 'TOPIC text is required', 'reason identifies the missing topic text';

  my $bad_metadata = $adapter->map_input(%topic_args, text => 'topic', group_metadata => [],);
  ok !$bad_metadata->{valid}, 'authoritative TOPIC with non-object group_metadata is rejected';
  is $bad_metadata->{reason}, 'group_metadata must be an object', 'reason identifies the invalid group metadata';

  my $bad_delete = $adapter->map_input(%topic_args, command => 'DELETE', group_metadata => [],);
  ok !$bad_delete->{valid}, 'authoritative DELETE with non-object group_metadata is rejected';
  is $bad_delete->{reason}, 'group_metadata must be an object', 'reason identifies the invalid delete metadata';

  my $bad_undelete = $adapter->map_input(%topic_args, command => 'UNDELETE', group_metadata => [],);
  ok !$bad_undelete->{valid}, 'authoritative UNDELETE with non-object group_metadata is rejected';
  is $bad_undelete->{reason}, 'group_metadata must be an object', 'reason identifies the invalid undelete metadata';
};

subtest 'authoritative MODE rejects invalid mode input' => sub {
  my %mode_args = (_authoritative_kick_args(), command => 'MODE',);
  delete @mode_args{qw(target_nick target_pubkey)};

  my $no_mode = $adapter->map_input(%mode_args);
  ok !$no_mode->{valid}, 'authoritative MODE without mode is rejected';
  is $no_mode->{reason}, 'MODE mode is required', 'reason identifies the missing mode';

  my $unsupported = $adapter->map_input(%mode_args, mode => '+x',);
  ok !$unsupported->{valid}, 'unsupported authoritative modes are rejected';
  is $unsupported->{reason}, 'Unsupported authoritative NIP-29 MODE: +x', 'reason identifies the unsupported mode';

  my $bad_target = $adapter->map_input(%mode_args, mode => '+o', target_pubkey => 'not-hex',);
  ok !$bad_target->{valid}, 'role mode without a target pubkey is rejected';
  is $bad_target->{reason}, 'authoritative NIP-29 MODE +o requires target_pubkey',
    'reason identifies the missing role target';

  my $no_roles = $adapter->map_input(%mode_args, mode => '+o', target_pubkey => 'b' x 64,);
  ok !$no_roles->{valid}, 'role mode without current_roles is rejected';
  is $no_roles->{reason}, 'authoritative NIP-29 MODE +o requires current_roles',
    'reason identifies the missing role context';

  my $empty_role = $adapter->map_input(
    %mode_args,
    mode          => '+o',
    target_pubkey => 'b' x 64,
    current_roles => [q{}],
  );
  ok !$empty_role->{valid}, 'role mode with empty current_roles entries is rejected';
  is $empty_role->{reason}, 'current_roles must be an array of non-empty strings',
    'reason identifies the invalid role list';

  my $bad_metadata = $adapter->map_input(%mode_args, mode => '+m', group_metadata => [],);
  ok !$bad_metadata->{valid}, 'metadata mode with non-object group_metadata is rejected';
  is $bad_metadata->{reason}, 'group_metadata must be an object', 'reason identifies the invalid mode metadata';
};

subtest 'authoritative MODE rejects missing per-mode arguments' => sub {
  my %mode_args = (_authoritative_kick_args(), command => 'MODE',);
  delete @mode_args{qw(target_nick target_pubkey)};

  my %reason_for = (
    '+b' => 'authoritative NIP-29 MODE +b requires ban_mask',
    '+e' => 'authoritative NIP-29 MODE +e requires exception_mask',
    '+I' => 'authoritative NIP-29 MODE +I requires invite_exception_mask',
    '+k' => 'authoritative NIP-29 MODE +k requires channel_key',
    '+l' => 'authoritative NIP-29 MODE +l requires user_limit',
  );

  for my $mode (sort keys %reason_for) {
    my $result = $adapter->map_input(%mode_args, mode => $mode,);
    ok !$result->{valid}, "authoritative MODE $mode without its argument is rejected";
    is $result->{reason}, $reason_for{$mode}, "reason identifies the missing $mode argument";
  }

  my $bad_limit = $adapter->map_input(%mode_args, mode => '+l', user_limit => 'lots',);
  ok !$bad_limit->{valid}, 'authoritative MODE +l with a non-integer limit is rejected';
  is $bad_limit->{reason}, 'authoritative NIP-29 MODE +l requires user_limit', 'reason identifies the invalid limit';
};

subtest 'derive rejects invalid dispatch arguments' => sub {
  my $no_operation = $adapter->derive(input => {},);
  ok !$no_operation->{valid}, 'derive without an operation is rejected';
  is $no_operation->{reason}, 'derive operation is required', 'reason identifies the missing operation';

  my $bad_input = $adapter->derive(operation => 'channel_presence', input => 'not-an-object',);
  ok !$bad_input->{valid}, 'derive with non-object input is rejected';
  is $bad_input->{reason}, 'derive input must be an object', 'reason identifies the invalid input';

  my $unsupported = $adapter->derive(operation => 'bogus_operation', input => {},);
  ok !$unsupported->{valid}, 'unsupported derive operations are rejected';
  is $unsupported->{reason}, 'Unsupported derive operation: bogus_operation',
    'reason identifies the unsupported operation';
};

subtest 'derived presence rejects invalid derivation arguments' => sub {
  my %presence_args = (
    network    => 'irc.example.test',
    target     => '#overnet',
    created_at => 1_744_301_001,
    events     => [
      {
        command    => 'JOIN',
        network    => 'irc.example.test',
        target     => '#overnet',
        nick       => 'alice',
        created_at => 1_744_301_000,
      },
    ],
  );

  my %no_network = %presence_args;
  delete $no_network{network};
  my $missing_network = $adapter->derive_channel_presence(%no_network);
  ok !$missing_network->{valid}, 'derived presence without a network is rejected';
  is $missing_network->{reason}, 'IRC network is required', 'reason identifies the missing network';

  my %no_target = %presence_args;
  delete $no_target{target};
  my $missing_target = $adapter->derive_channel_presence(%no_target);
  ok !$missing_target->{valid}, 'derived presence without a target is rejected';
  is $missing_target->{reason}, 'IRC target is required', 'reason identifies the missing target';

  my $not_array = $adapter->derive_channel_presence(%presence_args, events => {},);
  ok !$not_array->{valid}, 'derived presence with non-array events is rejected';
  is $not_array->{reason}, 'events must be a non-empty array', 'reason identifies the invalid events value';

  my $empty = $adapter->derive_channel_presence(%presence_args, events => [],);
  ok !$empty->{valid}, 'derived presence with no events is rejected';
  is $empty->{reason}, 'events must be a non-empty array', 'reason identifies the empty events list';
};

subtest 'derived presence rejects malformed observed events' => sub {
  my %presence_args = (
    network    => 'irc.example.test',
    target     => '#overnet',
    created_at => 1_744_301_001,
  );
  my %join_event = (
    command    => 'JOIN',
    network    => 'irc.example.test',
    target     => '#overnet',
    nick       => 'alice',
    created_at => 1_744_301_000,
  );

  my $not_object = $adapter->derive_channel_presence(%presence_args, events => ['not-an-object'],);
  ok !$not_object->{valid}, 'non-object observed events are rejected';
  is $not_object->{reason}, 'derived presence events must be objects', 'reason identifies the non-object event';

  my %no_command = %join_event;
  delete $no_command{command};
  my $missing_command = $adapter->derive_channel_presence(%presence_args, events => [\%no_command],);
  ok !$missing_command->{valid}, 'observed events without a command are rejected';
  is $missing_command->{reason}, 'derived presence event command is required',
    'reason identifies the missing event command';

  my %no_network = %join_event;
  delete $no_network{network};
  my $missing_network = $adapter->derive_channel_presence(%presence_args, events => [\%no_network],);
  ok !$missing_network->{valid}, 'observed events without a network are rejected';
  is $missing_network->{reason}, 'derived presence event network mismatch',
    'reason identifies the undisclosed event network';

  my %no_nick = %join_event;
  delete $no_nick{nick};
  my $missing_nick = $adapter->derive_channel_presence(%presence_args, events => [\%no_nick],);
  ok !$missing_nick->{valid}, 'observed events without a nick are rejected';
  is $missing_nick->{reason}, 'derived presence event nick is required', 'reason identifies the missing event nick';

  my $empty_user = $adapter->derive_channel_presence(%presence_args, events => [{%join_event, user => q{},}],);
  ok !$empty_user->{valid}, 'observed events with empty identity fields are rejected';
  is $empty_user->{reason}, 'derived presence event user must be a non-empty string',
    'reason identifies the invalid identity field';
};

subtest 'derived presence rejects non-channel membership events' => sub {
  my %presence_args = (
    network    => 'irc.example.test',
    target     => '#overnet',
    created_at => 1_744_301_001,
  );
  my %base_event = (
    network    => 'irc.example.test',
    nick       => 'alice',
    created_at => 1_744_301_000,
  );

  for my $command (qw(JOIN PART KICK)) {
    my $result = $adapter->derive_channel_presence(
      %presence_args,
      events => [{%base_event, command => $command, target => 'bob', target_nick => 'bob',},],
    );
    ok !$result->{valid}, "$command presence events with non-channel targets are rejected";
    is $result->{reason}, "$command target must be a channel", "reason identifies the non-channel $command target";
  }

  my $kick_no_nick = $adapter->derive_channel_presence(
    %presence_args,
    events => [{%base_event, command => 'KICK', target => '#overnet',},],
  );
  ok !$kick_no_nick->{valid}, 'KICK presence events without target_nick are rejected';
  is $kick_no_nick->{reason}, 'KICK target_nick is required', 'reason identifies the missing kicked nick';

  my $nick_no_new = $adapter->derive_channel_presence(
    %presence_args,
    events => [{%base_event, command => 'NICK', new_nick => q{},},],
  );
  ok !$nick_no_new->{valid}, 'NICK presence events without new_nick are rejected';
  is $nick_no_new->{reason}, 'NICK new_nick is required', 'reason identifies the missing new nick';
};

subtest 'derived presence rejects non-numeric created_at values' => sub {
  my $result = $adapter->derive_channel_presence(
    network    => 'irc.example.test',
    target     => '#overnet',
    created_at => 'not-a-timestamp',
    events     => [
      {
        command    => 'JOIN',
        network    => 'irc.example.test',
        target     => '#overnet',
        nick       => 'alice',
        created_at => 1_744_301_000,
      },
    ],
  );

  ok !$result->{valid}, 'derived presence is rejected';
  is $result->{reason}, 'created_at must be a non-negative integer', 'reason identifies invalid timestamp';

  $result = $adapter->derive_channel_presence(
    network    => 'irc.example.test',
    target     => '#overnet',
    created_at => 1_744_301_001,
    events     => [
      {
        command    => 'JOIN',
        network    => 'irc.example.test',
        target     => '#overnet',
        nick       => 'alice',
        created_at => 'not-a-timestamp',
      },
    ],
  );

  ok !$result->{valid}, 'derived presence event is rejected';
  is $result->{reason}, 'derived presence event created_at must be a non-negative integer',
    'reason identifies invalid event timestamp';
};

subtest 'authoritative channel view rejects invalid derivation context' => sub {
  my %view_args = (
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => _operator_events(),
    },
  );

  my $wrong_profile = $adapter->derive(%view_args, session_config => {},);
  ok !$wrong_profile->{valid}, 'authoritative view without a nip29 profile is rejected';
  is $wrong_profile->{reason}, 'authoritative_channel_view requires session_config.authority_profile = nip29',
    'reason identifies the missing authority profile';

  my $no_binding = $adapter->derive(%view_args, session_config => {authority_profile => 'nip29',},);
  ok !$no_binding->{valid}, 'authoritative view without a group binding is rejected';
  is $no_binding->{reason}, 'authoritative NIP-29 mapping requires session_config.group_host',
    'reason identifies the missing group host';

  my %input = %{$view_args{input}};

  my %no_network = %input;
  delete $no_network{network};
  my $missing_network = $adapter->derive(%view_args, input => \%no_network,);
  ok !$missing_network->{valid}, 'authoritative view without a network is rejected';
  is $missing_network->{reason}, 'IRC network is required', 'reason identifies the missing network';

  my %no_target = %input;
  delete $no_target{target};
  my $missing_target = $adapter->derive(%view_args, input => \%no_target,);
  ok !$missing_target->{valid}, 'authoritative view without a target is rejected';
  is $missing_target->{reason}, 'IRC target is required', 'reason identifies the missing target';

  my $non_channel = $adapter->derive(%view_args, input => {%input, target => 'bob',},);
  ok !$non_channel->{valid}, 'authoritative view for a non-channel target is rejected';
  is $non_channel->{reason}, 'authoritative_channel_view target must be a channel',
    'reason identifies the non-channel target';

  my $not_array = $adapter->derive(%view_args, input => {%input, authoritative_events => {},},);
  ok !$not_array->{valid}, 'authoritative view with non-array events is rejected';
  is $not_array->{reason}, 'authoritative_events must be a non-empty array',
    'reason identifies the invalid events value';

  my $empty = $adapter->derive(%view_args, input => {%input, authoritative_events => [],},);
  ok !$empty->{valid}, 'authoritative view with no events is rejected';
  is $empty->{reason}, 'authoritative_events must be a non-empty array', 'reason identifies the empty events list';
};

subtest 'authoritative channel view rejects invalid optional actor context' => sub {
  my %input = (
    network              => 'irc.example.test',
    target               => '#overnet',
    authoritative_events => _operator_events(),
  );
  my %view_args = (
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
  );

  my $bad_actor = $adapter->derive(%view_args, input => {%input, actor_pubkey => 'not-hex',},);
  ok !$bad_actor->{valid}, 'invalid actor pubkeys are rejected';
  is $bad_actor->{reason}, 'actor_pubkey must be a 64-character hex pubkey when supplied',
    'reason identifies the invalid actor pubkey';

  my $bad_mask = $adapter->derive(%view_args, input => {%input, actor_mask => q{},},);
  ok !$bad_mask->{valid}, 'empty actor masks are rejected';
  is $bad_mask->{reason}, 'actor_mask must be a non-empty string when supplied',
    'reason identifies the invalid actor mask';

  my $bad_key = $adapter->derive(%view_args, input => {%input, join_key => q{},},);
  ok !$bad_key->{valid}, 'empty join keys are rejected';
  is $bad_key->{reason}, 'join_key must be a non-empty string when supplied', 'reason identifies the invalid join key';
};

subtest 'authoritative channel view rejects malformed authoritative events' => sub {
  my %view_args = (
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
  );
  my %input = (
    network => 'irc.example.test',
    target  => '#overnet',
  );

  my $not_object = $adapter->derive(%view_args, input => {%input, authoritative_events => ['not-an-object'],},);
  ok !$not_object->{valid}, 'non-object authoritative events are rejected';
  like $not_object->{reason}, qr/\Aauthoritative\sevents\smust\sbe\sobjects/msx,
    'reason identifies the non-object event';

  my $not_event = $adapter->derive(%view_args, input => {%input, authoritative_events => [{}],},);
  ok !$not_event->{valid}, 'invalid Nostr event structures are rejected';
  like $not_event->{reason}, qr/\Aauthoritative\sevents\smust\sbe\svalid\sNostr\sevents/msx,
    'reason identifies the invalid event structure';

  my $other_group = Net::Nostr::Group->metadata(
    pubkey     => 'f' x 64,
    group_id   => 'other-group',
    created_at => 1_744_301_102,
  )->to_hash;
  my $mismatch = $adapter->derive(%view_args, input => {%input, authoritative_events => [$other_group],},);
  ok !$mismatch->{valid}, 'authoritative events for another group are rejected';
  is $mismatch->{reason}, 'authoritative event group mismatch', 'reason identifies the group mismatch';
};

subtest 'authoritative channel view rejects malformed membership change events' => sub {
  my %view_args = (
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
  );
  my %input = (
    network => 'irc.example.test',
    target  => '#overnet',
  );

  my $put_user = Net::Nostr::Group->put_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_301_103,
    roles      => [],
  )->to_hash;
  $put_user->{tags} = [grep { $_->[0] ne 'p' } @{$put_user->{tags}}];
  my $bad_put = $adapter->derive(%view_args, input => {%input, authoritative_events => [$put_user],},);
  ok !$bad_put->{valid}, 'put-user events without a target are rejected';
  is $bad_put->{reason}, 'put-user event must include one p tag target', 'reason identifies the missing put target';

  my $remove_user = Net::Nostr::Group->remove_user(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    target     => 'a' x 64,
    created_at => 1_744_301_104,
  )->to_hash;
  $remove_user->{tags} = [grep { $_->[0] ne 'p' } @{$remove_user->{tags}}];
  my $bad_remove = $adapter->derive(%view_args, input => {%input, authoritative_events => [$remove_user],},);
  ok !$bad_remove->{valid}, 'remove-user events without a target are rejected';
  is $bad_remove->{reason}, 'remove-user event must include one p tag target',
    'reason identifies the missing remove target';

  my $invite = Net::Nostr::Group->create_invite(
    pubkey     => 'f' x 64,
    group_id   => 'overnet',
    code       => 'invite-bob',
    created_at => 1_744_301_105,
  )->to_hash;
  $invite->{tags} = [grep { $_->[0] ne 'code' } @{$invite->{tags}}];
  my $bad_invite = $adapter->derive(%view_args, input => {%input, authoritative_events => [$invite],},);
  ok !$bad_invite->{valid}, 'create-invite events without a code are rejected';
  is $bad_invite->{reason}, 'create-invite event must include one code tag',
    'reason identifies the missing invite code';
};

subtest 'authoritative join admission rejects invalid derivation input' => sub {
  my %admission_args = (
    operation      => 'authoritative_join_admission',
    session_config => _authority_config(),
  );
  my %input = (
    network => 'irc.example.test',
    target  => '#overnet',
  );

  my $not_array = $adapter->derive(%admission_args, input => {%input, authoritative_events => {},},);
  ok !$not_array->{valid}, 'join admission with non-array events is rejected';
  is $not_array->{reason}, 'authoritative_events must be an array', 'reason identifies the invalid events value';

  my $bad_view = $adapter->derive(%admission_args, input => {%input, authoritative_events => ['not-an-object'],},);
  ok !$bad_view->{valid}, 'join admission propagates authoritative view failures';
  like $bad_view->{reason}, qr/\Aauthoritative\sevents\smust\sbe\sobjects/msx,
    'reason identifies the invalid view event';
};

subtest 'authoritative permission derivations reject invalid context' => sub {
  my %permission_args = (
    operation      => 'authoritative_speak_permission',
    session_config => _authority_config(),
  );
  my %input = (
    network              => 'irc.example.test',
    target               => '#overnet',
    authoritative_events => _operator_events(),
    actor_pubkey         => 'a' x 64,
  );

  my $wrong_profile = $adapter->derive(%permission_args, session_config => {}, input => \%input,);
  ok !$wrong_profile->{valid}, 'permission derivation without a nip29 profile is rejected';
  is $wrong_profile->{reason}, 'authoritative permission derivation requires session_config.authority_profile = nip29',
    'reason identifies the missing authority profile';

  my %no_network = %input;
  delete $no_network{network};
  my $missing_network = $adapter->derive(%permission_args, input => \%no_network,);
  ok !$missing_network->{valid}, 'permission derivation without a network is rejected';
  is $missing_network->{reason}, 'IRC network is required', 'reason identifies the missing network';

  my %no_target = %input;
  delete $no_target{target};
  my $missing_target = $adapter->derive(%permission_args, input => \%no_target,);
  ok !$missing_target->{valid}, 'permission derivation without a target is rejected';
  is $missing_target->{reason}, 'IRC target is required', 'reason identifies the missing target';

  my $non_channel = $adapter->derive(%permission_args, input => {%input, target => 'bob',},);
  ok !$non_channel->{valid}, 'permission derivation for a non-channel target is rejected';
  is $non_channel->{reason}, 'authoritative permission target must be a channel',
    'reason identifies the non-channel target';

  my $no_binding =
    $adapter->derive(%permission_args, session_config => {authority_profile => 'nip29',}, input => \%input,);
  ok !$no_binding->{valid}, 'permission derivation without a group binding is rejected';
  is $no_binding->{reason}, 'authoritative NIP-29 mapping requires session_config.group_host',
    'reason identifies the missing group host';

  my $not_array = $adapter->derive(%permission_args, input => {%input, authoritative_events => {},},);
  ok !$not_array->{valid}, 'permission derivation with non-array events is rejected';
  is $not_array->{reason}, 'authoritative_events must be an array', 'reason identifies the invalid events value';

  my $bad_actor = $adapter->derive(%permission_args, input => {%input, actor_pubkey => 'not-hex',},);
  ok !$bad_actor->{valid}, 'permission derivation without a valid actor pubkey is rejected';
  is $bad_actor->{reason}, 'actor_pubkey is required', 'reason identifies the missing actor pubkey';

  my $no_events = $adapter->derive(%permission_args, input => {%input, authoritative_events => [],},);
  ok !$no_events->{valid}, 'permission derivation without authoritative state is rejected';
  is $no_events->{reason}, 'authoritative state unavailable', 'reason identifies the missing authoritative state';

  my $bad_view =
    $adapter->derive(%permission_args, input => {%input, authoritative_events => ['not-an-object'],},);
  ok !$bad_view->{valid}, 'permission derivation propagates authoritative view failures';
  like $bad_view->{reason}, qr/\Aauthoritative\sevents\smust\sbe\sobjects/msx,
    'reason identifies the invalid view event';
};

subtest 'authoritative state and view projections propagate context failures' => sub {
  for my $operation (qw(authoritative_channel_state authoritative_ban_list_view authoritative_list_entry_view)) {
    my $result = $adapter->derive(
      operation      => $operation,
      session_config => _authority_config(),
      input          => {
        network              => 'irc.example.test',
        target               => '#overnet',
        authoritative_events => [],
      },
    );
    ok !$result->{valid}, "$operation propagates authoritative view failures";
    is $result->{reason}, 'authoritative_events must be a non-empty array',
      "$operation reports the underlying view failure";
  }
};

subtest 'authoritative mode write permission rejects invalid mode input' => sub {
  my %mode_args = (
    operation      => 'authoritative_mode_write_permission',
    session_config => _authority_config(),
  );
  my %input = (
    network              => 'irc.example.test',
    target               => '#overnet',
    authoritative_events => _operator_events(),
    actor_pubkey         => 'a' x 64,
    mode_args            => [],
  );

  my $no_mode = $adapter->derive(%mode_args, input => {%input, mode_args => [],},);
  ok !$no_mode->{valid}, 'mode write permission without a mode is rejected';
  is $no_mode->{reason}, 'mode is required', 'reason identifies the missing mode';

  my $bad_args = $adapter->derive(%mode_args, input => {%input, mode => '+m', mode_args => {},},);
  ok !$bad_args->{valid}, 'mode write permission with non-array mode_args is rejected';
  is $bad_args->{reason}, 'mode_args must be an array', 'reason identifies the invalid mode_args';

  my $bad_role_target = $adapter->derive(%mode_args, input => {%input, mode => '+o',},);
  ok !$bad_role_target->{valid}, 'role mode writes without a target pubkey are rejected';
  is $bad_role_target->{reason}, 'mode_args[0] target pubkey is required for channel role mode writes',
    'reason identifies the missing role mode target';

  my $bad_list_mask = $adapter->derive(%mode_args, input => {%input, mode => '+e',},);
  ok !$bad_list_mask->{valid}, 'list mode writes without a mask are rejected';
  is $bad_list_mask->{reason}, 'mode_args[0] exception mask is required for channel exception mode writes',
    'reason identifies the missing list mode mask';

  my $bad_key = $adapter->derive(%mode_args, input => {%input, mode => '+k',},);
  ok !$bad_key->{valid}, 'state mode writes without a channel key are rejected';
  is $bad_key->{reason}, 'mode_args[0] channel key is required for +k', 'reason identifies the missing channel key';

  my $bad_limit = $adapter->derive(%mode_args, input => {%input, mode => '+l', mode_args => ['lots'],},);
  ok !$bad_limit->{valid}, 'state mode writes without a valid user limit are rejected';
  is $bad_limit->{reason}, 'mode_args[0] user limit is required for +l', 'reason identifies the invalid user limit';

  my $unsupported = $adapter->derive(%mode_args, input => {%input, mode => '+x',},);
  ok !$unsupported->{valid}, 'unsupported authoritative mode writes are rejected';
  is $unsupported->{reason}, 'unsupported authoritative channel mode write', 'reason identifies the unsupported mode';
};

subtest 'authoritative channel action permission rejects invalid action input' => sub {
  my %action_args = (
    operation      => 'authoritative_channel_action_permission',
    session_config => _authority_config(),
  );
  my %input = (
    network              => 'irc.example.test',
    target               => '#overnet',
    authoritative_events => _operator_events(),
    actor_pubkey         => 'a' x 64,
  );

  my $no_action = $adapter->derive(%action_args, input => \%input,);
  ok !$no_action->{valid}, 'channel action permission without an action is rejected';
  is $no_action->{reason}, 'action is required', 'reason identifies the missing action';

  my $unsupported = $adapter->derive(%action_args, input => {%input, action => 'ban',},);
  ok !$unsupported->{valid}, 'unsupported channel actions are rejected';
  is $unsupported->{reason}, 'unsupported authoritative channel action', 'reason identifies the unsupported action';

  my $no_target = $adapter->derive(%action_args, input => {%input, action => 'kick',},);
  ok !$no_target->{valid}, 'kick actions without a target pubkey are rejected';
  is $no_target->{reason}, 'target_pubkey is required for authoritative channel action',
    'reason identifies the missing action target';
};

subtest 'authoritative snapshots with invalid event pubkeys are rejected, not trusted for group refs' => sub {
  my $result = $adapter->derive(
    operation      => 'authoritative_channel_view',
    session_config => _authority_config(),
    input          => {
      network              => 'irc.example.test',
      target               => '#overnet',
      authoritative_events => [
        {
          kind       => 39_000,
          pubkey     => 'not-a-valid-pubkey',
          created_at => 1_744_301_200,
          content    => '',
          tags       => [['d', 'overnet'],],
        },
      ],
    },
  );

  ok !$result->{valid}, 'an authoritative event with an invalid pubkey is rejected';
  like $result->{reason}, qr/\Aauthoritative\sevents\smust\sbe\svalid\sNostr\sevents/msx,
    'the invalid pubkey is reported as an invalid authoritative event';
};

subtest 'an explicitly supplied overnet_version is preserved even when falsy' => sub {
  my $versioned = Overnet::Adapter::IRC->new(overnet_version => '0');
  my $result    = $versioned->map_input(
    command    => 'PRIVMSG',
    network    => 'irc.example.test',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'hi',
    created_at => 10,
  );

  ok $result->{valid}, 'the message maps successfully';
  my ($version_tag) = grep { $_->[0] eq 'overnet_v' } @{$result->{event}{tags}};
  is $version_tag->[1], '0',
    'a defined but falsy overnet_version is kept, not replaced with the default';
};

subtest 'a defined but falsy session_state is defaulted to an empty hashref' => sub {
  my $adapter_zero = Overnet::Adapter::IRC->new(session_state => 0);
  is ref($adapter_zero->session_state), 'HASH',
    'session_state => 0 is coerced to an empty hashref, not kept as a falsy scalar';

  my $opened = $adapter_zero->open_session(
    adapter_session_id => 'session-falsy',
    session_config     => {},
  );
  ok $opened, 'open_session works because the falsy session_state became a usable hashref';
};

subtest 'a non-authoritative KICK omits the reason body field for empty text' => sub {
  my %kick = (
    command     => 'KICK',
    network     => 'irc.example.test',
    target      => '#overnet',
    nick        => 'alice',
    target_nick => 'bob',
    created_at  => 1_744_301_000,
  );

  my $empty = $adapter->map_input(%kick, text => q{});
  ok $empty->{valid}, 'KICK with empty reason text is accepted';
  my $empty_body = JSON::decode_json($empty->{event}{content})->{body};
  ok !exists $empty_body->{reason},
    'an empty reason text produces no reason field (defined-and-length guard, not defined-or-length)';

  my $reasoned = $adapter->map_input(%kick, text => 'because');
  my $reasoned_body = JSON::decode_json($reasoned->{event}{content})->{body};
  is $reasoned_body->{reason}, 'because', 'a non-empty reason text is carried in the body';
};

done_testing;
