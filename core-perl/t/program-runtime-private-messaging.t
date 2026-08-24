use strictures 2;
use Test::More;
use JSON ();

use Net::Nostr::DirectMessage;
use Net::Nostr::Key;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

sub _structured_error (&) {
  my ($code) = @_;
  my $error;
  eval {
    $code->();
    1;
  } or $error = $@;
  return $error;
}

sub _private_message_candidate {
  my (%args) = @_;

  my $sender_key    = $args{sender_key}    || Net::Nostr::Key->new;
  my $recipient_key = $args{recipient_key} || Net::Nostr::Key->new;
  my $private_type  = $args{private_type}  || 'chat.dm_message';
  my $object_id     = $args{object_id}     || 'irc:local:dm:bob';
  my $text          = exists $args{text} ? $args{text} : 'hello in private';
  my $provenance =
    exists $args{provenance}
    ? $args{provenance}
    : {
    type              => 'adapted',
    protocol          => 'irc',
    origin            => 'local/bob',
    external_identity => 'alice',
    limitations       => ['unsigned'],
    };

  my $payload = {
    overnet_v    => '0.1.0',
    private_type => $private_type,
    object_type  => 'chat.dm',
    object_id    => $object_id,
    provenance   => $provenance,
    body         => {
      text => $text,
    },
  };

  my $rumor = Net::Nostr::DirectMessage->create(
    sender_pubkey => $sender_key->pubkey_hex,
    content       => JSON::encode_json($payload),
    recipients    => [$recipient_key->pubkey_hex],
  );
  my ($wrap) = Net::Nostr::DirectMessage->wrap_for_recipients(
    rumor       => $rumor,
    sender_key  => $sender_key,
    skip_sender => 1,
  );

  return {
    transport => {
      %{$wrap->to_hash}, decrypted_rumor => $rumor->to_hash,
    },
  };
}

sub _opaque_private_message_candidate {
  my (%args) = @_;

  my $sender_key    = $args{sender_key}    || Net::Nostr::Key->new;
  my $recipient_key = $args{recipient_key} || Net::Nostr::Key->new;
  my $private_type  = $args{private_type}  || 'chat.dm_message';
  my $object_id     = $args{object_id}     || 'irc:local:dm:bob';
  my $text          = exists $args{text} ? $args{text} : 'opaque hello';

  my $payload = {
    overnet_v    => '0.1.0',
    private_type => $private_type,
    object_type  => 'chat.dm',
    object_id    => $object_id,
    provenance   => {
      type              => 'adapted',
      protocol          => 'irc',
      origin            => 'local/bob',
      external_identity => 'alice',
      limitations       => ['unsigned'],
    },
    body => {
      text => $text,
    },
  };

  my $rumor = Net::Nostr::DirectMessage->create(
    sender_pubkey => $sender_key->pubkey_hex,
    content       => JSON::encode_json($payload),
    recipients    => [$recipient_key->pubkey_hex],
  );
  my ($wrap) = Net::Nostr::DirectMessage->wrap_for_recipients(
    rumor       => $rumor,
    sender_key  => $sender_key,
    skip_sender => 1,
  );

  return {
    source => {
      protocol => 'irc',
      network  => 'local',
      line     => ':alice PRIVMSG bob :+overnet-e2ee-v1 opaque',
    },
    private_type    => $private_type,
    object_type     => 'chat.dm',
    object_id       => $object_id,
    sender_identity => 'alice',
    transport       => $wrap->to_hash,
  };
}

subtest 'services accept encrypted private messages and deliver matching subscription notifications' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $open = $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'dm-bob',
      query           => {
        kind        => 1059,
        overnet_et  => 'chat.dm_message',
        overnet_ot  => 'chat.dm',
        overnet_oid => 'irc:local:dm:bob',
      },
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-1',
  );
  is $open->{subscription_id}, 'dm-bob', 'private-message subscription opens';

  my $candidate = _private_message_candidate();
  my $result    = $services->dispatch_request(
    'overnet.emit_private_message',
    {message => $candidate},
    permissions => ['overnet.emit_private_message'],
  );

  is $result->{accepted}, JSON::true, 'private message is accepted';
  like $result->{event_id}, qr/\A[0-9a-f]{64}\z/mx, 'accepted private message returns visible wrap event id';
  like $result->{rumor_id}, qr/\A[0-9a-f]{64}\z/mx, 'accepted private message returns rumor id';

  my $emitted = $runtime->emitted_items;
  is scalar @{$emitted},                1,                  'runtime records one emitted private message';
  is $emitted->[0]{item_type},          'private_message',  'runtime stores private message item type';
  is $emitted->[0]{data}{private_type}, 'chat.dm_message',  'stored private message keeps logical type';
  is $emitted->[0]{data}{object_type},  'chat.dm',          'stored private message keeps logical object type';
  is $emitted->[0]{data}{object_id},    'irc:local:dm:bob', 'stored private message keeps logical object id';

  my $notifications = $runtime->drain_runtime_notifications('session-1');
  is scalar @{$notifications}, 1, 'matching subscription receives one runtime notification';
  is $notifications->[0]{method}, 'runtime.subscription_event',
    'private message notification uses runtime.subscription_event';
  is $notifications->[0]{params}{item_type}, 'private_message', 'notification item_type is private_message';
  is $notifications->[0]{params}{data}{private_type}, 'chat.dm_message',
    'notification data includes logical private type';
  is $notifications->[0]{params}{data}{decrypted_rumor}{content}{body}{text},
    'hello in private',
    'notification data preserves decrypted body text';
};

subtest 'services reject relay-carried private intent encoded as a public core event' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error = _structured_error {
    $services->dispatch_request(
      'overnet.emit_private_message',
      {
        message => {
          relay_carried_private_intent => JSON::true,
          event                        => {
            kind => 7800,
            tags =>
              [['overnet_et', 'chat.dm_message'], ['overnet_ot', 'chat.dm'], ['overnet_oid', 'irc:local:dm:bob'],],
            content => '{"body":{"text":"hello"}}',
          },
        },
      },
      permissions => ['overnet.emit_private_message'],
    );
  };
  is ref($error),    'HASH',                      'invalid private-message fallback error is structured';
  is $error->{code}, 'runtime.validation_failed', 'public-event fallback is a validation failure';
  like $error->{details}{errors}[0], qr/NIP-17/mx, 'validation explains that NIP-17 transport is required';
};

subtest 'services enforce overnet.emit_private_message permission' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error = _structured_error {
    $services->dispatch_request(
      'overnet.emit_private_message',
      {message => _private_message_candidate()},
      permissions => [],
    );
  };
  is ref($error),    'HASH',                      'permission error is structured';
  is $error->{code}, 'runtime.permission_denied', 'private-message emission requires permission';
  is $error->{details}{required_permission}, 'overnet.emit_private_message',
    'required private-message emission permission is reported';
};

subtest 'services accept opaque endpoint-blind private messages without decrypted_rumor' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $open = $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'dm-bob-opaque',
      query           => {
        kind        => 1059,
        overnet_et  => 'chat.dm_message',
        overnet_ot  => 'chat.dm',
        overnet_oid => 'irc:local:dm:bob',
      },
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-opaque',
  );
  is $open->{subscription_id}, 'dm-bob-opaque', 'opaque private-message subscription opens';

  my $candidate = _opaque_private_message_candidate();
  my $result    = $services->dispatch_request(
    'overnet.emit_private_message',
    {message => $candidate},
    permissions => ['overnet.emit_private_message'],
  );

  is $result->{accepted}, JSON::true, 'opaque private message is accepted';
  like $result->{event_id}, qr/\A[0-9a-f]{64}\z/mx, 'opaque private message returns visible wrap event id';
  ok !exists($result->{rumor_id}), 'opaque private message does not return a rumor id';

  my $emitted = $runtime->emitted_items;
  is scalar @{$emitted},                   1,                  'runtime records one opaque private message';
  is $emitted->[0]{item_type},             'private_message',  'runtime stores opaque private message item type';
  is $emitted->[0]{data}{private_type},    'chat.dm_message',  'opaque private message keeps logical type';
  is $emitted->[0]{data}{object_type},     'chat.dm',          'opaque private message keeps logical object type';
  is $emitted->[0]{data}{object_id},       'irc:local:dm:bob', 'opaque private message keeps logical object id';
  is $emitted->[0]{data}{sender_identity}, 'alice',            'opaque private message keeps sender identity metadata';
  ok !exists($emitted->[0]{data}{decrypted_rumor}), 'opaque private message does not expose decrypted_rumor';

  my $notifications = $runtime->drain_runtime_notifications('session-opaque');
  is scalar @{$notifications}, 1, 'matching subscription receives one opaque private-message notification';
  is $notifications->[0]{params}{item_type}, 'private_message',   'notification item_type stays private_message';
  is $notifications->[0]{params}{data}{sender_identity}, 'alice', 'notification preserves sender identity metadata';
  ok !exists($notifications->[0]{params}{data}{decrypted_rumor}),
    'notification does not include decrypted rumor for opaque messages';
};

done_testing;
