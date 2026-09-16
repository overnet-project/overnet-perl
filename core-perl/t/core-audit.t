use strictures 2;
use Test::More;
use JSON ();
use Overnet::Core::Nostr;
use Overnet::Core::Validator;

my $author = Overnet::Core::Nostr->generate_key;
my $delegate = Overnet::Core::Nostr->generate_key;

sub event {
  my (%args) = @_;
  my $type = $args{type} // 'chat.message';
  my $object = $args{object} // 'channel:A';
  my $object_type = $args{object_type} // 'chat.channel';
  return ($args{key} // $author)->sign_event_hash(event => {
    kind => $args{kind} // 7800,
    created_at => $args{at} // 190,
    content => $args{content} // JSON::encode_json({
      provenance => {type => 'native'}, body => $args{body} // {},
    }),
    tags => [
      ['overnet_v', '0.1.0'], ['v', '0.1.0'],
      ['overnet_et', $type], ['t', $type],
      ['overnet_ot', $object_type], ['o', $object_type],
      ['overnet_oid', $object], ['d', $object], @{$args{extra} // []},
    ],
  });
}

sub removal {
  my ($target, $grant, %args) = @_;
  return event(kind => 7801, type => 'core.removal',
    key => $grant ? $delegate : $author,
    extra => [['e', $target->{id}], $grant ? (['overnet_delegate', $grant->{id}]) : ()],
    %args);
}

subtest 'removal scope and fully validated authorization inputs (core 6.13)' => sub {
  my $target = event();
  my $grant = event(type => 'core.delegation', body => {
    action => 'remove', delegate_pubkey => $delegate->pubkey_hex,
  });
  for my $delegation (undef, $grant) {
    my %context = (target_event => $target, delegation_event => $delegation);
    ok Overnet::Core::Validator::validate(removal($target, $delegation), \%context)->{valid},
      'matching target and grant accepted';
    for my $mismatch ({object => 'channel:B'}, {object_type => 'chat.thread'}) {
      ok !Overnet::Core::Validator::validate(removal($target, $delegation, %{$mismatch}), \%context)->{valid},
        'scope mismatch rejected';
    }
  }
  for my $invalid_target (
    event(kind => 1),
    event(content => '{}'),
    event(extra => [['overnet_ot', 'chat.channel']]),
  ) {
    ok !Overnet::Core::Validator::validate(removal($invalid_target, undef), {
      target_event => $invalid_target,
    })->{valid}, 'a signed but non-core-valid target cannot authorize removal';
  }
  my $bad_grant = event(type => 'core.delegation', extra => [['v', '0.1.0']], body => {
    action => 'remove', delegate_pubkey => $delegate->pubkey_hex,
  });
  ok !Overnet::Core::Validator::validate(removal($target, $bad_grant), {
    target_event => $target, delegation_event => $bad_grant,
  })->{valid}, 'duplicate tags in a signed grant are rejected';
  my $first = removal($target, undef);
  my $second = removal($first, undef);
  ok !Overnet::Core::Validator::validate($second, {target_event => $first})->{valid},
    'removing a removal requires its authorization evidence';
  ok Overnet::Core::Validator::validate($second, {
    target_event => $first, target_context => {target_event => $target},
  })->{valid}, 'a target removal with valid authorization evidence can be removed';
};

subtest 'grant expiry uses receiver time and exact accepted event ID (core 6.13)' => sub {
  my $target = event();
  my $grant = event(type => 'core.delegation', body => {
    action => 'remove', delegate_pubkey => $delegate->pubkey_hex, expires_at => 200,
  });
  my $action = removal($target, $grant);
  my %context = (target_event => $target, delegation_event => $grant);
  for my $case ([199, 1], [200, 0], [201, 0], [undef, 0]) {
    is Overnet::Core::Validator::validate($action, {%context, now => $case->[0]})->{valid},
      $case->[1], 'live admission respects exclusive expiry and clock availability';
  }
  ok !Overnet::Core::Validator::validate(removal($target, $grant, at => 200), {%context, now => 199})->{valid},
    'event timestamp at expiry rejected';
  ok !Overnet::Core::Validator::validate($action, \%context)->{valid},
    'omitting the test clock uses the actual receiver clock';
  for my $case ([$action->{id}, 195, 1], ['f' x 64, 195, 0], [$action->{id}, 200, 0]) {
    is Overnet::Core::Validator::validate($action, {%context, now => 201,
      trusted_acceptance => {event_id => $case->[0], accepted_at => $case->[1]},
    })->{valid}, $case->[2], 'historical verification requires timely evidence for this exact ID';
  }
};

subtest 'authority identifiers are unambiguous (core 6.15)' => sub {
  for my $case (
    ['irc', 'local', 'urn:overnet:adapter-authority:697263:6c6f63616c', 1],
    ['irc', 'a:b', 'urn:overnet:adapter-authority:697263:613a62', 1],
    ['irc:a', 'b', 'urn:overnet:adapter-authority:6972633a61:62', 1],
    ['irc', 'local', 'irc:local', 0],
  ) {
    is Overnet::Core::Validator::validate(event(kind => 37800,
      type => 'core.adapter_authority', object_type => 'core.adapter_authority',
      object => $case->[2], body => {protocol => $case->[0], origin => $case->[1], pubkeys => []},
    ))->{valid}, $case->[3], $case->[2];
  }
};

subtest 'JSON members and Unicode at signed boundaries (core 2.3)' => sub {
  for my $content (
    '{"provenance":{"type":"native"},"body":{},"body":{}}',
    '{"provenance":{"type":"native"},"body":{"x":1,"\\u0078":2}}',
    '{"provenance":{"type":"native"},"body":{"x":"\\ud800"}}',
  ) {
    ok !Overnet::Core::Validator::validate(event(content => $content))->{valid},
      'ambiguous or non-scalar signed JSON is rejected';
  }
  my $valid = event();
  my $wire = JSON::encode_json($valid);
  $wire =~ s/\A\{/{"kind":7800,/;
  ok !Overnet::Core::Validator::validate($wire)->{valid}, 'duplicate envelope members rejected before parsing';
  my $unicode = '{"provenance":{"type":"native"},"body":{"x":"\\ud83d\\ude00"}}';
  ok Overnet::Core::Validator::validate(event(content => $unicode))->{valid}, 'a valid surrogate pair remains valid';
};

subtest 'typed core fields are not coerced into valid data' => sub {
  for my $expiry (undef, '200', JSON::true, [], {}) {
    ok !Overnet::Core::Validator::validate(event(type => 'core.delegation', body => {
      action => 'remove', delegate_pubkey => $delegate->pubkey_hex, expires_at => $expiry,
    }))->{valid}, 'an optional expiry, when present, must be an integer';
  }
  for my $bound (qw(not_before not_after)) {
    ok !Overnet::Core::Validator::validate(event(kind => 37800,
      type => 'core.adapter_authority', object_type => 'core.adapter_authority',
      object => 'urn:overnet:adapter-authority:697263:6c6f63616c',
      body => {protocol => 'irc', origin => 'local', pubkeys => [], $bound => undef},
    ))->{valid}, 'null authority bounds cannot silently remove a validity constraint';
  }
  for my $field (qw(kind created_at)) {
    my $wire = event();
    $wire->{$field} = "$wire->{$field}";
    ok !Overnet::Core::Validator::validate($wire)->{valid}, 'wire numbers must not be strings';
  }
  my $invalid_tag = event(extra => [['custom', 123]]);
  ok !Overnet::Core::Validator::validate($invalid_tag)->{valid}, 'Nostr tag values must be strings';
};

subtest 'base64 JSON exchanges reject alternate encodings and duplicate members' => sub {
  require MIME::Base64;
  my $valid = MIME::Base64::encode_base64('{"ok":true}', q{});
  ok Overnet::Core::JSON::decode_base64_json($valid)->{ok}, 'canonical payload accepted';
  for my $bad ($valid . '!', ' ' . $valid, MIME::Base64::encode_base64('{"ok":true,"ok":false}', q{})) {
    ok !eval { Overnet::Core::JSON::decode_base64_json($bad); 1 }, 'ambiguous payload rejected';
  }
};

done_testing;
