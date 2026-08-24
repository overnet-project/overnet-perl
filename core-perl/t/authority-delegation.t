use strictures 2;
use Test2::V0;

use Net::Nostr::Key;
use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;

subtest 'create_auth_event builds a verifiable kind 22242 auth event' => sub {
  my $key        = Overnet::Core::Nostr->generate_key;
  my $challenge  = 'c' x 64;
  my $scope      = 'irc://irc.example.test/overnet';
  my $created_at = 1_744_301_000;

  my $event = Overnet::Authority::Delegation->create_auth_event(
    key        => $key,
    challenge  => $challenge,
    scope      => $scope,
    created_at => $created_at,
  );

  is $event->{kind},       22242,       'the auth event uses kind 22242';
  is $event->{created_at}, $created_at, 'the auth event preserves the requested timestamp';
  is $event->{content},    '',          'the auth event uses an empty content payload';
  is $event->{tags},
    [[relay => $scope], [challenge => $challenge],],
    'the auth event includes the required relay scope and challenge tags';
  like $event->{id},  qr/\A[0-9a-f]{64}\z/mx,  'the auth event is signed';
  like $event->{sig}, qr/\A[0-9a-f]{128}\z/mx, 'the auth event includes a Schnorr signature';

  my $verification = Overnet::Authority::Delegation->verify_auth_event(
    challenge => $challenge,
    scope     => $scope,
    event     => $event,
  );

  ok $verification->{valid}, 'the generated auth event verifies';
  is $verification->{pubkey}, $key->pubkey_hex, 'the generated auth event preserves the signing pubkey';
};

subtest 'create_delegation_grant_event builds a verifiable kind 14142 delegation grant' => sub {
  my $key             = Overnet::Core::Nostr->generate_key;
  my $relay_url       = 'ws://127.0.0.1:7448';
  my $scope           = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = 'd' x 64;
  my $session_id      = 'session-123';
  my $expires_at      = 1_744_304_600;
  my $created_at      = 1_744_301_100;

  my $event = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $relay_url,
    scope           => $scope,
    delegate_pubkey => $delegate_pubkey,
    session_id      => $session_id,
    expires_at      => $expires_at,
    created_at      => $created_at,
    nick            => 'alice',
  );

  is $event->{kind},       14142,       'the delegation grant uses the default kind 14142';
  is $event->{created_at}, $created_at, 'the delegation grant preserves the requested timestamp';
  is $event->{content},    '',          'the delegation grant uses an empty content payload';
  is $event->{tags},
    [
    [relay      => $relay_url],
    [server     => $scope],
    [delegate   => $delegate_pubkey],
    [session    => $session_id],
    [expires_at => $expires_at],
    [nick       => 'alice'],
    ],
    'the delegation grant includes the required relay, scope, delegate, session, and expiration tags';
  like $event->{id},  qr/\A[0-9a-f]{64}\z/mx,  'the delegation grant is signed';
  like $event->{sig}, qr/\A[0-9a-f]{128}\z/mx, 'the delegation grant includes a Schnorr signature';

  my $verification = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $key->pubkey_hex,
    relay_url        => $relay_url,
    scope            => $scope,
    delegate_pubkey  => $delegate_pubkey,
    session_id       => $session_id,
    expires_at       => $expires_at,
    event            => $event,
  );

  ok $verification->{valid}, 'the generated delegation grant verifies';
  is $verification->{pubkey}, $key->pubkey_hex, 'the generated delegation grant preserves the signing pubkey';
};

subtest 'auth event creation and verification reject invalid inputs' => sub {
  my $key = Overnet::Core::Nostr->generate_key;

  like dies { Overnet::Authority::Delegation->create_auth_event(key => 'junk') },
    qr/key must be an Overnet::Core::Nostr::Key instance/, 'unwrapped keys croak';

  my $create = sub {
    return Overnet::Authority::Delegation->create_auth_event(key => $key, @_);
  };
  is $create->(scope => 's')->{reason}, 'challenge is required', 'a challenge is required';
  is $create->(challenge => 'c', scope => [])->{reason}, 'scope is required', 'a scalar scope is required';
  is $create->(challenge => 'c', scope => 's', created_at => undef)->{reason},
    'created_at is required', 'an explicit undef created_at is refused';
  ok $create->(challenge => 'c', scope => 's')->{created_at}, 'created_at defaults to now';

  my $event  = $create->(challenge => 'c' x 64, scope => 'irc://net/scope');
  my $verify = sub {
    my (%override) = @_;
    return Overnet::Authority::Delegation->verify_auth_event(
      challenge => 'c' x 64,
      scope     => 'irc://net/scope',
      event     => $event,
      %override,
    );
  };
  is $verify->(challenge => q{})->{reason}, 'challenge is required',   'verification requires a challenge';
  is $verify->(scope => undef)->{reason},   'scope is required',       'verification requires a scope';
  is $verify->(event => 'junk')->{reason},  'event must be an object', 'events must be hashes';
  is $verify->(event => {kind => 22_242})->{reason},
    'event must be a valid signed Nostr event', 'unsigned events are refused';

  my $wrong_kind = $key->sign_event_hash(
    event =>
      {kind => 1, created_at => 1, tags => [['relay', 'irc://net/scope'], ['challenge', 'c' x 64]], content => q{}},
  );
  is $verify->(event => $wrong_kind)->{reason}, 'auth event requires kind 22242', 'wrong kinds are refused';

  my $wrong_challenge = $key->sign_event_hash(
    event =>
      {kind => 22_242, created_at => 1, tags => [['relay', 'irc://net/scope'], ['challenge', 'x']], content => q{}},
  );
  is $verify->(event => $wrong_challenge)->{reason},
    'auth event challenge does not match', 'foreign challenges are refused';

  my $wrong_scope = $key->sign_event_hash(
    event => {kind => 22_242, created_at => 1, tags => [['challenge', 'c' x 64]], content => q{}},
  );
  is $verify->(event => $wrong_scope)->{reason},
    'auth event relay scope does not match', 'missing relay scopes are refused';
};

subtest 'delegation grants validate every field' => sub {
  my $key  = Overnet::Core::Nostr->generate_key;
  my %base = (
    relay_url       => 'ws://127.0.0.1:1',
    scope           => 'irc://net/scope',
    delegate_pubkey => 'd' x 64,
    session_id      => 'session-1',
    expires_at      => 100,
    created_at      => 50,
  );

  my $create = sub {
    my (%override) = @_;
    return Overnet::Authority::Delegation->create_delegation_grant_event(key => $key, %base, %override);
  };

  is $create->(relay_url => q{})->{reason}, 'relay_url is required', 'relay_url is validated';
  is $create->(scope => undef)->{reason},   'scope is required',     'scope is validated';
  is $create->(delegate_pubkey => 'D' x 64)->{reason}, 'delegate_pubkey is required',
    'delegate pubkeys must be lowercase hex';
  is $create->(session_id => [])->{reason},      'session_id is required',          'session_id is validated';
  is $create->(expires_at => 'later')->{reason}, 'expires_at is required',          'expires_at must be digits';
  is $create->(kind => 0)->{reason},             'kind must be a positive integer', 'kind is validated';
  is $create->(created_at => undef)->{reason},   'created_at is required',          'created_at is validated';
  is $create->(nick => q{})->{reason}, 'nick must be a non-empty string', 'empty nicks are refused';
  is $create->(nick => {})->{reason},  'nick must be a non-empty string', 'reference nicks are refused';

  my $nickless = $create->(kind => 14_143);
  is $nickless->{kind}, 14_143, 'a custom kind is applied';
  is scalar(grep { ref($_) eq 'ARRAY' && $_->[0] eq 'nick' } @{$nickless->{tags}}), 0, 'nick tags are optional';
  ok $create->()->{id}, 'the default grant signs';

  my $grant  = $create->();
  my $verify = sub {
    my (%override) = @_;
    return Overnet::Authority::Delegation->verify_delegation_grant(
      authority_pubkey => $key->pubkey_hex,
      %base,
      event => $grant,
      %override,
    );
  };

  is $verify->(authority_pubkey => 'nope')->{reason}, 'authority_pubkey is required',
    'the authority pubkey is validated first';
  is $verify->(event => [])->{reason}, 'event must be an object', 'events must be hashes';
  is $verify->(kind => 14_143)->{reason},
    'delegation event uses the wrong event kind', 'kind mismatches are refused';
  is $verify->(authority_pubkey => 'e' x 64)->{reason},
    'delegation event pubkey does not match the authenticated user', 'foreign signers are refused';
  is $verify->(relay_url => 'ws://other:1')->{reason},
    'delegation event relay does not match', 'relay mismatches are refused';
  is $verify->(scope => 'irc://other/scope')->{reason},
    'delegation event server scope does not match', 'scope mismatches are refused';
  is $verify->(delegate_pubkey => 'e' x 64)->{reason},
    'delegation event delegate pubkey does not match', 'delegate mismatches are refused';
  is $verify->(session_id => 'session-2')->{reason},
    'delegation event session does not match', 'session mismatches are refused';
  is $verify->(expires_at => 101)->{reason},
    'delegation event expiration does not match', 'expiration mismatches are refused';

  my $verified = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $key->pubkey_hex,
    %base,
    event => $grant,
  );
  ok $verified->{valid}, 'a matching grant verifies';
  is $verified->{event_id}, $grant->{id}, 'the verified grant echoes its event id';

  my $duplicate_tags = $key->sign_event_hash(
    event => {
      kind       => 14_142,
      created_at => 50,
      content    => q{},
      tags       => [
        ['relay', 'ws://127.0.0.1:1'],
        ['relay', 'ws://ignored:1'],
        ['short'],
        ['server',     'irc://net/scope'],
        ['delegate',   'd' x 64],
        ['session',    'session-1'],
        ['expires_at', '100'],
      ],
    },
  );
  ok(
    Overnet::Authority::Delegation->verify_delegation_grant(
      authority_pubkey => $key->pubkey_hex,
      %base,
      event => $duplicate_tags,
    )->{valid},
    'duplicate and malformed tags are tolerated with first-value-wins semantics',
  );
};

subtest 'load_key accepts PEM text, raw hex, and nsec secrets' => sub {
  my $net_key = Net::Nostr::Key->new;

  my $pem_key = Overnet::Core::Nostr->load_key(privkey => $net_key->privkey_pem,);
  is $pem_key->pubkey_hex, $net_key->pubkey_hex, 'PEM key text loads correctly';

  my $hex_key = Overnet::Core::Nostr->load_key(privkey => $net_key->privkey_hex,);
  is $hex_key->pubkey_hex, $net_key->pubkey_hex, 'raw hex key text loads correctly';

  my $nsec_key = Overnet::Core::Nostr->load_key(privkey => $net_key->privkey_nsec,);
  is $nsec_key->pubkey_hex, $net_key->pubkey_hex, 'nsec key text loads correctly';
};

done_testing;
