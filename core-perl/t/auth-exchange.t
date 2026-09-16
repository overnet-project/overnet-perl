use strictures 2;
use Test2::V0;

use Overnet::Auth::Agent;
use Overnet::Auth::Exchange;
use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;

my $scope        = 'https://lists.example.test/family';
my $relay_url    = 'wss://authority.example.test';
my $challenge    = 'list-session-challenge';
my $user_key     = Overnet::Core::Nostr->load_key(privkey => '1' x 64);
my $delegate_key = Overnet::Core::Nostr->load_key(privkey => '2' x 64);
my %delegation   = (
  relay_url       => $relay_url,
  grant_kind      => 14_142,
  delegate_pubkey => $delegate_key->pubkey_hex,
  session_id      => 'list-session',
  expires_at      => time() + 3_600,
);

subtest 'a non-IRC application completes the shared exchange through the auth agent' => sub {
  my $agent = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [
      {
        identity_id     => 'default',
        backend_type    => 'direct_secret',
        backend_config  => {secret => '1' x 64},
        public_identity => {scheme => 'nostr.pubkey', value => $user_key->pubkey_hex},
      },
    ],
  );
  my $payload = Overnet::Auth::Exchange->challenge_payload(
    challenge  => $challenge,
    scope      => $scope,
    delegation => {%delegation, key => $delegate_key, scope => 'unrelated'},
  );
  is $payload, {challenge => $challenge, scope => $scope, %delegation},
    'only the public delegation fields enter the challenge';
  my $parsed = Overnet::Auth::Exchange->parse_challenge($payload);
  ok $parsed->{delegation_required}, 'the challenge requests delegation';
  is $parsed->{delegation}, \%delegation, 'delegation parameters survive parsing';

  my @requests = (
    Overnet::Auth::Exchange->authentication_request(%{$parsed}),
    Overnet::Auth::Exchange->delegation_request(scope => $parsed->{scope}, %{$parsed->{delegation}}),
  );
  my @events;
  for my $request (@requests) {
    my $reply = $agent->dispatch(
      {
        type   => 'request',
        id     => $request->{action},
        method => 'sessions.authorize',
        params => {
          program_id  => 'shared-list',
          identity_id => 'default',
          service     => {locators => [$relay_url]},
          %{$request},
        },
      },
      caller => {program_id => 'shared-list'},
    );
    ok $reply->{ok}, 'the agent accepts ' . $request->{action};
    push @events, $reply->{result}{artifacts}[0]{value};
  }
  my $response = Overnet::Auth::Exchange->response_payload(auth_event => $events[0], delegate_event => $events[1]);
  is $response, {auth_event => $events[0], delegate_event => $events[1]},
    'the combined response preserves both signed events';

  my $auth = Overnet::Authority::Delegation->verify_auth_event(
    challenge => $challenge,
    scope     => $scope,
    event     => $response->{auth_event},
  );
  ok $auth->{valid}, 'the service verifies the identity proof';
  is $auth->{pubkey}, $user_key->pubkey_hex, 'the proof identifies the user';
  my $grant = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $auth->{pubkey},
    scope            => $scope,
    %delegation,
    kind  => $delegation{grant_kind},
    event => $response->{delegate_event},
  );
  ok $grant->{valid}, 'the service verifies the separate delegation grant';
  ok !Overnet::Authority::Delegation->verify_auth_event(
    challenge => $challenge,
    scope     => 'https://other.example.test',
    event     => $response->{auth_event},
  )->{valid}, 'another service scope cannot reuse the identity proof';
  ok !Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $auth->{pubkey},
    scope            => $scope,
    %delegation,
    session_id => 'another-session',
    event      => $response->{delegate_event},
  )->{valid}, 'another session cannot reuse the grant';
};

subtest 'sign-in can proceed without delegation' => sub {
  my $payload = Overnet::Auth::Exchange->challenge_payload(challenge => $challenge, scope => $scope);
  my $parsed  = Overnet::Auth::Exchange->parse_challenge($payload);
  is $parsed->{delegation_required}, 0,     'no delegation is requested';
  is $parsed->{delegation},          undef, 'no grant parameters are invented';
  my $event = Overnet::Authority::Delegation->create_auth_event(
    key       => $user_key,
    challenge => $challenge,
    scope     => $scope,
  );
  my $response = Overnet::Auth::Exchange->response_payload(auth_event => $event);
  is $response, {auth_event => $event}, 'the response contains only the signed authentication event';
};

subtest 'malformed challenges cannot silently lose their delegation requirement' => sub {
  for my $payload (
    undef, [], q{}, {},
    {challenge => $challenge},
    {scope     => $scope},
    {challenge => [],         scope => $scope},
    {challenge => $challenge, scope => []}
  ) {
    my $parsed = Overnet::Auth::Exchange->parse_challenge($payload);
    is $parsed, undef, 'an unusable auth challenge is rejected';
  }
  for my $field (sort keys %delegation) {
    for my $value (undef, q{}, []) {
      my $parsed = Overnet::Auth::Exchange->parse_challenge(
        {challenge => $challenge, scope => $scope, %delegation, $field => $value},);
      ok $parsed->{delegation_required}, "$field cannot turn off delegation";
      is $parsed->{delegation}, undef, "$field must be a nonempty scalar";
    }
    my %partial = %delegation;
    delete $partial{$field};
    my $parsed = Overnet::Auth::Exchange->parse_challenge({challenge => $challenge, scope => $scope, %partial});
    ok $parsed->{delegation_required}, "a missing $field cannot turn off delegation";
    is $parsed->{delegation}, undef, "a missing $field leaves an incomplete grant";
  }
};

subtest 'request builders preserve the default grant kind and optional IRC nickname' => sub {
  my %params = (%delegation, scope => $scope, nick => 'alice');
  delete $params{grant_kind};
  my $request = Overnet::Auth::Exchange->delegation_request(%params);
  is $request->{artifacts}[0]{params}{kind},     14_142,            'the existing grant kind is the default';
  is $request->{artifacts}[0]{params}{tags}[-1], [nick => 'alice'], 'the IRC nickname remains an optional tag';
};

done_testing;
