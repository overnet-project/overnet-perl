use strictures 2;
use Test2::V0;
use JSON ();
use Overnet::Auth::Agent;
use Overnet::Auth::Exchange;
use Overnet::Core::Nostr;

my $key = Overnet::Core::Nostr->load_key(privkey => '1' x 64);
my $now = 2_000_000_000;
my $agent = Overnet::Auth::Agent->new(
  identities => [{identity_id => 'alice', backend_config => {secret => '1' x 64},
    public_identity => {scheme => 'nostr.pubkey', value => $key->pubkey_hex}}],
  allow_unattended_autoapprove => 1,
  clock => sub { $now },
);
my $admin = {admin => 1, program_id => 'admin'};
my $alice = {program_id => 'app.alice'};
my $bob = {program_id => 'app.bob'};
sub request {
  my ($method, $params) = @_;
  return {type => 'request', id => 'audit', method => $method, params => $params || {}};
}
sub authorize {
  return request('sessions.authorize', {
    program_id => 'app.alice', identity_id => 'alice',
    service => {locators => ['irc://example.test/overnet']},
    %{Overnet::Auth::Exchange->authentication_request(
      scope => 'irc://example.test/overnet', challenge => 'challenge')},
    @_,
  });
}
subtest 'request content cannot authenticate a caller or authorize administration' => sub {
  for my $method (qw(policies.list policies.grant policies.revoke service_pins.list service_pins.set service_pins.forget sessions.list)) {
    my $message = request($method, {caller => $admin, admin => JSON::true});
    $message->{caller} = $message->{_caller} = $admin;
    is $agent->dispatch($message)->{error}{code}, 'auth.policy_denied', $method;
  }
  is $agent->dispatch(authorize(interactive => JSON::true))->{error}{code},
    'auth.policy_denied', 'operator autoapproval does not authenticate callers';
  is $agent->dispatch(authorize(), caller => $bob)->{error}{code},
    'auth.policy_denied', 'bound program cannot claim another program';
  ok $agent->dispatch(request('agent.info'))->{ok}, 'discovery remains available';
};
my $session;
subtest 'sessions belong to the bound program' => sub {
  my $result = $agent->dispatch(authorize(), caller => $alice);
  ok $result->{ok}, 'authenticated program can use operator approval';
  $session = $result->{result}{session_handle};
  ok $session, 'bound caller receives a handle';
  my $listed = $agent->dispatch(request('sessions.list'), caller => $bob);
  is $listed->{result}{sessions}, [], 'other program cannot enumerate it';
  for my $method (qw(sessions.renew sessions.revoke)) {
    is $agent->dispatch(request($method, {session_handle => $session}), caller => $bob)->{error}{code},
      'auth.policy_denied', "$method cannot use a known foreign handle";
  }
  is scalar @{$agent->dispatch(request('sessions.list'), caller => $alice)->{result}{sessions}},
    1, 'failed foreign revocation changed nothing';
};
subtest 'a missing service identity cannot downgrade an existing pin' => sub {
  ok $agent->dispatch(request('service_pins.set', {
    locator => 'irc://example.test/overnet', service_identity => {scheme => 'nostr.pubkey', value => 'a' x 64},
  }), caller => $admin)->{ok}, 'trusted administrator pins the service';
  is $agent->dispatch(authorize(), caller => $alice)->{error}{code},
    'auth.service_identity_mismatch', 'omitting an established identity fails closed';
};
subtest 'session expiry is enforced independently of the current policy' => sub {
  ok $agent->dispatch(request('service_pins.forget', {locator => 'irc://example.test/overnet'}), caller => $admin)->{ok};
  ok $agent->dispatch(request('policies.grant', {policy => {
    identity_id => 'alice', program_id => 'app.alice', scope => 'irc://example.test/overnet',
    action => 'session.authenticate', locators => ['irc://example.test/overnet'],
  }}), caller => $admin)->{ok};
  my $listed = $agent->dispatch(request('sessions.list'), caller => $alice)->{result}{sessions}[0];
  ok defined $listed->{expires_at}, 'every session has an expiry';
  $now = $listed->{expires_at} // $now + 86_400;
  is $agent->dispatch(request('sessions.renew', {session_handle => $session,
    challenge => {value => 'new'}}), caller => $alice)->{error}{code},
    'auth.policy_denied', 'expiry is exclusive even with a matching policy';
};
subtest 'invalid saved trust data cannot be silently downgraded' => sub {
  like dies { Overnet::Auth::Agent->new(service_pins => {'irc://pinned' => 'broken'}) },
    qr/invalid stored service pin/, 'an unreadable pin prevents startup';
  my $policy = {identity_id => 'alice', program_id => 'app.alice', scope => 'scope',
    action => 'session.authenticate', locators => ['irc://pinned'], service_identity => []};
  like dies { Overnet::Auth::Agent->new(policies => [$policy]) },
    qr/invalid stored auth policy/, 'a broken identity-bound policy cannot become locator-only';
  is $agent->dispatch(request('policies.grant', {policy => $policy}), caller => $admin)->{error}{code},
    'protocol.invalid_params', 'new malformed policies also fail closed';
};

subtest 'backend identity must match the approved public identity' => sub {
  my $mismatch = Overnet::Auth::Agent->new(
    identities => [{identity_id => 'alice', backend_config => {secret => '2' x 64},
      public_identity => {scheme => 'nostr.pubkey', value => $key->pubkey_hex}}],
    allow_unattended_autoapprove => 1,
  );
  is $mismatch->dispatch(authorize(), caller => $alice)->{error}{code},
    'auth.backend_unavailable', 'a substituted backend key cannot sign as the selected identity';
};

subtest 'session requests preserve declared JSON parameter types' => sub {
  for my $override (
    {scope => 42}, {service => {locators => [42]}},
    {service => {locators => ['irc://test'], service_identity => {scheme => 4, value => 'value'}}},
    {service => {locators => ['irc://test'], service_identity => {scheme => 'scheme', value => 4}}},
    {interactive => 0}, {identity_id => 42}, {identity_id => undef},
    {challenge => []}, {bridge_context => []},
  ) {
    is $agent->dispatch(authorize(%{$override}), caller => $alice)->{error}{code},
      'protocol.invalid_params', 'malformed typed fields cannot authorize a session';
  }
  for my $override ({interactive => 0}, {challenge => []}, {bridge_context => undef}) {
    is $agent->dispatch(request('sessions.renew', {session_handle => $session, %{$override}}), caller => $alice)->{error}{code},
      'protocol.invalid_params', 'renewal applies the same optional field types';
  }
  ok $agent->dispatch(authorize(interactive => JSON::false, bridge_context => {}), caller => $alice)->{ok},
    'valid optional values continue to work with explicit operator approval';
};

subtest 'session listings encode expiry as a number and renewable as a boolean' => sub {
  my $grant = Overnet::Auth::Exchange->delegation_request(
    scope => 'irc://example.test/overnet', relay_url => 'ws://relay.test',
    delegate_pubkey => 'd' x 64, session_id => 'remote', expires_at => $now + 30);
  my $reply = $agent->dispatch(authorize(%{$grant}), caller => $alice);
  ok $reply->{ok}, 'short-lived delegation is approved';
  my $sessions = $agent->dispatch(request('sessions.list'), caller => $alice)->{result}{sessions};
  my ($listed) = grep { $_->{session_handle}{id} eq $reply->{result}{session_handle}{id} } @{$sessions};
  is JSON::encode_json($listed->{expires_at}), q{} . ($now + 30), 'a tag string becomes a numeric descriptor expiry';
  is JSON::encode_json($listed->{renewable}), 'true', 'renewable is a JSON boolean';
};

done_testing;
