package main;

use strictures 2;
use utf8;

use Carp    qw(croak);
use English qw(-no_match_vars);
use Encode  qw(encode);
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use JSON ();
use Test2::V0;
use Overnet::Core::Naming;
use Overnet::Core::Naming::Verifier;
use Overnet::Core::Nostr;

my $JSON   = JSON->new->utf8->canonical;
my @actors = qw(registrar alice bob host-a host-b other-registrar);
my %keys;
for my $number (1 .. @actors) {
  $keys{$actors[$number - 1]} = Overnet::Core::Nostr->load_key(privkey => sprintf('%064x', $number));
}
my $namespace = {
  namespace_id  => 'ns:' . $keys{registrar}->pubkey_hex,
  normalization => 'irc-rfc1459-v1',
  registrar_url => 'https://registrar.example.test/',
  irc_network   => 'overnet',
};
my $nonce        = 'a' x 64;
my $base_history = _history(3);

sub _test_normalization {
  my $fixture  = _fixture('normalization');
  my %expected = map { $_->{id} => $_ } @{$fixture->{expected}{cases}};
  for my $case (@{$fixture->{input}{cases}}) {
    my $name   = $case->{operation} eq 'normalize_bytes' ? pack('H*', $case->{utf8_hex}) : $case->{name};
    my $result = Overnet::Core::Naming->normalize_name(normalization => $case->{normalization}, name => $name);
    my $want   = $expected{$case->{id}};
    if ($want->{error}) {
      is($result->{outcome}, $want->{error}, $case->{id});
    } else {
      is($result->{name}, $want->{name}, $case->{id});
    }
  }
  my $bytes = encode('UTF-8', 'café');
  is(Overnet::Core::Naming->normalize_name(normalization => 'exact-utf8-v1', name => $bytes)->{name},
    'café', 'bytes decode once');
  ok(Overnet::Core::Naming->normalize_name(normalization => 'exact-utf8-v1', name => chr(0xffff))->{valid},
    'noncharacters are Unicode scalar values');
  for my $invalid (undef, [], 42, "a\x00b", "\x{d800}", "\x{110000}") {
    is(Overnet::Core::Naming->normalize_name(normalization => 'exact-utf8-v1', name => $invalid)->{outcome},
      'invalid', 'invalid exact name');
  }
  my $id = Overnet::Core::Naming->binding_id(%{$namespace}, name => '#Overnet');
  is(
    $id->{binding_id},
    'urn:overnet:name:' . $keys{registrar}->pubkey_hex . ':236f7665726e6574',
    'binding identity encodes canonical bytes'
  );
  is(Overnet::Core::Naming->binding_id(%{$namespace}, namespace_id => 'overnet', name => '#x')->{outcome},
    'untrusted', 'labels are not anchors');
  return;
}

sub _test_records {
  my $request = _request();
  my $commit  = _commit($request);
  for my $event ($request, $commit, _proof($commit)) {
    my $result = _record_result($event);
    ok $result->{valid}, 'valid signed record' or diag $result;
    ok(_record_result($JSON->encode($event))->{valid}, 'JSON wire input is verified');
  }
  my @mutations = (
    ['signature forgery',   sub { $_[0]{sig} = '0' x 128; }],
    ['wrong event ID',      sub { $_[0]{id}  = 'f' x 64; }],
    ['changed content',     sub { $_[0]{content} .= chr 32; }],
    ['missing signature',   sub { delete $_[0]{sig}; }],
    ['asserted validation', sub { $_[0]{signature_valid} = JSON::true; }],
    ['wrong kind',          sub { $_[0]{kind}            = 37_800; }],
    ['string timestamp',    sub { $_[0]{created_at}      = '1000'; }],
    ['boolean timestamp',   sub { $_[0]{created_at}      = JSON::true; }],
    ['numeric tag',         sub { $_[0]{tags}[0][1]      = 1; }],
    ['empty tag',           sub { push @{$_[0]{tags}}, []; }],
  );
  for my $case (@mutations) {
    my $event = _copy($request);
    $case->[1]->($event);
    is(_record_result($event)->{outcome}, 'invalid', $case->[0]);
  }
  for my $input (undef, [], '{}', '{', 'x' x 1_048_577) {
    is(_record_result($input)->{outcome}, 'invalid', 'malformed or oversized event');
  }
  my $duplicate = $JSON->encode($request);
  $duplicate =~ s/\A\{/\{"id":"$request->{id}",/mxs;
  is(_record_result($duplicate)->{outcome}, 'invalid', 'duplicate outer member is rejected');
  for my $content (
    '{"provenance":{"type":"native"},"body":{"version":1,"version":1}}',
    '{"provenance":{"type":"native"},"body":{"version":1,"ver\\u0073ion":1}}',
    '{"provenance":{"type":"native"},"body":{"a":{"x":1,"x":2}}}',
    '{"provenance":{"type":"native"},"body":{"name":"\ud800"}}',
  ) {
    my $event = $keys{alice}->sign_event_hash(event => {%{$request}, content => $content});
    is(_record_result($event)->{outcome}, 'invalid', 'signed duplicate content member is rejected');
  }
  my $noncharacter = JSON->new->canonical->encode({provenance => {type => 'native'}, body => _body($request)});
  $noncharacter =~ s/\}\z/,"extension":"\\uffff"\}/mxs;
  ok(_record_result($keys{alice}->sign_event_hash(event => {%{$request}, content => $noncharacter}))->{valid},
    'escaped noncharacter in signed content does not crash the parser');
  my $duplicate_unicode = JSON->new->canonical->encode({provenance => {type => 'native'}, body => _body($request)});
  $duplicate_unicode =~ s/\}\z/,"é":1,"\\u00e9":2\}/mxs;
  is(_record_result($keys{alice}->sign_event_hash(event => {%{$request}, content => $duplicate_unicode}))->{outcome},
    'invalid', 'literal and escaped Unicode member names collide');
  my $duplicate_request = _copy($request);
  $duplicate_request->{content} =~ s/"version":1/"version":1,"version":1/mxs;
  $duplicate_request = $keys{alice}->sign_event_hash(event => $duplicate_request);
  is(_record_result(_commit($duplicate_request))->{outcome},
    'invalid', 'duplicate members in embedded signed content are rejected');
  my $forged = _copy($request);
  $forged->{sig} = '0' x 128;
  is(_record_result(_commit($forged))->{outcome}, 'invalid',
    'registrar signature cannot bless forged embedded request');
  my $bad_tags = _copy($request);
  push @{$bad_tags->{tags}}, ['t', 'naming.change'];
  is(_record_result($keys{alice}->sign_event_hash(event => $bad_tags))->{outcome}, 'invalid', 'duplicate mirror tag');
  $bad_tags               = _copy($request);
  $bad_tags->{tags}[0][1] = '0.2.0';
  $bad_tags->{tags}[1][1] = '0.2.0';
  is(_record_result($keys{alice}->sign_event_hash(event => $bad_tags))->{outcome},
    'invalid', 'naming pins core version');
  return;
}

sub _test_requests {
  my @cases = (
    ['missing field',            sub { delete $_[0]{name}; }],
    ['unknown field',            sub { $_[0]{override}    = 1; }],
    ['string version',           sub { $_[0]{version}     = '1'; }],
    ['string revision',          sub { $_[0]{revision}    = '1'; }],
    ['zero revision',            sub { $_[0]{revision}    = 0; }],
    ['unsafe integer',           sub { $_[0]{revision}    = 9_007_199_254_740_992; }],
    ['bad request interval',     sub { $_[0]{expires_at}  = 1301; }],
    ['expired before creation',  sub { $_[0]{expires_at}  = 999; }],
    ['unknown state',            sub { $_[0]{status}      = 'pending'; }],
    ['noncanonical name',        sub { $_[0]{name}        = '#Overnet'; }],
    ['empty controllers',        sub { $_[0]{controllers} = []; }],
    ['bad controller key',       sub { $_[0]{controllers} = ['ALICE']; }],
    ['off-curve controller key', sub { $_[0]{controllers} = ['f' x 64]; }],
    ['duplicate controller',     sub { push @{$_[0]{controllers}}, $_[0]{controllers}[0]; }],
    [
      'out-of-order controllers',
      sub {
        $_[0]{controllers} = [reverse sort map { $keys{$_}->pubkey_hex } qw(alice bob)];
      }
    ],
    ['requester not controller',     sub { $_[0]{controllers}       = [$keys{bob}->pubkey_hex]; }],
    ['registration has predecessor', sub { $_[0]{previous}          = 'a' x 64; }],
    ['registration has target',      sub { $_[0]{object_id}         = 'urn:overnet:object:' . ('a' x 64); }],
    ['registration not active',      sub { $_[0]{status}            = 'suspended'; }],
    ['update missing target',        sub { $_[0]{revision}          = 2; $_[0]{previous} = 'a' x 64; }],
    ['authority extra field',        sub { $_[0]{authority}{admin}  = 1; }],
    ['authority invalid key',        sub { $_[0]{authority}{pubkey} = 'x'; }],
    ['duplicate reader',             sub { $_[0]{read_relays}       = ['wss://reader.test/', 'wss://reader.test/']; }],
    ['authority as reader',          sub { $_[0]{read_relays}       = [$_[0]{authority}{relay_url}]; }],
    ['invalid read URL',             sub { $_[0]{read_relays}       = ['file:///tmp/data']; }],
    ['wrong object type',            sub { $_[0]{object_type}       = 'chat.message'; }],
    ['wrong network',                sub { $_[0]{profile_data}{network}           = 'another'; }],
    ['wrong group',                  sub { $_[0]{profile_data}{group_id}          = 'irc-bad'; }],
    ['wrong bootstrap',              sub { $_[0]{profile_data}{bootstrap_pubkey}  = $keys{bob}->pubkey_hex; }],
    ['extra profile field',          sub { $_[0]{profile_data}{operator_override} = 1; }],
  );
  for my $case (@cases) {
    my $body = _body(_request());
    $case->[1]->($body);
    is(_record_result(_event('naming.change', $body, 'alice', 1000))->{outcome}, 'invalid', $case->[0]);
  }
  is(_record_result(_request(body => {profile => 'future.profile'}))->{outcome},
    'unsupported', 'unknown binding profile fails closed');
  my $bad_config = {%{$namespace}, normalization => 'discovered'};
  is(Overnet::Core::Naming->verify_record(namespace => $bad_config, event => _request())->{outcome},
    'unsupported', 'unsupported normalization');
  is(Overnet::Core::Naming->verify_record(event => _request())->{outcome}, 'untrusted', 'no implicit namespace');
  my $wrong_namespace = _request(body => {namespace_id => 'ns:' . $keys{'other-registrar'}->pubkey_hex});
  is(_record_result($wrong_namespace)->{outcome}, 'untrusted', 'same name in another namespace is distinct');
  my $unicode_config = {%{$namespace}, irc_network => 'café'};
  my $unicode        = _request(
    body => {
      profile_data => {
        network          => 'café',
        group_id         => 'irc-636166c3a9-236f7665726e6574',
        bootstrap_pubkey => $keys{alice}->pubkey_hex,
      }
    }
  );
  my $unicode_result = Overnet::Core::Naming->verify_record(namespace => $unicode_config, event => $unicode);
  ok($unicode_result->{valid}, 'IRC network label uses UTF-8 bytes') or diag $JSON->encode($unicode_result);
  return;
}

sub _test_endpoints {
  for my $url (
    'ws://127.0.0.1/',           'wss://HOST.test/',
    'WSS://host.test/',          'wss://host.test:443/',
    'wss://host.test',           'wss://user@host.test/',
    'wss://host.test/#fragment', 'wss://host.test:bad/',
    'wss://host.test:0/',        'wss://host.test:65536/',
    'wss://host.test:0444/',     'wss://host.test/space here',
    'https://host.test/',        'wss://host.test/%zz',
    'wss://host.test/\\path',    'wss://[not-an-ip]/',
    'wss://host.test/<path>',    'wss://::1/',
    'wss://host]/',
  ) {
    is(
      _record_result(_request(body => {authority => {pubkey => $keys{'host-a'}->pubkey_hex, relay_url => $url}}))
        ->{outcome},
      'invalid', $url
    );
  }
  for my $url ('wss://host.test:8443/path?x=%2f', 'wss://[::1]:8443/', 'wss://host.test/?x=%2F') {
    ok(
      _record_result(_request(body => {authority => {pubkey => $keys{'host-a'}->pubkey_hex, relay_url => $url}}))
        ->{valid},
      $url
    );
  }
  my $local = {
    %{$namespace},
    registrar_url        => 'http://127.0.0.1:8080/',
    local_plaintext_urls => ['http://127.0.0.1:8080/', 'ws://127.0.0.1:8081/']
  };
  my $request =
    _request(body => {authority => {pubkey => $keys{'host-a'}->pubkey_hex, relay_url => 'ws://127.0.0.1:8081/'}});
  ok(Overnet::Core::Naming->verify_record(namespace => $local, event => $request)->{valid}, 'exact local exceptions');
  is(
    Overnet::Core::Naming->validate_namespace({%{$namespace}, registrar_url => 'https://registrar.test/?q=x'})
      ->{outcome},
    'invalid',
    'registrar base excludes query'
  );
  return;
}

sub _test_histories {
  my $first      = $base_history->[0];
  my $first_body = _body(_body($first)->{request});
  my $successor  = _next($first);
  my $history    = [$first, $successor];
  ok(_history_result($history)->{valid},                                'controller-authorized successor');
  ok(_history_result([reverse @{$history}], $successor->{id})->{valid}, 'delivery order is irrelevant');
  my $unauthorized =
    _next($first, actor => 'bob', body => {controllers => [sort map { $keys{$_}->pubkey_hex } qw(alice bob)]});
  is(_history_result([$first, $unauthorized])->{code}, 'naming.unauthorized', 'new-controller-cannot-authorize-itself');
  my $handed_over = _next($first, body => {controllers => [$keys{bob}->pubkey_hex]});
  ok(_history_result([$first, $handed_over, _next($handed_over, actor => 'bob')])->{valid},
    'new controller can authorize after valid handover');
  is(_history_result([$first, $handed_over, _next($handed_over)])->{code},
    'naming.unauthorized', 'removed controller loses authority');
  my $new_host = {pubkey => $keys{'host-b'}->pubkey_hex, relay_url => 'wss://host-b.example.test/'};
  is(_history_result([$first, _next($first, body => {authority => $new_host})])->{code},
    'naming.transition_denied', 'direct-active-host-change');
  my $suspended = _next($first,     body => {status => 'suspended'});
  my $moved     = _next($suspended, body => {status => 'active', authority => $new_host});
  ok(_history_result([$first, $suspended, $moved])->{valid}, 'legal recorded transfer preserves target and profile');
  is(_body($moved)->{object_id}, _body($first)->{object_id}, 'target remains stable');
  my $retired = _next($first, body => {status => 'retired'});
  is(_history_result([$first, $retired, _next($retired)])->{code}, 'naming.transition_denied', 'retirement-terminal');

  for my $body (
    {revision     => 3},
    {object_id    => 'urn:overnet:object:' . ('f' x 64)},
    {profile_data => {%{$first_body->{profile_data}}, bootstrap_pubkey => $keys{bob}->pubkey_hex}},
  ) {
    is(_history_result([$first, _next($first, body => $body)])->{outcome},
      'invalid', 'immutable or revision constraints');
  }
  my $early = _next($successor, at => 1000);
  is(_history_result([$first, $successor, $early])->{outcome}, 'invalid', 'commit timestamps cannot move backwards');
  my $request = _request();
  for my $commit (
    _commit($request, at     => 999),
    _commit($request, at     => 1301),
    _commit($request, target => 'urn:overnet:object:' . ('f' x 64)),
    _commit($request, refs   => []),
    _commit($request, refs   => [['e', 'f' x 64]]),
    _commit($request, refs   => [['e', $request->{id}], ['e', $request->{id}]]),
  ) {
    is(_record_result($commit)->{outcome}, 'invalid', 'invalid commit relationship');
  }
  is(_record_result(_commit($request, actor => 'other-registrar'))->{outcome},
    'untrusted', 'registrar signer is pinned');
  is(_record_result(_commit(_proof($first)))->{outcome}, 'invalid', 'binding cannot embed another event type');
  return;
}

sub _test_spec_resolution {
  my $fixture  = _fixture('resolution');
  my %expected = map { $_->{id} => $_ } @{$fixture->{expected}{cases}};
  for my $case (@{$fixture->{input}{cases}}) {
    my ($args, $aliases) = _scenario($case, $fixture->{input}{context});
    my $result = Overnet::Core::Naming->verify_resolution(%{$args});
    my $want   = $expected{$case->{id}};
    is $result->{outcome}, $want->{outcome}, $case->{id} or diag $result;
    if ($want->{authority}) {
      is($result->{authority}{pubkey}, $keys{$want->{authority}}->pubkey_hex, 'assigned authority');
    } else {
      ok(!exists $result->{authority}, 'no authority on a negative result');
    }
    if ($want->{checkpoint}) {
      my $retained = $result->{checkpoint} // $args->{checkpoint};
      is($retained->{event_id}, $aliases->{$want->{checkpoint}{id}}{id}, 'checkpoint retains expected event');
      is($retained->{revision}, $want->{checkpoint}{revision},           'checkpoint revision');
    }
    if (exists $want->{retain_conflict}) {
      is(!!$result->{conflicts}, !!$want->{retain_conflict}, 'only verified conflict evidence is retained');
    }
  }
  return;
}

sub _test_proofs {
  my $first = $base_history->[0];
  my $proof = _proof($first);
  ok(_resolve(proof => $proof, history => [$first])->{valid}, 'historical request expiry is evaluated at commit time');
  for my $entry (
    ['future proof',                {at => 1105, expires_at => 1150}, 1100, 2, 'invalid'],
    ['allowed future clock margin', {at => 1104, expires_at => 1150}, 1100, 2, 'resolved'],
    ['expiry with clock margin',    {},                               1148, 2, 'unavailable'],
    ['before conservative expiry',  {},                               1147, 2, 'resolved'],
    ['oversized lease',             {expires_at => 1151},             1100, 0, 'invalid'],
    ['empty lease',                 {expires_at => 1090},             1090, 0, 'invalid'],
    ['wrong nonce',                 {nonce => 'b' x 64},              1100, 0, 'invalid'],
  ) {
    is(
      _resolve(
        proof   => _proof($first, %{$entry->[1]}),
        history => [$first],
        now     => $entry->[2],
        epsilon => $entry->[3]
      )->{outcome},
      $entry->[4],
      $entry->[0]
    );
  }
  my $forged = _copy($base_history->[2]);
  $forged->{sig} = '0' x 128;
  is(_resolve(proof => $proof, history => [$forged, $first])->{outcome},
    'resolved', 'unrelated forged event does not poison valid evidence');
  my $forged_first = _copy($first);
  $forged_first->{sig} = '0' x 128;
  is(_resolve(proof => $proof, history => [$forged_first])->{outcome}, 'invalid', 'required forged event is invalid');
  is(_resolve(proof => $proof, history => [$forged_first, $first])->{outcome},
    'resolved', 'forged duplicate cannot hide real event');
  my $unauthorized = _next($first, actor => 'bob');
  is(_resolve(proof => $proof, history => [$first, $unauthorized])->{outcome},
    'resolved', 'signed unauthorized branch is not conflict evidence');
  my $branch = _next($first, body => {read_relays => ['wss://reader.test/']});
  is(_resolve(proof => _proof($base_history->[1]), history => [$first, $base_history->[1], $branch])->{outcome},
    'conflict', 'two valid branches conflict without an existing checkpoint');
  is(_resolve(proof => $proof, history => [$first, $base_history->[1]])->{outcome},
    'conflict', 'older proof cannot hide a supplied valid newer head');
  is(_resolve(proof => $proof, history => [$first, $base_history->[1], $branch])->{outcome},
    'conflict', 'fork beyond selected head is still a conflict');
  is(_resolve(proof => _proof(undef), history => [$first])->{outcome},
    'conflict', 'supplied verified registration contradicts absence');
  my $bob_registration = _commit(
    _request(
      actor => 'bob',
      body  => {
        controllers  => [$keys{bob}->pubkey_hex],
        profile_data =>
          {%{_body(_body($first)->{request})->{profile_data}}, bootstrap_pubkey => $keys{bob}->pubkey_hex},
      }
    )
  );
  is(_resolve(proof => $proof, history => [$first, $bob_registration])->{outcome},
    'conflict', 'two registrar-signed initial claims for one name conflict');
  my $other = _commit(
    _request(
      body => {
        name         => '#other',
        profile_data => {
          network          => 'overnet',
          group_id         => 'irc-6f7665726e6574-236f74686572',
          bootstrap_pubkey => $keys{alice}->pubkey_hex,
        },
      }
    )
  );
  my $other_a       = _next($other);
  my $other_b       = _next($other, body => {read_relays => ['wss://other-branch.test/']});
  my $wrong_channel = _resolve(proof => _proof($other_a), history => [$other, $other_a, $other_b]);
  is($wrong_channel->{outcome}, 'invalid', 'a proof pointing into another channel is invalid');
  ok(!exists($wrong_channel->{conflicts}), 'another channel fork cannot poison this checkpoint');
  my $suspended = _next($first,     body => {status => 'suspended'});
  my $retired   = _next($suspended, body => {status => 'retired'});

  for my $history ([$first, $suspended], [$first, $suspended, $retired]) {
    my $result = _resolve(proof => _proof($history->[-1]), history => $history);
    is($result->{outcome}, _body(_body($history->[-1])->{request})->{status}, 'non-active status is preserved');
    ok(!exists $result->{authority}, 'no write route for suspension or retirement');
  }
  is(_resolve(proof => _proof(undef), history => [])->{outcome},
    'not_found', 'signed absence permits only registration attempt');
  is(_resolve(proof => _proof($first, revision => 2), history => [$first])->{outcome},
    'invalid', 'proof revision matches last commit');
  is(_resolve(proof => _proof(undef, revision => 1), history => [])->{outcome},
    'invalid', 'null proof head requires revision zero');
  is(_resolve(proof => _proof($first, revision => 0), history => [$first])->{outcome},
    'invalid', 'positive proof requires positive revision');
  is(
    _resolve(proof => _proof($first), history => [$first], checkpoint => {event_id => 'bad', revision => 1})->{outcome},
    'unavailable',
    'malformed retained state fails closed'
  );
  return;
}

sub _test_persistence {
  my $dir   = tempdir(CLEANUP => 1);
  my $path  = File::Spec->catfile($dir, 'checkpoints.json');
  my $saved = Overnet::Core::Naming::Verifier->empty_state(namespace => $namespace);
  _write_json($path, $saved);
  my $now       = 1100;
  my $fail_save = 0;
  my $saves     = 0;
  my %args      = (
    namespace  => $namespace,
    epsilon    => 0,
    clock      => sub { return $now; },
    load_state => sub { return _read_json($path); },
    save_state => sub {
      my ($state) = @_;
      $saves++;
      if ($fail_save) { return 0; }
      _write_json($path, $state);
      return 1;
    },
  );
  my $verifier = Overnet::Core::Naming::Verifier->new(\%args);
  my $lookup   = $verifier->begin_lookup(name => '#Overnet');
  is($lookup->{name}, '#overnet', 'outstanding lookup owns canonical name');
  like($lookup->{nonce}, qr/\A[0-9a-f]{64}\z/mxs, 'unpredictable nonce has required shape');
  my $response = {
    nonce   => $lookup->{nonce},
    proof   => _proof($base_history->[1], nonce => $lookup->{nonce}),
    history => [@{$base_history}[0, 1]]
  };
  my $result = $verifier->verify_resolution(%{$response}, checkpoint => {revision => 999, event_id => 'f' x 64});
  is($result->{outcome}, 'resolved', 'peer-supplied checkpoint is ignored');
  is(_read_json($path)->{bindings}{'#overnet'}{checkpoint},
    $result->{checkpoint}, 'checkpoint is on disk before route returns');
  is($saves,                                                1,         'successful verification persists');
  is($verifier->verify_resolution(%{$response})->{outcome}, 'invalid', 'same nonce cannot be reused');
  my $fresh = $verifier->begin_lookup(name => '#overnet');
  isnt($fresh->{nonce}, $lookup->{nonce}, 'new lookup has different nonce');
  is($verifier->verify_resolution(%{$response}, nonce => $fresh->{nonce})->{outcome},
    'invalid', 'old proof cannot answer fresh lookup');
  $verifier = Overnet::Core::Naming::Verifier->new(%args);
  my $restart  = $verifier->begin_lookup(name => '#overnet');
  my $rollback = $verifier->verify_resolution(
    nonce   => $restart->{nonce},
    proof   => _proof($base_history->[0], nonce => $restart->{nonce}),
    history => [$base_history->[0]]
  );
  is($rollback->{outcome},                                            'conflict', 'rollback detected after restart');
  is(_read_json($path)->{bindings}{'#overnet'}{checkpoint}{revision}, 2,          'rollback cannot lower checkpoint');
  ok(@{_read_json($path)->{bindings}{'#overnet'}{conflicts}}, 'conflict evidence saved');
  $verifier = Overnet::Core::Naming::Verifier->new(%args);
  my $again = $verifier->begin_lookup(name => '#overnet');
  is(
    $verifier->verify_resolution(
      nonce   => $again->{nonce},
      proof   => _proof($base_history->[1], nonce => $again->{nonce}),
      history => [@{$base_history}[0, 1]]
    )->{outcome},
    'conflict',
    'sticky-conflict-after-restart'
  );
  _write_json($path, $saved);
  $verifier  = Overnet::Core::Naming::Verifier->new(%args);
  $fail_save = 1;
  my $failed  = $verifier->begin_lookup(name => '#overnet');
  my $failure = $verifier->verify_resolution(
    nonce   => $failed->{nonce},
    proof   => _proof($base_history->[1], nonce => $failed->{nonce}),
    history => [@{$base_history}[0, 1]]
  );
  is($failure->{outcome}, 'unavailable', 'failed persistence prevents authority use');
  ok(!exists $failure->{authority}, 'no authority returned after write failure');
  $fail_save = 0;
  my $lower = $verifier->begin_lookup(name => '#overnet');
  is(
    $verifier->verify_resolution(
      nonce   => $lower->{nonce},
      proof   => _proof($base_history->[0], nonce => $lower->{nonce}),
      history => [$base_history->[0]]
    )->{outcome},
    'conflict',
    'failed save does not erase observed head in live verifier'
  );
  my $pending = $verifier->begin_lookup(name => '#new');
  $now = 1160;
  is($verifier->verify_resolution(nonce => $pending->{nonce})->{outcome}, 'unavailable', 'lookup lifetime is bounded');
  is($verifier->verify_resolution(nonce => $pending->{nonce})->{outcome}, 'invalid',     'expired lookup was consumed');

  for my $load (sub { return; }, sub { return {}; }, sub { return {%{$saved}, namespace => {}}; }) {
    like(
      dies { Overnet::Core::Naming::Verifier->new(%args, load_state => $load); },
      qr/Stored\ naming\ state/mxs,
      'missing state is never silently reset'
    );
  }
  like(dies { Overnet::Core::Naming::Verifier->new(%args, epsilon => undef); },
    qr/epsilon/mxs, 'clock bound must be explicit');
  like(dies { Overnet::Core::Naming::Verifier->new(%args, save_state => undef); },
    qr/save_state/mxs, 'persistence is required');
  return;
}

sub _test_limits {
  my $now   = 1100;
  my $state = Overnet::Core::Naming::Verifier->empty_state(namespace => $namespace);
  my %args  = (
    namespace  => $namespace,
    epsilon    => 0,
    clock      => sub { return $now; },
    load_state => sub { return _copy($state); },
    save_state => sub { return 1; },
  );
  my $verifier = Overnet::Core::Naming::Verifier->new(%args);
  is($verifier->begin_lookup(name => '&local')->{outcome}, 'invalid', 'invalid names cannot open a lookup');
  for my $invalid (undef, [], 'short') {
    is($verifier->verify_resolution(nonce => $invalid)->{outcome},
      'invalid', 'invalid nonce cannot match pending state');
  }
  for my $count (1 .. 128) {
    ok($verifier->begin_lookup(name => '#overnet')->{valid}, "pending lookup $count");
  }
  is($verifier->begin_lookup(name => '#overnet')->{outcome}, 'unavailable', 'pending work is bounded');
  $now = 1160;
  ok($verifier->begin_lookup(name => '#overnet')->{valid}, 'expired pending entries are pruned');
  for my $clock (sub { return; }, sub { croak 'clock failure'; }) {
    my $bad_clock = Overnet::Core::Naming::Verifier->new(%args, clock => $clock);
    is($bad_clock->begin_lookup(name => '#overnet')->{outcome}, 'unavailable', 'clock failure stops lookup');
  }
  my $backwards = $verifier->begin_lookup(name => '#overnet');
  $now = 1159;
  is($verifier->verify_resolution(nonce => $backwards->{nonce})->{outcome},
    'unavailable', 'backward clock stops response use');
  my %defaults = %args;
  delete $defaults{clock};
  ok(Overnet::Core::Naming::Verifier->new(%defaults)->begin_lookup(name => '#overnet')->{valid},
    'default clock supplies Unix time');
  $now = 1100;
  my $throwing = Overnet::Core::Naming::Verifier->new(%args, save_state => sub { croak 'storage failure'; });
  my $lookup   = $throwing->begin_lookup(name => '#overnet');
  is(
    $throwing->verify_resolution(
      nonce   => $lookup->{nonce},
      proof   => _proof($base_history->[0], nonce => $lookup->{nonce}),
      history => [$base_history->[0]]
    )->{outcome},
    'unavailable',
    'storage exception does not expose a route'
  );
  return;
}

sub _test_invalid_state {
  my $empty = Overnet::Core::Naming::Verifier->empty_state(namespace => $namespace);
  my %args  = (
    namespace  => $namespace,
    epsilon    => 0,
    load_state => sub { return _copy($empty); },
    save_state => sub { return 1; }
  );
  for my $entry (
    [],
    {checkpoint => []},
    {checkpoint => {revision => 0, event_id => 'a' x 64}},
    {checkpoint => {revision => 1, event_id => 'bad'}},
    {conflicts  => []},
    {conflicts  => {}},
  ) {
    my $state = {%{$empty}, bindings => {'#overnet' => $entry}};
    like(
      dies {
        Overnet::Core::Naming::Verifier->new(%args, load_state => sub { return $state; });
      },
      qr/Stored\ naming/mxs,
      'malformed checkpoint/conflict state cannot be loaded'
    );
  }
  my $noncanonical = {%{$empty}, bindings => {'#Overnet' => {}}};
  like(
    dies {
      Overnet::Core::Naming::Verifier->new(%args, load_state => sub { return $noncanonical; });
    },
    qr/malformed/mxs,
    'checkpoint keys must be canonical names'
  );
  like(dies { Overnet::Core::Naming::Verifier->new(%args, clock => []); }, qr/clock/mxs, 'clock must be callable');
  like(dies { Overnet::Core::Naming::Verifier->new('namespace'); },
    qr/Constructor/mxs, 'odd constructor arguments rejected');
  like(dies { Overnet::Core::Naming::Verifier->new(%args, namespace => {}); },
    qr/namespace/mxs, 'constructor cannot infer trust');
  like(dies { Overnet::Core::Naming::Verifier->empty_state(namespace => {}); },
    qr/namespace/mxs, 'initial state requires explicit trust');
  return;
}

subtest 'normalization specification vectors'                                 => \&_test_normalization;
subtest 'real signed records and wire validation'                             => \&_test_records;
subtest 'request types, identity, and IRC binding constraints'                => \&_test_requests;
subtest 'endpoint canonicalization and explicit local exceptions'             => \&_test_endpoints;
subtest 'commits validate request references, authorization, and transitions' => \&_test_histories;
subtest 'resolution specification vectors use complete signed wire events'    => \&_test_spec_resolution;
subtest 'proof boundaries and unrelated adversarial evidence'                 => \&_test_proofs;
subtest 'lookup replay, persistence, restart, and storage failure'            => \&_test_persistence;
subtest 'bounded pending lookups and failure handling'                        => \&_test_limits;
subtest 'malformed persistent state is not reset'                             => \&_test_invalid_state;

done_testing;

sub _copy {
  my ($value) = @_;
  return $JSON->decode($JSON->encode($value));
}

sub _body {
  my ($event) = @_;
  my $text = $event->{content};
  return $JSON->decode(utf8::is_utf8($text) ? encode('UTF-8', $text) : $text)->{body};
}

sub _event {
  my ($type, $body, $actor, $at, $refs) = @_;
  my $identity_body = $type eq 'naming.binding' ? _body($body->{request}) : $body;
  my $identity      = Overnet::Core::Naming->binding_id(
    %{$namespace},
    namespace_id => $identity_body->{namespace_id} // $namespace->{namespace_id},
    name         => $identity_body->{name}         // '#overnet',
  );
  my $id = $identity->{binding_id}
    // Overnet::Core::Naming->binding_id(%{$namespace}, name => '#overnet')->{binding_id};
  return $keys{$actor}->create_event_hash(
    kind       => 7800,
    created_at => $at,
    content    => JSON->new->canonical->encode({provenance => {type => 'native'}, body => $body}),
    tags       => [
      ['overnet_v',   '0.1.0'],
      ['v',           '0.1.0'],
      ['overnet_et',  $type],
      ['t',           $type],
      ['overnet_ot',  'naming.binding'],
      ['o',           'naming.binding'],
      ['overnet_oid', $id],
      ['d',           $id],
      @{$refs // []},
    ],
  );
}

sub _request {
  my (%args) = @_;
  my $body = {
    version      => 1,
    namespace_id => $namespace->{namespace_id},
    name         => '#overnet',
    revision     => 1,
    previous     => undef,
    expires_at   => 1300,
    object_type  => 'chat.channel',
    object_id    => undef,
    profile      => 'irc.naming.nip29.v1',
    status       => 'active',
    controllers  => [$keys{alice}->pubkey_hex],
    authority    => {pubkey => $keys{'host-a'}->pubkey_hex, relay_url => 'wss://host-a.example.test/'},
    read_relays  => [],
    profile_data => {
      network          => 'overnet',
      group_id         => 'irc-6f7665726e6574-236f7665726e6574',
      bootstrap_pubkey => $keys{alice}->pubkey_hex
    },
    %{$args{body} // {}},
  };
  return _event('naming.change', $body, $args{actor} // 'alice', $args{at} // 1000);
}

sub _commit {
  my ($request, %args) = @_;
  my $target = _body($request)->{object_id} // ('urn:overnet:object:' . $request->{id});
  return _event(
    'naming.binding',
    {version => 1, request => $request, object_id => $args{target} // $target},
    $args{actor} // 'registrar',
    $args{at}    // $request->{created_at},
    $args{refs}  // [['e', $request->{id}]]
  );
}

sub _next {
  my ($previous, %args) = @_;
  my $prior   = _body(_body($previous)->{request});
  my $at      = $args{at} // ($previous->{created_at} + 1);
  my $request = _request(
    actor => $args{actor},
    at    => $at,
    body  => {
      %{$prior},
      revision   => $prior->{revision} + 1,
      previous   => $previous->{id},
      object_id  => _body($previous)->{object_id},
      expires_at => $at + 300,
      %{$args{body} // {}},
    }
  );
  return _commit($request, at => $at);
}

sub _history {
  my ($count) = @_;
  my @history = (_commit(_request()));
  for my $revision (2 .. $count) {
    push @history, _next($history[-1]);
  }
  return \@history;
}

sub _proof {
  my ($head, %args) = @_;
  my $revision = $head ? _body(_body($head)->{request})->{revision} : 0;
  return _event(
    'naming.resolution',
    {
      version      => 1,
      namespace_id => $namespace->{namespace_id},
      name         => '#overnet',
      nonce        => $args{nonce} // $nonce,
      head         => $head ? $head->{id} : undef,
      revision     => $args{revision}   // $revision,
      expires_at   => $args{expires_at} // 1150,
    },
    $args{actor} // 'registrar',
    $args{at}    // 1090
  );
}

sub _record_result {
  my ($event) = @_;
  return Overnet::Core::Naming->verify_record(namespace => $namespace, event => $event);
}

sub _history_result {
  my ($history, $head) = @_;
  return Overnet::Core::Naming->verify_history(
    namespace => $namespace,
    history   => $history,
    head      => $head // $history->[-1]{id}
  );
}

sub _resolve {
  my (%args) = @_;
  return Overnet::Core::Naming->verify_resolution(
    namespace => $namespace,
    name      => '#overnet',
    now       => 1100,
    epsilon   => 0,
    nonce     => $nonce,
    %args
  );
}

sub _scenario {
  my ($case, $context) = @_;
  my %aliases = map { 'commit-' . $_ => $base_history->[$_ - 1] } 1 .. 3;
  $aliases{'commit-2a'} = $aliases{'commit-2'};
  $aliases{'commit-2b'} = _next($aliases{'commit-1'}, body => {read_relays => ['wss://branch.example.test/']});
  my %args = (
    namespace => $namespace,
    name      => $context->{name},
    nonce     => $nonce,
    now       => $context->{now},
    epsilon   => $context->{clock_error_bound},
  );
  if ($case->{retained_head}) {
    $args{checkpoint} =
      {revision => $case->{retained_head}{revision}, event_id => $aliases{$case->{retained_head}{id}}{id}};
  }
  if ($case->{proof}) {
    my $projection = $case->{proof};
    my $head       = defined $projection->{head} ? $aliases{$projection->{head}} : undef;
    $args{proof} = _proof(
      $head,
      at         => $projection->{created_at},
      expires_at => $projection->{expires_at},
      nonce      => $projection->{nonce} eq 'nonce-current' ? $nonce : 'b' x 64,
      revision   => $projection->{revision}
    );
    $args{history} = $case->{history} ? [map { $aliases{$_->{id}} } @{$case->{history}}] : [$base_history->[0]];
  }
  if ($case->{candidate}) {
    my $forged = _next($base_history->[1], body => {revision => $case->{candidate}{revision}});
    $forged->{sig} = '0' x 128;
    $args{proof}   = _proof($forged);
    $args{history} = [$base_history->[0], $base_history->[1], $forged];
  }
  if ($case->{candidate_namespace}) {
    my $body = _body(_proof($base_history->[0]));
    $body->{namespace_id} = 'ns:' . $keys{'other-registrar'}->pubkey_hex;
    $args{proof}          = _event('naming.resolution', $body, 'other-registrar', 1090);
    $args{history}        = [$base_history->[0]];
  }
  if ($case->{retained_conflict}) {
    $args{conflicts} = [map { $aliases{$_} } @{$case->{retained_conflict}}];
  }
  return (\%args, \%aliases);
}

sub _fixture {
  my ($name)  = @_;
  my $bundled = File::Spec->catfile($FindBin::Bin, 'fixtures', 'naming', "$name.json");
  my $fixture = _read_json($bundled);
  for my $prefix (qw(../.. ../../..)) {
    my $spec = File::Spec->catfile($FindBin::Bin, $prefix, 'spec', 'fixtures', 'naming', "$name.json");
    if (-f $spec) {
      is($fixture, _read_json($spec), "$name bundled scenarios match the spec");
      last;
    }
  }
  return $fixture;
}

sub _read_json {
  my ($path) = @_;
  open my $fh, '<:raw', $path or croak "open $path: $OS_ERROR";
  my $text = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  close $fh or croak "close $path: $OS_ERROR";
  return $JSON->decode($text);
}

sub _write_json {
  my ($path, $value) = @_;
  open my $fh, '>:raw', "$path.tmp" or croak "open $path.tmp: $OS_ERROR";
  print {$fh} $JSON->encode($value) or croak "write $path: $OS_ERROR";
  close $fh                         or croak "close $path: $OS_ERROR";
  rename "$path.tmp", $path or croak "rename $path: $OS_ERROR";
  return;
}

1;
