use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use JSON       ();
use Test2::V0;

use Overnet::Core::Nostr;
use Overnet::Test::SpecConformance qw(run_core_validator_conformance);

my $SC = 'Overnet::Test::SpecConformance';

subtest 'fixture family without a directory is skipped' => sub {
  my $events = intercept {
    Overnet::Test::SpecConformance::_run_fixture_family(
      family => 'no-such-fixture-family',
      runner => sub { fail('runner must not run for a missing family') },
    );
  };
  my @subtests = grep { $_->isa('Test2::Event::Subtest') } @{$events};
  is(scalar(@subtests), 1, 'one placeholder subtest was emitted');
  ok($subtests[0]->pass, 'the placeholder subtest passes via skip_all');
};

subtest '_load_fixture rejects unreadable paths' => sub {
  my $missing = File::Spec->catfile(tempdir(CLEANUP => 1), 'nope.json');
  like(
    dies { Overnet::Test::SpecConformance::_load_fixture($missing) },
    qr/Can't read/,
    'a missing fixture file croaks',
  );
};

subtest '_subset_match compares nested structures' => sub {
  ok(Overnet::Test::SpecConformance::_subset_match(undef,    undef), 'undef matches undef');
  ok(!Overnet::Test::SpecConformance::_subset_match('value', undef), 'defined value does not match undef');
  ok(!Overnet::Test::SpecConformance::_subset_match('scalar', {a => 1}), 'scalar does not match a hash');
  ok(!Overnet::Test::SpecConformance::_subset_match({},        {a => 1}), 'missing key fails');
  ok(!Overnet::Test::SpecConformance::_subset_match({a => 2},  {a => 1}), 'mismatched value fails');
  ok(Overnet::Test::SpecConformance::_subset_match({a => 1, b => 2}, {a => 1}), 'subset of keys matches');
  ok(!Overnet::Test::SpecConformance::_subset_match({a => 1}, [1]), 'hash does not match an array');
  ok(!Overnet::Test::SpecConformance::_subset_match([1],      [1, 2]), 'length mismatch fails');
  ok(!Overnet::Test::SpecConformance::_subset_match([1, 3],   [1, 2]), 'element mismatch fails');
  ok(Overnet::Test::SpecConformance::_subset_match([1, {a => 1}], [1, {a => 1}]), 'deep array matches');
  ok(!Overnet::Test::SpecConformance::_subset_match(undef, 'x'), 'undef does not match a scalar');
};

subtest '_plain_data flattens references' => sub {
  is(Overnet::Test::SpecConformance::_plain_data(undef), undef, 'undef stays undef');
  is(Overnet::Test::SpecConformance::_plain_data('x'),   'x',   'plain scalar stays as-is');
  is(
    Overnet::Test::SpecConformance::_plain_data({b => [1, 2], a => 'z'}),
    {b => [1, 2], a => 'z'},
    'nested containers are copied',
  );
  my $code = sub { };
  is(Overnet::Test::SpecConformance::_plain_data($code), "$code", 'other references stringify');
  is(Overnet::Test::SpecConformance::plain_data_for_harness([{k => 1}]), [{k => 1}], 'harness wrapper delegates');
};

subtest '_path_get walks dotted paths' => sub {
  my $root = {a => {b => [10, {c => 'deep'}]}};
  is(Overnet::Test::SpecConformance::_path_get($root, undef),      $root,  'no path returns the root');
  is(Overnet::Test::SpecConformance::_path_get($root, 'a.b.1.c'),  'deep', 'hash and array steps resolve');
  is(Overnet::Test::SpecConformance::_path_get($root, 'a.x.c'),    undef,  'missing hash key returns undef');
  is(Overnet::Test::SpecConformance::_path_get($root, 'a.b.zz'),   undef,  'non-numeric array part returns undef');
  is(Overnet::Test::SpecConformance::_path_get('flat', 'a'),       undef,  'non-container value returns undef');
};

subtest '_assertions handles equals, missing and unsupported shapes' => sub {
  my $events = intercept {
    Overnet::Test::SpecConformance::_assertions(
      {found => 1},
      [
        {path => 'found',   equals => 1},
        {path => 'absent',  missing => 1},
        {path => 'found'},
      ],
    );
  };
  my @asserts = grep { $_->isa('Test2::Event::Ok') } @{$events};
  is(scalar(@asserts), 3, 'three assertion events were emitted');
  ok($asserts[0]->pass,  'equals assertion passes');
  ok($asserts[1]->pass,  'missing assertion passes');
  ok(!$asserts[2]->pass, 'unsupported assertion shape fails');
};

subtest '_contains_lines_in_order and _line_matches' => sub {
  ok(!Overnet::Test::SpecConformance::_contains_lines_in_order('x', []), 'non-array input fails');
  ok(Overnet::Test::SpecConformance::_contains_lines_in_order([], []),   'empty expectations always match');
  ok(
    Overnet::Test::SpecConformance::_contains_lines_in_order([undef, 'a', 'x', 'b'], ['a', 'b']),
    'expected lines may be interleaved and undef lines are skipped',
  );
  ok(
    !Overnet::Test::SpecConformance::_contains_lines_in_order(['b', 'a'], ['a', 'b']),
    'out-of-order lines fail',
  );
  ok(!Overnet::Test::SpecConformance::_line_matches(undef, 'a'), 'undef line never matches');
  ok(
    Overnet::Test::SpecConformance::_line_matches(
      'AUTH abc123 done',
      'AUTH <base64_json_transport> done',
    ),
    'base64 transport placeholder matches a token',
  );
  ok(
    !Overnet::Test::SpecConformance::_line_matches(
      'AUTH two words done',
      'AUTH <base64_json_transport> done',
    ),
    'base64 transport placeholder rejects spaces',
  );
  ok(!Overnet::Test::SpecConformance::_line_matches('a', 'b'), 'different literal lines do not match');
};

subtest '_first_tag_values keeps the first value per tag name' => sub {
  is(
    Overnet::Test::SpecConformance::_first_tag_values(
      [['a', '1'], 'junk', ['short'], ['a', '2'], ['b', '3']],
    ),
    {a => '1', b => '3'},
    'malformed tags are skipped and duplicates ignored',
  );
  is(Overnet::Test::SpecConformance::_first_tag_values(undef), {}, 'undef tags produce an empty map');
};

subtest '_coerce_fixture_wire_event signs unsigned fixture data' => sub {
  is(Overnet::Test::SpecConformance::_coerce_fixture_wire_event('nope'), undef, 'non-hash input returns undef');

  my $key    = Overnet::Core::Nostr->generate_key;
  my $signed = $key->sign_event_hash(
    event => {kind => 1, content => 'hi', tags => [], created_at => 1},
  );
  is(Overnet::Test::SpecConformance::_coerce_fixture_wire_event($signed), $signed, 'valid wire events pass through');

  my $coerced = Overnet::Test::SpecConformance::_coerce_fixture_wire_event(
    {kind => 1, content => 'hi', tags => [], created_at => 1, id => 'bogus'},
  );
  ok(ref($coerced) eq 'HASH' && $coerced->{sig}, 'unsigned fixture data is re-signed');
};

subtest '_topic_from_fixture_item extracts state topics' => sub {
  is(Overnet::Test::SpecConformance::_topic_from_fixture_item('x'), undef, 'non-hash item is rejected');
  is(
    Overnet::Test::SpecConformance::_topic_from_fixture_item({item_type => 'event', data => {}}),
    undef, 'non-state item is rejected',
  );

  my $item = sub {
    my ($content) = @_;
    return {
      item_type => 'state',
      data      => {
        kind       => 37_800,
        content    => JSON::encode_json($content),
        tags       => [],
        created_at => 1,
      },
    };
  };
  is(
    Overnet::Test::SpecConformance::_topic_from_fixture_item($item->({body => 'notahash'})),
    undef, 'content without a body object is rejected',
  );
  is(
    Overnet::Test::SpecConformance::_topic_from_fixture_item($item->({body => {topic => ['ref']}})),
    undef, 'non-scalar topics are rejected',
  );
  is(
    Overnet::Test::SpecConformance::_topic_from_fixture_item(
      $item->({body => {topic => 'greetings'}, provenance => {external_identity => 'alice'}}),
    ),
    {nick => 'alice', text => 'greetings'},
    'provenance identity becomes the topic nick',
  );
  is(
    Overnet::Test::SpecConformance::_topic_from_fixture_item($item->({body => {topic => 'greetings'}})),
    {nick => 'server', text => 'greetings'},
    'missing provenance falls back to the server nick',
  );
};

subtest '_expanded_authoritative_input expands scenarios' => sub {
  my $session_config = {group_host => 'groups.example'};
  my $scenario       = {events => [{type => 'metadata', name => 'ops'}]};

  my $nested = Overnet::Test::SpecConformance::_expanded_authoritative_input(
    {
      session_config => $session_config,
      input          => {
        network                => 'local',
        target                 => '#ops',
        authoritative_scenario => $scenario,
      },
    },
  );
  ok(ref($nested->{input}{authoritative_events}) eq 'ARRAY', 'nested scenario expands to events');
  ok(!exists $nested->{input}{authoritative_scenario}, 'nested scenario key is removed');

  my $flat = Overnet::Test::SpecConformance::_expanded_authoritative_input(
    {
      session_config         => $session_config,
      network                => 'local',
      target                 => '#ops',
      authoritative_scenario => $scenario,
    },
  );
  ok(ref($flat->{authoritative_events}) eq 'ARRAY', 'top-level scenario expands to events');
  ok(!exists $flat->{authoritative_scenario}, 'top-level scenario key is removed');

  my $plain = Overnet::Test::SpecConformance::_expanded_authoritative_input({network => 'local'});
  is($plain, {network => 'local'}, 'input without scenarios is passed through');
};

subtest '_build_authoritative_events covers every event type' => sub {
  my %base = (
    session_config => {group_host => 'groups.example'},
    network        => 'local',
    target         => '#ops',
  );

  is(Overnet::Test::SpecConformance::_build_authoritative_events(%base, scenario => 'nope'),
    [], 'non-hash scenarios build nothing');

  like(
    dies {
      Overnet::Test::SpecConformance::_build_authoritative_events(%base, scenario => {events => 'nope'})
    },
    qr/events must be an array/,
    'non-array event lists croak',
  );
  like(
    dies {
      Overnet::Test::SpecConformance::_build_authoritative_events(%base, scenario => {events => ['nope']})
    },
    qr/event must be an object/,
    'non-object event specs croak',
  );
  like(
    dies {
      Overnet::Test::SpecConformance::_build_authoritative_events(
        %base,
        session_config => {},
        scenario       => {events => []},
      )
    },
    qr/group_host/,
    'a failed group binding croaks with the resolver error',
  );
  like(
    dies {
      Overnet::Test::SpecConformance::_build_authoritative_events(
        %base,
        scenario => {events => [{type => 'mystery'}]},
      )
    },
    qr/Unsupported authoritative_scenario event type: mystery/,
    'unknown event types croak',
  );

  my $pubkey = 'a' x 64;
  my $events = Overnet::Test::SpecConformance::_build_authoritative_events(
    %base,
    scenario => {
      events => [
        {
          type               => 'metadata',
          name               => 'ops',
          closed             => 1,
          private            => 1,
          restricted         => 1,
          hidden             => 1,
          moderated          => 1,
          topic_restricted   => 1,
          ban_masks          => ['bad!*@*'],
          except_masks       => ['good!*@*'],
          invite_exception_masks => ['vip!*@*'],
          key                => 'sekrit',
          user_limit         => 5,
          topic              => 'ops topic',
          tombstoned         => 1,
        },
        {type => 'metadata_edit', name => 'ops2'},
        {type => 'admins',      members => [{pubkey => $pubkey, roles => ['admin']}]},
        {type => 'members',     members => [$pubkey]},
        {type => 'roles',       roles   => ['helper', {name => 'chief'}]},
        {type => 'put_user',    target_pubkey => $pubkey, roles => ['helper']},
        {type => 'remove_user', target_pubkey => $pubkey, reason => 'gone'},
        {type => 'invite',      code => 'welcome1', target_pubkey => $pubkey},
        {type => 'join',        code => 'welcome1', actor_mask => 'alice!a@host'},
        {type => 'join'},
        {type => 'part',        reason => 'bye'},
        {
          type               => 'metadata',
          actor_pubkey       => $pubkey,
          authority_event_id => 'e' x 64,
          authority_sequence => 3,
        },
      ],
    },
  );
  is(scalar(@{$events}), 12, 'every supported event type builds an event');
  my %kinds = map { ($_->{kind} => 1) } @{$events};
  ok($kinds{39_000}, 'metadata events were built');
  my ($tagged) = grep {
    grep { ref($_) eq 'ARRAY' && $_->[0] eq 'overnet_actor' } @{$_->{tags}}
  } @{$events};
  ok($tagged, 'actor pubkey specs add authority tags');
};

subtest 'fixture-driven core validator conformance still runs' => sub {
  # Sanity check that the exported entry point remains callable after the
  # internals above were exercised directly.
  my $events = intercept { run_core_validator_conformance() };
  ok(scalar(grep { $_->isa('Test2::Event::Subtest') && !$_->pass } @{$events}) == 0,
    'validator conformance subtests all pass');
};

done_testing;
