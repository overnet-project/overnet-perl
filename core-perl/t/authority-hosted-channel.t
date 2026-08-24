use strictures 2;
use Test2::V0;

use Overnet::Authority::HostedChannel;

subtest 'deterministic authoritative group ids are reversible' => sub {
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => 'irc.example.test',
    channel => '#Fresh',
  );

  is $group_id, 'irc-6972632e6578616d706c652e74657374-236672657368',
    'the deterministic hosted-channel group id encodes the IRC network and folded channel';
  is Overnet::Authority::HostedChannel::channel_name_from_group_id(
    network  => 'irc.example.test',
    group_id => $group_id,
    ),
    '#fresh',
    'the deterministic hosted-channel group id decodes back to the folded channel name';
};

subtest 'authoritative discovery prefers the channel name tag when it matches the deterministic binding' => sub {
  my $channel = Overnet::Authority::HostedChannel::channel_name_from_group_event(
    network => 'irc.example.test',
    event   => {
      kind => 39000,
      tags => [['d', 'irc-6972632e6578616d706c652e74657374-236672657368'], ['name', '#Fresh'],],
    },
  );

  is $channel, '#Fresh', 'authoritative discovery preserves the presentational channel spelling from metadata';
};

subtest 'hosted-channel helper detects tombstoned metadata events' => sub {
  ok Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {
      kind => 9002,
      tags => [['h', 'irc-6972632e6578616d706c652e74657374-236672657368'], ['status', 'tombstoned'],],
    },
    ),
    'the helper detects the profile tombstone status tag';

  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {
      kind => 39000,
      tags => [['d', 'irc-6972632e6578616d706c652e74657374-236672657368'], ['name', '#Fresh'],],
    },
    ),
    'the helper ignores ordinary hosted-channel metadata';
};

subtest 'IRC mask helpers build and match presentational user masks' => sub {
  is Overnet::Authority::HostedChannel::irc_user_mask(
    nick => 'Bob',
    user => 'bob',
    host => '127.0.0.1',
    ),
    'Bob!bob@127.0.0.1',
    'the helper renders a standard IRC nick!user@host mask';

  ok Overnet::Authority::HostedChannel::irc_mask_matches(
    mask  => 'bob!*@127.0.0.1',
    value => 'Bob!bob@127.0.0.1',
    ),
    'IRC mask matching uses RFC1459-style case folding and wildcards';

  ok !Overnet::Authority::HostedChannel::irc_mask_matches(
    mask  => 'alice!*@127.0.0.1',
    value => 'Bob!bob@127.0.0.1',
    ),
    'non-matching IRC masks are rejected';
};

subtest 'mask helpers reject unusable inputs' => sub {
  is Overnet::Authority::HostedChannel::irc_casefold(undef), undef, 'casefold rejects undef';
  is Overnet::Authority::HostedChannel::irc_casefold([]),    undef, 'casefold rejects references';

  is Overnet::Authority::HostedChannel::irc_user_mask(user => 'bob', host => 'h'), undef,
    'user masks require a nick';
  is Overnet::Authority::HostedChannel::irc_user_mask(nick => 'Bob', user => q{}, host => 'h'), undef,
    'user masks require a non-empty user';

  ok !Overnet::Authority::HostedChannel::irc_mask_matches(value => 'Bob!bob@h'), 'matching requires a mask';
  ok !Overnet::Authority::HostedChannel::irc_mask_matches(mask => 'a!*@*', value => []),
    'matching requires a scalar value';
  ok Overnet::Authority::HostedChannel::irc_mask_matches(mask => 'b?b!*@*', value => 'Bob!bob@h'),
    'single-character wildcards match';
};

subtest 'authoritative group id derivation rejects invalid scopes' => sub {
  is Overnet::Authority::HostedChannel::authoritative_group_id(channel => '#x'), undef,
    'a network is required';
  is Overnet::Authority::HostedChannel::authoritative_group_id(network => 'net', channel => 'nochan'),
    undef, 'a channel name is required';
};

subtest 'group id decoding rejects foreign and malformed ids' => sub {
  my $decode = sub {
    return Overnet::Authority::HostedChannel::channel_name_from_group_id(@_);
  };
  is $decode->(group_id => 'irc-61-2361'), undef, 'a network is required';
  is $decode->(network => 'a', group_id => undef),            undef, 'a group id is required';
  is $decode->(network => 'a', group_id => 'not-irc-shaped'), undef, 'non-IRC group ids are refused';
  is $decode->(network => 'a', group_id => 'irc-62-2361'),    undef, 'foreign-network group ids are refused';
  is $decode->(network => 'a', group_id => 'irc-61-61'),      undef,
    'group ids that decode to non-channel names are refused';
  is $decode->(network => 'a', group_id => 'irc-61-2361'), '#a', 'well-formed group ids decode';
};

subtest 'NIP-29 group binding resolution' => sub {
  my $resolve = sub {
    my ($host, $group_id, $error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(@_);
    return {host => $host, group_id => $group_id, error => $error};
  };

  like $resolve->(network => 'a', target => '#x')->{error},
    qr/requires session_config[.]group_host/, 'a group host is required';
  like $resolve->(session_config => {group_host => 'g'}, network => 'a', target => 'nope')->{error},
    qr/requires a channel target/, 'a channel target is required';

  my $exact = $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#x' => {group_id => 'irc-61-2378'}}},
    network        => 'a',
    target         => '#x',
  );
  is $exact->{group_id}, 'irc-61-2378', 'exact channel bindings resolve';
  is $exact->{host},     'g',           'the configured group host is returned';

  my $folded = $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#other' => 'x', '#FOO' => 'irc-61-23666f6f'}},
    network        => 'a',
    target         => '#foo',
  );
  is $folded->{group_id}, 'irc-61-23666f6f', 'casefolded channel bindings resolve';

  my $fallback = $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#x' => {}}},
    network        => 'a',
    target         => '#x',
  );
  is $fallback->{group_id},
    Overnet::Authority::HostedChannel::authoritative_group_id(network => 'a', channel => '#x'),
    'bindings without a group id fall back to the deterministic id';

  like $resolve->(
    session_config => {group_host => 'g'},
    network        => undef,
    target         => '#x',
  )->{error}, qr/requires group_id/, 'an underivable group id is an error';

  like $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#x' => {group_id => ['not-a-string']}}},
    network        => 'a',
    target         => '#x',
  )->{error}, qr/uses an invalid group_id/, 'non-string configured group ids are refused';
};

subtest 'group event helpers tolerate malformed events' => sub {
  my $from_event = sub {
    return Overnet::Authority::HostedChannel::channel_name_from_group_event(@_);
  };
  is $from_event->(event => {tags => []}), undef, 'a network is required';
  is $from_event->(network => 'a', event => 'junk'), undef, 'non-event inputs are refused';
  is $from_event->(network => 'a', event => {tags => 'junk'}), undef,
    'hash events with non-array tags are refused';
  is $from_event->(network => 'a', event => {}), undef,
    'hash events without tags are refused';
  is $from_event->(network => 'a', event => [['d', 'irc-61-2361']]), undef,
    'array reference events are refused';
  is $from_event->(network => 'a', event => \'junk'), undef,
    'scalar reference events are refused';

  {

    package t::hosted_channel::NoTagsObject;

    sub new { my ($class) = @_; return bless {}, $class }
  }
  is $from_event->(network => 'a', event => t::hosted_channel::NoTagsObject->new), undef,
    'objects without a tags accessor are refused';
  is $from_event->(network => 'a', event => {tags => [['x', 'y']]}), undef,
    'events without group id tags are refused';
  is $from_event->(network => 'a', event => {tags => [['h', 'irc-61-2361'], ['h', 'other'], 'junk']}),
    '#a', 'h tags resolve and only the first tag value counts';
  is $from_event->(network => 'a', event => {tags => [['d', 'irc-61-2361'], ['name', '#unrelated']]}),
    '#a', 'name tags that do not fold to the decoded channel are ignored';

  {

    package t::hosted_channel::TagObject;

    sub new  { my ($class, $tags) = @_; return bless {tags => $tags}, $class }
    sub tags { my ($self) = @_; return $self->{tags} }
  }
  is $from_event->(network => 'a', event => t::hosted_channel::TagObject->new([['d', 'irc-61-2361']])),
    '#a', 'objects with a tags accessor resolve';

  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(event => undef),
    'missing events are not tombstoned';
  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(event => {tags => 'junk'}),
    'hash events with non-array tags are not tombstoned';
  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => [['status', 'tombstoned']],
    ),
    'array reference events are not tombstoned';
  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {tags => [['short'], ['status', 'active']]},
    ),
    'non-tombstone status tags are ignored';
};

subtest 'guard operators are pinned against boolean mutation' => sub {

  # authoritative_group_id network guard: a reference network must be rejected,
  # not stringified through unpack() into a bogus group id.
  is Overnet::Authority::HostedChannel::authoritative_group_id(network => [], channel => '#x'),
    undef, 'a reference network is refused rather than stringified into a group id';

  {

    package t::hosted_channel::OverloadStr;

    use overload '""' => sub { $_[0]->{string} }, fallback => 1;
    sub new { my ($class, $string) = @_; return bless {string => $string}, $class }
  }
  my $over_network  = t::hosted_channel::OverloadStr->new('a');
  my $over_group_id = t::hosted_channel::OverloadStr->new('irc-61-2361');

  # channel_name_from_group_id network guard is a real gate, not merely the
  # downstream decoded-network equality check: an overloaded object that
  # stringifies to the decoded network is still refused because a network must
  # be a plain scalar.
  is Overnet::Authority::HostedChannel::channel_name_from_group_id(
    network  => $over_network,
    group_id => 'irc-61-2361',
    ),
    undef, 'an overloaded network object is refused even when it stringifies to the decoded network';

  # channel_name_from_group_id group_id guard: an overloaded object that
  # stringifies to a well-formed id is still refused because a group id must be
  # a plain scalar, not a reference.
  is Overnet::Authority::HostedChannel::channel_name_from_group_id(
    network  => 'a',
    group_id => $over_group_id,
    ),
    undef, 'an overloaded group_id object is refused even when it stringifies to a valid id';

  # irc_mask_matches value guard: an empty value must never match. Without the
  # length() requirement an empty value would match a bare wildcard mask.
  ok !Overnet::Authority::HostedChannel::irc_mask_matches(mask => '*', value => ''),
    'an empty value never matches, even against a bare wildcard mask';

  # resolve_nip29_group_binding group_host guard: the host must be a defined,
  # non-reference, non-empty scalar.
  my (undef, undef, $ref_host_error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    session_config => {group_host => []},
    network        => 'a',
    target         => '#x',
  );
  like $ref_host_error, qr/requires session_config[.]group_host/,
    'a reference group_host is refused, not treated as a usable host';

  my (undef, undef, $empty_host_error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    session_config => {group_host => q{}},
    network        => 'a',
    target         => '#x',
  );
  like $empty_host_error, qr/requires session_config[.]group_host/,
    'an empty group_host is refused because a non-empty host is required';

  # resolve_nip29_group_binding fallback: a configured binding that resolves to
  # an empty group id must fall back to the deterministic id, not be accepted or
  # rejected as-is.
  my (undef, $fallback_group_id) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    session_config => {group_host => 'g', channel_groups => {'#x' => q{}}},
    network        => 'a',
    target         => '#x',
  );
  is $fallback_group_id,
    Overnet::Authority::HostedChannel::authoritative_group_id(network => 'a', channel => '#x'),
    'an empty configured binding falls back to the deterministic group id';

  # group_event_is_tombstoned tag guard: a non-array tag entry must be skipped,
  # not dereferenced as an array.
  is Overnet::Authority::HostedChannel::group_event_is_tombstoned(event => {tags => ['junk']}),
    0, 'non-array tag entries are tolerated rather than dereferenced';
};

done_testing;
