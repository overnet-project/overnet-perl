use strictures 2;

use Test2::V0;

use JSON ();
use Overnet::Core::Provenance;

my $ADAPTER = 'a1b2c3d4' x 8;
my $FORGER  = 'f0' x 32;
my $OTHER   = 'c0' x 32;

sub adapted_event {
  my (%args) = @_;
  return {
    pubkey     => $args{pubkey},
    created_at => $args{created_at} // 1_744_300_860,
    provenance => {
      type     => 'adapted',
      protocol => $args{protocol} // 'irc',
      origin   => $args{origin}   // 'irc.libera.chat/#overnet',
    },
  };
}

sub authority_record {
  my (%args) = @_;
  return {body => {protocol => 'irc', origin => 'irc.libera.chat', origin_match => 'prefix', %args}};
}

sub outcome {
  my ($event, $records, $options) = @_;
  return Overnet::Core::Provenance::verify_event($event, $records, $options)->{outcome};
}

# Native data is not subject to verification.
is outcome({pubkey => $ADAPTER, provenance => {type => 'native'}}, []), 'not_applicable',
  'native provenance is not applicable';

# No records at all, or only non-applicable records, is the permissionless default.
is outcome(adapted_event(pubkey => $FORGER), []), 'unverified', 'no records yields unverified';
is outcome(adapted_event(pubkey => $FORGER), [authority_record(protocol => 'email', pubkeys => [$ADAPTER])]),
  'unverified', 'a record for another protocol does not apply';

# A trusted record binding the signing key makes it authoritative.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(pubkeys => [$ADAPTER])]), 'authoritative',
  'listed pubkey is authoritative';

# A trusted record that excludes the signing key marks it forged.
is outcome(adapted_event(pubkey => $FORGER), [authority_record(pubkeys => [$ADAPTER])]), 'forged',
  'unlisted pubkey is forged';

# Revocation via an empty pubkey list forges a previously authoritative key.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(pubkeys => [])]), 'forged',
  'empty pubkey list forges every key';

# Prefix matching must not cross an origin boundary.
is outcome(
  adapted_event(pubkey => $ADAPTER, origin => 'irc.libera.chatnet/#x'),
  [authority_record(pubkeys => [$ADAPTER])],
  ),
  'unverified', 'prefix match respects the separator boundary';

# An exact record does not cover a channel-scoped origin.
is outcome(adapted_event(pubkey => $FORGER), [authority_record(origin_match => 'exact', pubkeys => [$ADAPTER])],),
  'unverified', 'exact network record does not cover a channel origin';

# The only applicable record being out of its window is unresolvable.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(not_after => 1_744_200_000, pubkeys => [$ADAPTER])],),
  'unresolvable', 'out-of-window record is unresolvable';

# Two applicable in-effect records that disagree cannot be reconciled.
is outcome(
  adapted_event(pubkey => $ADAPTER),
  [authority_record(pubkeys => [$ADAPTER]), authority_record(pubkeys => [$OTHER])],
  ),
  'unresolvable', 'conflicting records are unresolvable';

# A malformed applicable record cannot yield a determination on its own.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(pubkeys => 'not-an-array')]), 'unresolvable',
  'malformed applicable record is unresolvable';

# A malformed validity-window bound is not silently ignored: the record cannot
# be shown to be in effect, so it is unresolvable rather than authoritative.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(not_before => 'garbage', pubkeys => [$ADAPTER])]),
  'unresolvable', 'a malformed not_before makes the record unresolvable, not in effect';
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(not_after => 'soon', pubkeys => [$ADAPTER])]),
  'unresolvable', 'a malformed not_after makes the record unresolvable, not in effect';

# A record that declares a window cannot be shown to be in effect without a
# usable event timestamp to compare against, so the outcome is unresolvable.
is outcome(
  {pubkey => $ADAPTER, provenance => {type => 'adapted', protocol => 'irc', origin => 'irc.libera.chat/#overnet'}},
  [authority_record(not_after => 1_744_400_000, pubkeys => [$ADAPTER])],
  ),
  'unresolvable', 'a windowed record is unresolvable when the event has no timestamp';

# Boundary guard: a record without any window is in effect regardless of time,
# so it stays authoritative even when the event carries no timestamp.
is outcome(
  {pubkey => $ADAPTER, provenance => {type => 'adapted', protocol => 'irc', origin => 'irc.libera.chat/#overnet'}},
  [authority_record(pubkeys => [$ADAPTER])],
  ),
  'authoritative', 'an unwindowed record stays authoritative without an event timestamp';

# A custom origin separator is honored.
is outcome(
  {
    pubkey     => $ADAPTER,
    created_at => 1_744_300_860,
    provenance => {type => 'adapted', protocol => 'email', origin => 'lists.example.org::dev'},
  },
  [{body => {protocol => 'email', origin => 'lists.example.org', origin_match => 'prefix', pubkeys => [$ADAPTER]}}],
  {origin_separator => q{::}},
  ),
  'authoritative', 'custom origin separator is honored';

# A well-formed record from wire content (JSON string) is decoded.
is outcome(
  {
    pubkey     => $ADAPTER,
    created_at => 1_744_300_860,
    content    =>
      '{"provenance":{"type":"adapted","protocol":"irc","origin":"irc.libera.chat/#overnet"},"body":{"text":"hi"}}',
  },
  [
    {
      content =>
"{\"provenance\":{\"type\":\"native\"},\"body\":{\"protocol\":\"irc\",\"origin\":\"irc.libera.chat\",\"origin_match\":\"prefix\",\"pubkeys\":[\"$ADAPTER\"]}}",
    }
  ],
  ),
  'authoritative', 'wire content is decoded for event and record';

subtest 'malformed events, records, and windows' => sub {
  is outcome('junk', []), 'not_applicable', 'non-object events are not applicable';
  is outcome({pubkey => $ADAPTER, provenance => {type => 'adapted', protocol => q{}, origin => 'o'}}, []),
    'unverified', 'an empty protocol is unverified';
  is outcome({pubkey => $ADAPTER, provenance => {type => 'adapted', protocol => 'irc', origin => q{}}}, []),
    'unverified', 'an empty origin is unverified';

  my $content_event = {
    pubkey     => $ADAPTER,
    created_at => 1,
    content    => JSON::encode_json(
      {provenance => {type => 'adapted', protocol => 'irc', origin => 'irc.libera.chat/#overnet'}},
    ),
  };
  is outcome($content_event, [authority_record(pubkeys => [$ADAPTER])]), 'authoritative',
    'provenance can be carried in JSON content';
  is outcome({pubkey => $ADAPTER, content => 'not json'},  []), 'not_applicable',
    'invalid JSON content is not applicable';
  is outcome({pubkey => $ADAPTER, content => ['ref']},     []), 'not_applicable',
    'reference content is not applicable';
  is outcome({pubkey => $ADAPTER, content => '"scalar"'},  []), 'not_applicable',
    'non-object JSON content is not applicable';

  my $event = adapted_event(pubkey => $ADAPTER);
  is outcome($event, ['junk']), 'unverified', 'non-object records never apply';
  is outcome($event, [{body => 'junk'}]), 'unverified', 'records without a body object never apply';
  my $content_record = {
    content => JSON::encode_json(
      {body => {protocol => 'irc', origin => 'irc.libera.chat', origin_match => 'prefix', pubkeys => [$ADAPTER]}},
    ),
  };
  is outcome($event, [$content_record]), 'authoritative',
    'record bodies can be carried in JSON content';
  is outcome($event, [authority_record(origin => q{}, pubkeys => [$ADAPTER])]),
    'unverified', 'records with empty origins never apply';
  is outcome(
    adapted_event(pubkey => $ADAPTER, origin => 'irc.libera.chat'),
    [authority_record(pubkeys => [$ADAPTER])],
    ),
    'authoritative', 'an exact origin match applies';

  is outcome(
    $event,
    [authority_record(origin => 'irc.libera.chat/#overnet', origin_match => 'fuzzy', pubkeys => [$ADAPTER])],
    ),
    'unresolvable', 'malformed origin_match values are unresolvable';
  is outcome($event, [authority_record(origin_match => 'fuzzy', pubkeys => [$ADAPTER])]),
    'unverified', 'records that never match the origin stay unverified';
  my $no_match_record =
    {body => {protocol => 'irc', origin => 'irc.libera.chat/#overnet', pubkeys => [$ADAPTER]}};
  is outcome($event, [$no_match_record]), 'authoritative',
    'records without origin_match default to exact matching';
  is outcome($event, [authority_record(pubkeys => 'junk')]),
    'unresolvable', 'non-array pubkey lists are unresolvable';
  is outcome($event, [authority_record(pubkeys => ['short'])]),
    'unresolvable', 'malformed pubkey entries are unresolvable';
  is outcome($event, [authority_record(pubkeys => [$ADAPTER], not_before => 2_000_000_000)]),
    'unresolvable', 'records not yet in effect are unresolvable';
  is outcome($event, [authority_record(pubkeys => [$ADAPTER], not_after => 1)]),
    'unresolvable', 'expired records are unresolvable';
  is outcome($event, [authority_record(pubkeys => [$ADAPTER], not_before => 'soon')]),
    'unresolvable', 'malformed window bounds are unresolvable';
  is outcome(
    {%{$event}, created_at => 'yesterday'},
    [authority_record(pubkeys => [$ADAPTER], not_before => 1)],
    ),
    'unresolvable', 'windowed records need a usable event timestamp';
  is outcome(
    $event,
    [authority_record(pubkeys => [$ADAPTER]), authority_record(pubkeys => [])],
    ),
    'unresolvable', 'conflicting records are unresolvable';
};

done_testing;

