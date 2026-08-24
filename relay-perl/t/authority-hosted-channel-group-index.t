use strictures 2;

use Test2::V0;

use Net::Nostr::Event;
use Net::Nostr::RelayStore;
use Overnet::Authority::HostedChannel::Relay ();

# Collecting a group's authoritative events used to walk every event the relay
# had ever stored, so the cost of authorizing one control event grew with total
# relay history: a two-hour soak measured per-event latency rising from 37ms to
# over 1s purely as stored history accumulated (latency tracked store size with
# R^2 = 0.97), while throughput fell 85%.
#
# The lookup now takes its candidates from the store's `h`/`d` tag index and
# applies the SAME membership predicate to them. These tests pin the two things
# that makes safe: the candidate set may only be narrowed, never the predicate,
# and a store that cannot serve an index must still work.

my $GROUP  = 'localnet-overnet';
my $OTHER  = 'localnet-other';
my $SIGNER = 'a' x 64;
my $BASE   = 1_750_000_000;

{

  package GroupIndexTest::Relay;
  sub new { my ($class, $store) = @_; return bless {store => $store}, $class; }
  sub store { my ($self) = @_; return $self->{store}; }
}

# A store that serves the tag index but refuses a full scan: anything that walks
# every stored event fails loudly here.
{

  package GroupIndexTest::ScanForbiddenStore;
  our @ISA = ('Net::Nostr::RelayStore');
  sub all_events { die "all_events must not be called: the lookup scanned the whole store\n" }
}

# The store double the derivation tests use: it can ONLY do a full scan. The
# lookup has to keep working against stores with no index at all.
{

  package GroupIndexTest::ScanOnlyStore;
  sub new { my ($class, @events) = @_; return bless {events => [@events]}, $class; }
  sub all_events { my ($self) = @_; return $self->{events}; }
}

sub _event {
  my (%args) = @_;
  return Net::Nostr::Event->new(
    pubkey     => $args{signer} // $SIGNER,
    kind       => $args{kind},
    created_at => $args{created_at} // $BASE,
    tags       => $args{tags}       // [],
    content    => $args{content}    // q{},
  );
}

# The reference implementation: the full scan this change replaces. Equivalence
# against it is what proves the narrowing is sound.
sub _reference_group_events {
  my ($relay, $group_id, $snapshot_signers) = @_;
  my @events;
  for my $event (@{$relay->store->all_events || []}) {
    if (Overnet::Authority::HostedChannel::Relay::_event_belongs_to_group($event, $group_id, $snapshot_signers)) {
      push @events, $event;
    }
  }
  return sort { Overnet::Authority::HostedChannel::Relay::_compare_group_events($a, $b) } @events;
}

# A deliberately awkward corpus: two groups, control and snapshot kinds, the
# cross-group d/h trap a previous vulnerability turned on, an event whose first
# `h` value differs from a later one, an expired event, and unrelated kinds.
sub _corpus {
  return (
    _event(kind => 9_000,  tags => [['h', $GROUP], ['p', 'b' x 64]]),
    _event(kind => 9_001,  tags => [['h', $GROUP], ['p', 'c' x 64]], created_at => $BASE + 1),
    _event(kind => 9_002,  tags => [['h', $GROUP]], created_at => $BASE + 2),
    _event(kind => 9_021,  tags => [['h', $GROUP]], created_at => $BASE + 3),
    _event(kind => 39_000, tags => [['d', $GROUP]], created_at => $BASE + 4),
    _event(kind => 39_001, tags => [['d', $GROUP]], created_at => $BASE + 5),

    # Other group: must never be folded into this group's state.
    _event(kind => 9_000,  tags => [['h', $OTHER], ['p', 'd' x 64]]),
    _event(kind => 39_000, tags => [['d', $OTHER]]),

    # The cross-group trap: authorized against one group by `h`, addressed at
    # another by `d`. Each kind must bind by its OWN tag, never the other.
    _event(kind => 9_000,  tags => [['h', $OTHER], ['d', $GROUP], ['p', 'e' x 64]]),
    _event(kind => 39_000, tags => [['d', $OTHER], ['h', $GROUP]]),

    # First `h` value wins: this belongs to $OTHER even though it also carries
    # a later $GROUP tag the index will happily return as a candidate.
    _event(kind => 9_000, tags => [['h', $OTHER], ['h', $GROUP], ['p', 'f' x 64]]),

    # Expired: the full scan counts it, so the indexed lookup must too.
    _event(kind => 9_000, tags => [['h', $GROUP], ['p', 'g' x 64], ['expiration', $BASE - 1]]),

    # Unrelated kinds that are not group events at all.
    _event(kind => 1,      tags => [['h',     $GROUP]]),
    _event(kind => 14_142, tags => [['relay', 'ws://127.0.0.1:7448']]),
  );
}

sub _ids {
  return [map { $_->id } @_];
}

subtest 'the indexed lookup returns exactly what the full scan returned' => sub {
  my $store = Net::Nostr::RelayStore->new;
  $store->store($_) for _corpus();
  my $relay = GroupIndexTest::Relay->new($store);

  my @indexed   = Overnet::Authority::HostedChannel::Relay::_group_events($relay, $GROUP, {});
  my @reference = _reference_group_events($relay, $GROUP, {});

  is _ids(@indexed), _ids(@reference), 'the same events, in the same authoritative order, as the full scan';
  ok scalar(@indexed), 'and the corpus actually produced group events to compare';
};

subtest 'the cross-group trap stays shut' => sub {
  my $store = Net::Nostr::RelayStore->new;
  $store->store($_) for _corpus();
  my $relay = GroupIndexTest::Relay->new($store);

  my @indexed = Overnet::Authority::HostedChannel::Relay::_group_events($relay, $GROUP, {});

  # A control event authorized against $OTHER must not appear here just because
  # it also carries a `d` tag naming $GROUP, and vice versa for snapshots.
  my @leaked = grep {
    my %tag     = Overnet::Authority::HostedChannel::Relay::_first_tag_values($_->tags);
    my $binding = $_->kind >= 39_000 ? 'd' : 'h';
    ($tag{$binding} // q{}) ne $GROUP
  } @indexed;

  is \@leaked, [], 'no event bound to another group was folded into this group';
};

subtest 'an expired group event is still counted, as it was before' => sub {
  my $store = Net::Nostr::RelayStore->new;
  $store->store($_) for _corpus();
  my $relay = GroupIndexTest::Relay->new($store);

  my @indexed = Overnet::Authority::HostedChannel::Relay::_group_events($relay, $GROUP, {});
  my @expired = grep {
    my %tag = Overnet::Authority::HostedChannel::Relay::_first_tag_values($_->tags);
    defined $tag{expiration}
  } @indexed;

  is scalar(@expired), 1, 'expiration does not silently drop an event out of derived authority state';
};

subtest 'the lookup does not walk the whole store' => sub {
  my $store = GroupIndexTest::ScanForbiddenStore->new;
  $store->store($_) for _corpus();
  my $relay = GroupIndexTest::Relay->new($store);

  my @indexed;
  ok lives { @indexed = Overnet::Authority::HostedChannel::Relay::_group_events($relay, $GROUP, {}) },
    'collecting a group\'s events never asks the store for every event it holds'
    or note($@);

  my @reference = _reference_group_events(
    GroupIndexTest::Relay->new(
      do {
        my $plain = Net::Nostr::RelayStore->new;
        $plain->store($_) for _corpus();
        $plain;
      }
    ),
    $GROUP,
    {}
  );

  is _ids(@indexed), _ids(@reference), 'and it still returns the full-scan result';
};

subtest 'a store that cannot serve an index still works' => sub {

  # The derivation tests pass a bare double with nothing but all_events.
  my $store = GroupIndexTest::ScanOnlyStore->new(_corpus());
  my $relay = GroupIndexTest::Relay->new($store);

  my @indexed   = Overnet::Authority::HostedChannel::Relay::_group_events($relay, $GROUP, {});
  my @reference = _reference_group_events($relay, $GROUP, {});

  is _ids(@indexed), _ids(@reference), 'the unindexed store falls back to the full scan';
};

subtest 'unrelated history does not change a group lookup' => sub {

  # The soak's finding in miniature: pile up history that has nothing to do with
  # this group, and the group's own derived events must be untouched.
  my $small = Net::Nostr::RelayStore->new;
  $small->store($_) for _corpus();

  my $large = Net::Nostr::RelayStore->new;
  $large->store($_) for _corpus();
  for my $n (1 .. 2_000) {
    $large->store(_event(kind => 9_000, tags => [['h', "noise-$n"], ['p', 'b' x 64]], created_at => $BASE + $n));
  }

  my @from_small =
    Overnet::Authority::HostedChannel::Relay::_group_events(GroupIndexTest::Relay->new($small), $GROUP, {});
  my @from_large =
    Overnet::Authority::HostedChannel::Relay::_group_events(GroupIndexTest::Relay->new($large), $GROUP, {});

  is _ids(@from_large), _ids(@from_small),
    '2000 unrelated events later, the group derives from exactly the same events';
};

done_testing;
