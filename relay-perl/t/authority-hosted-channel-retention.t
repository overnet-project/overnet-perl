use strictures 2;

use Test2::V0;

use Net::Nostr::Key;
use Overnet::Authority::HostedChannel::Relay qw(build_authoritative_relay);

# An authority relay kept every event it had ever accepted, with no retention of
# any kind: a two-hour soak watched resident memory climb from 49MB to 124MB,
# linearly and without plateau, purely from accumulated history. Left alone the
# process grows until it is killed.
#
# Retention here is opt-in and deliberately kind-aware. Evicting an event the
# relay derives authority from would silently destroy group state -- membership,
# operator rights, the group's very existence -- which is the authority
# destruction that tombstone-squat attacks aim for. So content may be evicted;
# anything authorization reads may not, ever.

my $RELAY_URL  = 'ws://127.0.0.1:7448';
my $AUTH_SCOPE = 'irc://irc.example/localnet';
my $GRANT_KIND = 14_142;
my $GROUP_ID   = 'localnet-overnet';
my $BASE_TIME  = 1_750_000_000;

my $operator_key         = Net::Nostr::Key->new;
my $operator_session_key = Net::Nostr::Key->new;

sub _relay {
  my (%args) = @_;
  return build_authoritative_relay(relay_url => $RELAY_URL, grant_kind => $GRANT_KIND, %args,);
}

# What the real relay does with an incoming event: authorize it, and store it
# only if authorization accepted.
sub _admit {
  my ($relay,    $event)  = @_;
  my ($accepted, $reason) = $relay->on_event->($event);
  if ($accepted) {
    $relay->store->store($event);
  }
  return ($accepted, $reason);
}

sub _grant_event {
  my (%args) = @_;
  return $args{actor_key}->create_event(
    kind       => $GRANT_KIND,
    created_at => $BASE_TIME,
    content    => q{},
    tags       => [
      ['relay',    $RELAY_URL],
      ['server',   $AUTH_SCOPE],
      ['delegate', $args{delegate_pubkey}],
      ['session',  'session-1'],
      ['expires_at', ($BASE_TIME + 3_600) . q{}],
    ],
  );
}

sub _control_event {
  my (%args) = @_;
  return $args{session_key}->create_event(
    kind       => $args{kind},
    created_at => $args{created_at} // $BASE_TIME + 10,
    content    => q{},
    tags       => [
      ['h',                 $GROUP_ID],
      ['overnet_actor',     $args{actor_pubkey}],
      ['overnet_authority', $args{authority_id}],
      ['overnet_sequence',  $args{sequence} // '1'],
      @{$args{extra_tags} || []},
    ],
  );
}

# Ordinary group chat: kind 9 is not an authoritative kind, so authorization
# never reads it. This is the traffic retention is allowed to drop.
sub _content_event {
  my (%args) = @_;
  return $operator_session_key->create_event(
    kind       => 9,
    created_at => $args{created_at},
    content    => "message $args{n}",
    tags       => [['h', $GROUP_ID]],
  );
}

sub _seed_operator {
  my ($relay) = @_;
  my $grant = _grant_event(actor_key => $operator_key, delegate_pubkey => $operator_session_key->pubkey_hex,);
  $relay->store->store($grant);
  my $seed = _control_event(
    kind         => 9_000,
    session_key  => $operator_session_key,
    actor_pubkey => $operator_key->pubkey_hex,
    authority_id => $grant->id,
    created_at   => $BASE_TIME + 1,
    extra_tags   => [['p', $operator_key->pubkey_hex, 'irc.operator']],
  );
  my ($accepted, $reason) = _admit($relay, $seed);
  die "operator seed rejected: $reason" if !$accepted;
  return $grant;
}

sub _churn_content {
  my ($relay, $count) = @_;
  my @ids;
  for my $n (1 .. $count) {
    my $event = _content_event(n => $n, created_at => $BASE_TIME + 100 + $n);
    my ($accepted) = _admit($relay, $event);
    push @ids, $event->id if $accepted;
  }
  return @ids;
}

sub _present {
  my ($relay, @ids) = @_;
  return scalar grep { defined $relay->store->get_by_id($_) } @ids;
}

subtest 'without a limit nothing is ever evicted' => sub {
  my $relay = _relay();
  _seed_operator($relay);
  my @ids = _churn_content($relay, 40);

  is _present($relay, @ids), 40, 'every accepted content event is still held';
};

subtest 'content beyond the limit is evicted, oldest first' => sub {
  my $relay = _relay(max_content_events => 10);
  _seed_operator($relay);
  my @ids = _churn_content($relay, 40);

  is _present($relay, @ids),           10, 'the relay holds only the configured number of content events';
  is _present($relay, @ids[30 .. 39]), 10, 'and the ones it kept are the most recent';
  is _present($relay, @ids[0 .. 29]),  0,  'the oldest content is what was dropped';
};

subtest 'no amount of content churn evicts an authoritative event' => sub {
  my $relay = _relay(max_content_events => 5);
  my $grant = _seed_operator($relay);

  my $member    = Net::Nostr::Key->new;
  my $admission = _control_event(
    kind         => 9_000,
    session_key  => $operator_session_key,
    actor_pubkey => $operator_key->pubkey_hex,
    authority_id => $grant->id,
    created_at   => $BASE_TIME + 2,
    sequence     => '2',
    extra_tags   => [['p', $member->pubkey_hex]],
  );
  my ($admitted, $why) = _admit($relay, $admission);
  ok $admitted, 'the member was admitted' or diag($why);

  _churn_content($relay, 500);

  ok defined $relay->store->get_by_id($grant->id),     'the delegation grant survived the churn';
  ok defined $relay->store->get_by_id($admission->id), 'the admission survived the churn';
};

# The property that makes eviction safe to ship: authorization must still work
# after the relay has evicted far more events than it holds. If retention could
# drop a grant, every delegated write signed against it would start failing --
# an authority outage caused by ordinary chat traffic.
subtest 'a delegated write still authorizes after heavy content churn' => sub {
  my $relay = _relay(max_content_events => 5);
  my $grant = _seed_operator($relay);

  _churn_content($relay, 500);

  my $member = Net::Nostr::Key->new;
  my ($accepted, $reason) = _admit(
    $relay,
    _control_event(
      kind         => 9_000,
      session_key  => $operator_session_key,
      actor_pubkey => $operator_key->pubkey_hex,
      authority_id => $grant->id,
      created_at   => $BASE_TIME + 700,
      sequence     => '2',
      extra_tags   => [['p', $member->pubkey_hex]],
    )
  );

  ok $accepted, 'the operator can still exercise authority after 500 evictions' or diag($reason);
};

subtest 'derived membership is unchanged by content eviction' => sub {
  my $bounded   = _relay(max_content_events => 5);
  my $unbounded = _relay();

  # The SAME member on both relays: the only difference between the two runs
  # must be whether content was evicted.
  my $member = Net::Nostr::Key->new;

  my %roles;
  for my $case (['bounded', $bounded], ['unbounded', $unbounded]) {
    my ($name, $relay) = @{$case};
    my $grant = _seed_operator($relay);
    _admit(
      $relay,
      _control_event(
        kind         => 9_000,
        session_key  => $operator_session_key,
        actor_pubkey => $operator_key->pubkey_hex,
        authority_id => $grant->id,
        created_at   => $BASE_TIME + 2,
        sequence     => '2',
        extra_tags   => [['p', $member->pubkey_hex]],
      )
    );
    _churn_content($relay, 200);

    my $state = Overnet::Authority::HostedChannel::Relay::_derive_group_state(
      relay    => $relay,
      group_id => $GROUP_ID,
    );
    $roles{$name} = [sort keys %{$state->{members} || {}}];
  }

  is $roles{bounded}, $roles{unbounded}, 'the same members are derived whether or not content was evicted';
};

done_testing;
