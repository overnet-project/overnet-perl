use strictures 2;
use Test2::V0;
use File::Temp qw(tempdir);
use JSON ();
use Net::Nostr::Key;
use Overnet::Authority::HostedChannel::Relay qw(build_authoritative_relay);

{ package t::authority_audit::Connection;
  sub send { push @{$_[0]{messages}}, $_[1]; }
  sub on { $_[0]{handlers}{$_[1]} = $_[2]; }
  sub close { $_[0]{closed} = 1; }
}
{ package t::authority_audit::Message;
  sub body { $_[0]{body} }
}
my $directory = tempdir(CLEANUP => 1);
my $now = 2_000_000_000;
my $expires = $now + 60;
my $user = Net::Nostr::Key->new;
my @delegates = (Net::Nostr::Key->new, Net::Nostr::Key->new);
sub relay {
  return build_authoritative_relay(relay_url => 'ws://authority.test', grant_kind => 14142,
    store_file => "$directory/store.json", clock => sub { $now });
}
sub publish {
  my ($relay, $event) = @_;
  my $connection = bless {messages => []}, 't::authority_audit::Connection';
  $relay->_connections({audit => $connection});
  $relay->_subscriptions({});
  $relay->_handle_event('audit', $event);
  return JSON::decode_json($connection->{messages}[-1]);
}
my @grants = map {
  $user->create_event(kind => 14142, created_at => $now, content => q{}, tags => [
    [relay => 'ws://authority.test'], [server => 'irc://service.test/network'],
    [session => 'session-' . $_], [delegate => $delegates[$_]->pubkey_hex], [expires_at => "$expires"],
  ]);
} 0 .. 1;
my $relay = relay();
for my $grant (@grants) {
  ok publish($relay, $grant)->[2], 'concurrent grant accepted';
}
$relay = relay();
for my $grant (@grants) {
  ok $relay->store->get_by_id($grant->id), 'grant retained across restart';
}
sub action {
  my (%args) = @_;
  my $index = $args{index} // 0;
  return $delegates[$index]->create_event(kind => 9000, created_at => $args{created_at} // $now,
    content => $args{content} // q{}, tags => [
      [h => 'group'], [overnet_actor => $user->pubkey_hex], [overnet_authority => $grants[$index]->id],
      [overnet_sequence => '1'], [p => $user->pubkey_hex, 'irc.operator'],
    ]);
}
my $accepted = action();
ok publish($relay, $accepted)->[2], 'first session can establish the operator';
ok publish($relay, action(index => 1))->[2], 'concurrent session remains usable';
is $relay->store->acceptance_for($accepted->id), {event_id => $accepted->id, accepted_at => $now},
  'authority stores exact-ID local acceptance evidence';
$now = $expires;
my $reply = publish($relay, action(created_at => $expires - 1, content => 'new backdated event'));
ok !$reply->[2], 'backdated new ID is refused at receiver expiry';
like $reply->[3], qr/expired/, 'failure explains expiry';
my $count = $relay->store->event_count;
$relay = relay();
ok publish($relay, $accepted)->[2], 'already accepted ID remains an idempotent replay after restart';
is $relay->store->event_count, $count, 'replay stores nothing and repeats no mutation';
is $relay->store->acceptance_for($accepted->id)->{accepted_at}, $expires - 60,
  'replay preserves the original receipt';
subtest 'authority transport binds strict wire validation to new connections' => sub {
  my $transport = build_authoritative_relay(relay_url => 'ws://authority.test', grant_kind => 14142);
  my $socket = bless {messages => []}, 't::authority_audit::Connection';
  $transport->_on_connection($socket, '127.0.0.1');
  my ($connection) = values %{$transport->_connections};
  isa_ok $connection, ['Overnet::Relay::Connection'];
  my $message = bless {body => ' ["EVENT", {"kind":14142,"kind":14142}]'}, 't::authority_audit::Message';
  $socket->{handlers}{each_message}->($socket, $message);
  is JSON::decode_json($socket->{messages}[-1])->[0], 'NOTICE', 'ambiguous original JSON never reaches authority admission';
  is $transport->store->event_count, 0, 'invalid connection input stores nothing';
};

subtest 'authority transport checks clock, protection, expiry and rejection outcomes' => sub {
  my $clock = 2_000_000_000;
  my $transport = build_authoritative_relay(relay_url => 'ws://authority.test', grant_kind => 14142,
    clock => sub { $clock });
  my $grant = $grants[0];
  for my $bad_clock (undef, {}, 'not-a-time') {
    $clock = $bad_clock;
    like publish($transport, $grant)->[3], qr/\Aunavailable:/, 'an unavailable receiver clock fails closed';
  }
  $clock = 2_000_000_000;
  my $protected = $user->create_event(kind => 14142, created_at => $clock, content => q{},
    tags => [@{$grant->tags}, ['-']]);
  like publish($transport, $protected)->[3], qr/protected/, 'protected authority requires authenticated ownership';
  $transport->_authenticated({audit => {$user->pubkey_hex => 1}});
  ok publish($transport, $protected)->[2], 'the protected author can publish after authentication';
  my $expired = $user->create_event(kind => 14142, created_at => $clock, content => q{},
    tags => [@{$grant->tags}, ['expiration', '1']]);
  like publish($transport, $expired)->[3], qr/expired/, 'expired authority is rejected before side effects';
  $transport->on_event(sub { return (0, undef) });
  like publish($transport, $grant)->[3], qr/unauthorized: authority rejected/, 'a reasonless admission denial still has a typed outcome';
  my $malformed = $user->create_event(kind => 14142, created_at => $clock, content => q{}, tags => [[bad => 7]]);
  like publish($transport, $malformed)->[3], qr/malformed/, 'non-string tag data is rejected on direct admission too';
};

subtest 'ordinary content invokes retention only when newly stored' => sub {
  my $transport = build_authoritative_relay(relay_url => 'ws://authority.test', grant_kind => 14142);
  my $stored = 0;
  $transport->{authority_on_stored} = sub { $stored++ };
  my $note = $user->create_event(kind => 1, content => 'ordinary', tags => []);
  ok publish($transport, $note)->[2], 'ordinary Nostr content follows the normal path';
  ok publish($transport, $note)->[2], 'a duplicate stays accepted';
  is $stored, 1, 'duplicate content does not repeat retention side effects';
  my $expired = $user->create_event(kind => 1, content => 'expired', tags => [['expiration', '1']]);
  ok !publish($transport, $expired)->[2], 'expired content is refused';
  is $stored, 1, 'rejected content does not invoke retention';
};

done_testing;
