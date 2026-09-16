use strictures 2;
use Test::More;
use JSON ();
use File::Temp qw(tempdir);
use URI::Escape qw(uri_escape_utf8);
use Net::Nostr::Key;
use Net::Nostr::Filter;
use Overnet::Relay;
use Overnet::Relay::Store::File;
use Overnet::Relay::Connection;

my $author = Net::Nostr::Key->new;
my $other = Net::Nostr::Key->new;

{
  package AuditConnection;
  sub new { return bless {sent => [], handlers => {}}, shift; }
  sub send { my ($self, $wire) = @_; push @{$self->{sent}}, JSON::decode_json($wire); }
  sub on { my ($self, $event, $callback) = @_; $self->{handlers}{$event} = $callback; }
  sub close { return; }
}
{
  package AuditMessage;
  sub body { return $_[0]->{body}; }
}
{
  package RestrictedAuditRelay;
  use parent 'Overnet::Relay';
  sub _can_read { my ($self, $conn_id, $event) = @_; return $event->pubkey eq $author->pubkey_hex; }
}


sub event {
  my (%args) = @_;
  my $type = $args{type} // 'chat.topic';
  my $object = $args{object} // 'channel:A';
  return ($args{key} // $author)->create_event(
    kind => $args{kind} // 37800, created_at => $args{at} // time,
    content => JSON::encode_json({provenance => {type => 'native'}, body => $args{body} // {}}),
    tags => [['overnet_v', '0.1.0'], ['v', '0.1.0'], ['overnet_et', $type], ['t', $type],
      ['overnet_ot', 'chat.channel'], ['o', 'chat.channel'], ['overnet_oid', $object], ['d', $object],
      @{$args{extra} // []}],
  );
}
sub removal {
  my ($target, %args) = @_;
  return event(kind => 7801, type => 'core.removal', extra => [['e', $target->id]], %args);
}
sub relay { return Overnet::Relay->new(relay_url => 'ws://localhost', @_); }
sub read_object {
  my ($relay, $query) = @_;
  $query //= 'type=chat.channel&id=channel%3AA&author=' . $author->pubkey_hex;
  my $response = $relay->_handle_object_http_request('GET', '/.well-known/overnet/v1/object?' . $query);
  my ($head, $body) = split /\r\n\r\n/, $response, 2;
  my ($status) = $head =~ /HTTP\/1.1 (\d+)/;
  return ($status, JSON::decode_json($body));
}

subtest 'object selection is author scoped and removal targets exact state' => sub {
  my $relay = relay();
  my $old = event(at => 10);
  my $current = event(at => 20);
  my $foreign = event(at => 30, key => $other);
  my $message = event(at => 15, kind => 7800, type => 'chat.message');
  for my $ev ($old, $message, removal($old, at => 40), removal($message, at => 41), $current, $foreign) {
    ok $relay->accept_synced_event($ev)->{accepted}, 'valid event admitted';
  }
  my ($status, $body) = read_object($relay);
  is $status, 200, 'object read succeeds';
  is $body->{state_event}{id}, $current->id, 'a newer foreign author and older removals do not replace current state';
  is $body->{author}, $author->pubkey_hex, 'response identifies selected author';
  ok !$body->{removed}, 'current state is not removed';
  is $body->{removal_event}, undef, 'irrelevant removals are not returned';
  my $tombstone = removal($current, at => 50);
  ok $relay->accept_synced_event($tombstone)->{accepted}, 'current-state removal admitted';
  ($status, $body) = read_object($relay);
  ok $body->{removed}, 'current state is removed';
  is $body->{state_event}, undef, 'removed state is not exposed';
  is $body->{removal_event}{id}, $tombstone->id, 'exact removal evidence returned';
  ok $relay->accept_synced_event(removal($tombstone, at => 60))->{accepted}, 'a tombstone can itself be removed';
  (undef, $body) = read_object($relay);
  ok $body->{removed}, 'removing a tombstone does not undo it';
  $relay->store->delete_by_id($tombstone->id);
  ($status, $body) = read_object($relay);
  is $status, 503, 'missing tombstone evidence cannot resurrect state';
};

subtest 'object query parameters are unique and well-formed Unicode' => sub {
  my $relay = relay();
  for my $query ('type=a&id=b', 'type=a&id=b&author=x',
    'type=a&id=b&author=' . $author->pubkey_hex . '&%61uthor=' . $author->pubkey_hex,
    'type=%ff&id=b&author=' . $author->pubkey_hex,
    'type=a&id=%xx&author=' . $author->pubkey_hex) {
    my ($status) = read_object($relay, $query);
    is $status, 400, 'malformed request rejected';
  }
};

subtest 'discarded object evidence survives restart and compaction' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";
  my $relay = relay(store => Overnet::Relay::Store::File->new(path => $path));
  my $state = event();
  my $tombstone = removal($state, at => time + 1);
  ok $relay->accept_synced_event($state)->{accepted}, 'state stored';
  ok $relay->accept_synced_event($tombstone)->{accepted}, 'removal stored';
  $relay->store->delete_by_id($tombstone->id);
  $relay->store->_compact_to_disk;
  my $restarted = relay(store => Overnet::Relay::Store::File->new(path => $path));
  my ($status) = read_object($restarted);
  is $status, 503, 'restart retains evidence of discarded removal';
  $restarted->store->delete_by_id($state->id);
  $restarted->store->_compact_to_disk;
  ($status) = read_object(relay(store => Overnet::Relay::Store::File->new(path => $path)));
  is $status, 503, 'discarded state is unavailable rather than absent';
};

subtest 'delegated removal history remains valid after expiry without replaying it' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";
  my $relay = relay(store => Overnet::Relay::Store::File->new(path => $path));
  my $state = event();
  my $grant = event(kind => 7800, type => 'core.delegation', body => {
    action => 'remove', delegate_pubkey => $other->pubkey_hex, expires_at => time + 100,
  });
  my $tombstone = event(kind => 7801, type => 'core.removal', key => $other,
    extra => [['e', $state->id], ['overnet_delegate', $grant->id]]);
  ok $relay->accept_synced_event($_)->{accepted}, 'authorization chain admitted' for ($state, $grant, $tombstone);
  my $restarted = relay(store => Overnet::Relay::Store::File->new(path => $path));
  my $context = $restarted->_overnet_validation_context($tombstone);
  $context->{now} = time + 200;
  ok Overnet::Core::Validator::validate($tombstone->to_hash, $context)->{valid},
    'trusted acceptance history survives restart';
  my $result = $restarted->accept_synced_event($tombstone);
  ok $result->{accepted} && !$result->{stored}, 'exact duplicate does not repeat effects';
};

subtest 'service policy applies to publication and object reads' => sub {
  for my $case (['closed', 403, 'policy_denied'], ['auth', 401, 'unauthorized'], ['paid', 402, 'payment_required']) {
    my $relay = relay(service_policies => {publish => $case->[0], object_read => $case->[0]});
    my $result = $relay->accept_synced_event(event());
    ok !$result->{accepted}, 'publication is denied under restricted policy';
    like $result->{message}, qr/^$case->[2]:/, 'publication has a specific policy outcome';
    my ($status, $body) = read_object($relay);
    is $status, $case->[1], 'HTTP policy is enforced';
    is $body->{error}{code}, $case->[2], 'HTTP policy outcome is explicit';
  }
};

subtest 'stored subscription replay observes visibility, ordering and limits' => sub {
  my $relay = RestrictedAuditRelay->new(relay_url => 'ws://localhost');
  my $conn = AuditConnection->new;
  $relay->_connections({1 => $conn});
  $relay->_subscriptions({1 => {}});
  $relay->_sub_by_kind({});
  $relay->_sub_no_kind({});
  my @events = (event(kind => 7800, at => 10), event(kind => 7800, at => 30), event(kind => 7800, at => 40, key => $other));
  $relay->store->store($_) for @events;
  $relay->_handle_req(1, 'query', Net::Nostr::Filter->new(kinds => [7800], limit => 2));
  my @delivered = map { $_->[2]{id} } grep { $_->[0] eq 'EVENT' } @{$conn->{sent}};
  is_deeply \@delivered, [map { $_->id } @events[0, 1]], 'visible events selected before limit, then delivered oldest first';
  is $conn->{sent}[-1][0], 'EOSE', 'EOSE follows stored replay';
  $conn->{sent} = [];
  $relay->service_policies({query => 'closed'});
  $relay->_handle_req(1, 'denied', Net::Nostr::Filter->new(kinds => [7800]));
  is $conn->{sent}[0][0], 'CLOSED', 'base relay rejects denied queries';
};

subtest 'WebSocket boundary rejects ambiguous JSON before invoking Nostr parser' => sub {
  my $raw = AuditConnection->new;
  my $connection = Overnet::Relay::Connection->new(connection => $raw, max_message_length => 512);
  my $calls = 0;
  $connection->on(each_message => sub { $calls++; });
  for my $invalid ('["REQ","s",{"limit":1,"\\u006cimit":2}]', '["REQ","s",{"x":"\\ud800"}]', 'null', '[]', 'x' x 513) {
    $raw->{handlers}{each_message}->($raw, bless({body => $invalid}, 'AuditMessage'));
  }
  is $calls, 0, 'invalid original frames never reach the underlying parser';
  is scalar @{$raw->{sent}}, 5, 'each rejected frame has an explicit outcome';
  $raw->{handlers}{each_message}->($raw, bless({body => '["REQ","s",{}]'}, 'AuditMessage'));
  is $calls, 1, 'valid frame is forwarded';
  $connection->send('["OK","id",true,""]');
  like $raw->{sent}[-1][3], qr/^accepted:/, 'inherited authentication success has an accepted prefix';
  $connection->send('["CLOSED","s","error: bad filter"]');
  like $raw->{sent}[-1][2], qr/^invalid:/, 'inherited parsing error has an invalid prefix';
};

subtest 'custom stores cannot invent object retention evidence' => sub {
  my $relay = relay(store => Net::Nostr::RelayStore->new);
  my ($status) = read_object($relay);
  is $status, 503, 'unknown retention history is unavailable';
  ok !grep($_ eq 'overnet.objects.read', @{$relay->relay_info->to_hash->{overnet}{capabilities}}),
    'unsupported object capability is omitted';
};

subtest 'bounded file store replays eviction without changing its log' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my $path = "$dir/store.json";
  my $store = Overnet::Relay::Store::File->new(path => $path, max_events => 1);
  my $old = event(at => 10);
  my $new = event(at => 20);
  $store->store($old, 10);
  $store->store($new, 20);
  my $size = -s $path;
  my $restored = Overnet::Relay::Store::File->new(path => $path, max_events => 1);
  is -s $path, $size, 'replay is read only even when capacity evicts events';
  is_deeply [map { $_->id } @{$restored->all_events}], [$new->id], 'only retained event returns';
  is $restored->acceptance_for($new->id)->{accepted_at}, 20, 'receipt survives';
  $restored->store(event(at => 5), 30);
  $restored = Overnet::Relay::Store::File->new(path => $path, max_events => 1);
  is_deeply [map { $_->id } @{$restored->all_events}], [$new->id], 'self-evicted incoming event stays absent';
};

subtest 'persistence failure cannot leave usable uncommitted authority in memory' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my $store = Overnet::Relay::Store::File->new(path => "$dir/store.json");
  my $ev = event();
  {
    no warnings 'redefine';
    local *Overnet::Relay::Store::File::_append_record = sub { die "injected write failure" };
    ok !eval { $store->store($ev, 10); 1 }, 'write failure propagates';
  }
  ok !eval { $store->get_by_id($ev->id); 1 }, 'store refuses reads until reopened';
};

subtest 'changing service policies closes active data paths' => sub {
  my $relay = relay();
  my $conn = AuditConnection->new;
  $relay->_connections({1 => $conn});
  $relay->_subscriptions({1 => {}});
  $relay->_sub_by_kind({});
  $relay->_sub_no_kind({});
  $relay->_handle_req(1, 'live', Net::Nostr::Filter->new(kinds => [7800]));
  $relay->_neg_sessions({1 => {sync => 'old session'}});
  $conn->{sent} = [];
  $relay->service_policies({query => 'closed', subscribe => 'closed', sync => 'closed'});
  $relay->_handle_count(1, 'count', Net::Nostr::Filter->new(kinds => [7800]));
  is $conn->{sent}[-1][0], 'CLOSED', 'COUNT cannot bypass query policy';
  $relay->_handle_neg_msg(1, Net::Nostr::Message->new(type => 'NEG-MSG', subscription_id => 'sync', neg_msg => '61'));
  is $conn->{sent}[-1][0], 'NEG-ERR', 'ongoing reconciliation rechecks policy';
  ok !exists $relay->_neg_sessions->{1}{sync}, 'denied synchronization session removed';
  $relay->broadcast(event(kind => 7800));
  is $conn->{sent}[-1][0], 'CLOSED', 'active subscription closes when policy changes';
  ok !exists $relay->_subscriptions->{1}{live}, 'denied subscription removed';
};

subtest 'replicated publications obey the UTF-8 byte limit' => sub {
  my $ev = event(body => {text => chr(0x2603) x 100});
  my $bytes = JSON::encode_json($ev->to_hash);
  my $relay = relay(max_message_length => length($bytes) - 1);
  my $result = $relay->accept_synced_event($ev);
  ok !$result->{accepted}, 'oversized replicated event refused';
  ok !$relay->store->get_by_id($ev->id), 'oversized event not retained';
};

done_testing;
