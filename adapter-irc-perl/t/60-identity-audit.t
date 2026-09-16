use strictures 2;
use Test2::V0;
use JSON ();
use Overnet::Adapter::IRC;

my $adapter = Overnet::Adapter::IRC->new;
subtest 'fold object identity while retaining observed presentation' => sub {
  for my $command (qw(PRIVMSG NOTICE TOPIC JOIN PART QUIT KICK MODE)) {
    my $mapped = $adapter->map_input(
      command => $command, network => 'Local', target => '#[A]\\^',
      nick => 'Alice', text => 'hello', mode => '+o', target_nick => 'Bob', created_at => 100,
    );
    ok $mapped->{valid}, "$command maps";
    my %tags = map { $_->[0] => $_->[1] } @{$mapped->{event}{tags}};
    is $tags{overnet_oid}, 'irc:Local:#{a}|~', "$command uses folded channel";
    my $content = JSON::decode_json($mapped->{event}{content});
    is $content->{provenance}{origin}, 'Local/#[A]\\^', 'observed origin preserved';
  }
  my $dm = $adapter->map_input(command => 'PRIVMSG', network => 'Local', target => '[BOB]',
    nick => 'Alice', text => 'hi', created_at => 100);
  my %tags = map { $_->[0] => $_->[1] } @{$dm->{event}{tags}};
  is $tags{overnet_oid}, 'irc:Local:dm:{bob}', 'DM object uses folded peer';
};

subtest 'presence uses folded membership keys and an immutable event' => sub {
  my $result = $adapter->derive_channel_presence(network => 'Local', target => '#ROOM', created_at => 110,
    events => [
      {command => 'JOIN', network => 'Local', target => '#Room', nick => '[ALICE]', created_at => 100},
      {command => 'NICK', network => 'Local', nick => '{alice}', new_nick => 'Alice2', created_at => 101},
      {command => 'JOIN', network => 'Local', target => '#room', nick => 'Bob', created_at => 102},
      {command => 'KICK', network => 'Local', target => '#room', nick => 'Op', target_nick => 'BOB', created_at => 103},
    ]);
  ok $result->{valid}, 'presence derives';
  is $result->{event}{kind}, 7800, 'presence cannot replace topic';
  my %tags = map { $_->[0] => $_->[1] } @{$result->{event}{tags}};
  is $tags{overnet_oid}, 'irc:Local:#room', 'presence identity is folded';
  my $body = JSON::decode_json($result->{event}{content})->{body};
  is [map { $_->{nick} } @{$body->{members}}], ['Alice2'], 'nick change and kick affect case-equivalent members';
  is $body->{as_of}, 103, 'all relevant observations count';
};
subtest 'same-second authoritative order respects grant predecessors' => sub {
  my @events = map { +{id => $_->[0] x 64, pubkey => 'f' x 64, sig => '0' x 128,
    created_at => 100, kind => $_->[1], content => '',
    tags => [['h','room'], ['overnet_authority', $_->[2] x 64], ['overnet_sequence', $_->[3]]],
  } } (['a',9001,'d','1'], ['b',9000,'d','2'], ['c',9021,'e','1']);
  for my $order ([0,1,2], [0,2,1], [1,0,2], [1,2,0], [2,0,1], [2,1,0]) {
    my @sorted = Overnet::Adapter::IRC::NIP29::_sorted_authoritative_group_events([@events[@{$order}]]);
    is [map { $_->id } @sorted], [('c' x 64), ('a' x 64), ('b' x 64)], 'input order has no effect';
  }
  my @dedup = Overnet::Adapter::IRC::NIP29::_sorted_authoritative_group_events([@events, $events[0]]);
  is scalar(@dedup), 3, 'duplicate event IDs collapse';
};

subtest 'snapshot kinds alone do not establish relay authority' => sub {
  my $metadata = Net::Nostr::Group->metadata(pubkey => 'e' x 64, group_id => 'room', created_at => 100, closed => 1)->to_hash;
  my $members = Net::Nostr::Group->members(pubkey => 'e' x 64, group_id => 'room', created_at => 100, members => ['a' x 64])->to_hash;
  my %input = (network => 'local', target => '#room', authoritative_events => [$metadata, $members]);
  my %config = (authority_profile => 'nip29', group_host => 'host', channel_groups => {'#room' => 'room'});
  my $untrusted = $adapter->derive_authoritative_channel_view(%input, session_config => \%config);
  is $untrusted->{view}[0]{members}, [], 'no configured snapshot signer means no snapshot authority';
  my $trusted = $adapter->derive_authoritative_channel_view(%input, session_config => {%config, snapshot_pubkeys => ['e' x 64]});
  is [map { $_->{pubkey} } @{$trusted->{view}[0]{members}}], ['a' x 64], 'explicitly pinned snapshot signer applies';
};

done_testing;
