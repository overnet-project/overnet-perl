use strictures 2;
use Test2::V0;
use Overnet::Authority::HostedChannel;
use Net::Nostr::Key;

sub order_event {
  my ($id, $kind, @tags) = @_;
  return {id => $id x 64, kind => $kind, created_at => 100, pubkey => 'a' x 64, tags => \@tags};
}
sub order {
  return [map { $_->{id} } @{Overnet::Authority::HostedChannel::ordered_events($_[0], snapshot_signers => $_[1] || {})}];
}
subtest 'causal predecessors take priority over phase or event id at one timestamp' => sub {
  my $first = order_event('f', 9021, ['overnet_authority', 'b' x 64], ['overnet_sequence', '9']);
  my $second = order_event('1', 9000, ['overnet_authority', 'b' x 64], ['overnet_sequence', '10']);
  my $independent = order_event('2', 9001);
  for my $input ([$first,$second,$independent],[$second,$independent,$first],[$independent,$first,$second]) {
    is order($input), [$first->{id},$second->{id},$independent->{id}], 'sequence beats lexical id and phase';
  }
  is order([$first,$second,$first]), [$first->{id},$second->{id}], 'duplicate receipt does not duplicate application';
};
subtest 'malformed ordering inputs cannot crash or become trusted snapshots' => sub {
  my $valid = order_event('c', 7800);
  for my $bad (undef, [], {}, {%$valid, id => 'wrong'}, {%$valid, kind => []}, {%$valid, created_at => -1}, {%$valid, tags => {}}) {
    is order([$bad,$valid]), [$valid->{id}], 'invalid ordering input discarded';
  }
  for my $bad (undef, [], {}, {%$valid, kind => []}, {%$valid, kind => 39001, pubkey => undef}) {
    ok !Overnet::Authority::HostedChannel::trusted_snapshot($bad, []), 'unusable snapshot is untrusted';
  }
  ok !Overnet::Authority::HostedChannel::trusted_snapshot($valid, {}), 'invalid pin collection refused';
  ok Overnet::Authority::HostedChannel::trusted_snapshot($valid, []), 'ordinary action is not a snapshot';
};
subtest 'only pinned snapshots or completely scoped delegated metadata are eligible' => sub {
  my $metadata = order_event('3', 39000, ['overnet_actor','b' x 64],['overnet_authority','c' x 64],['overnet_sequence','1']);
  ok Overnet::Authority::HostedChannel::trusted_snapshot($metadata, []), 'delegated metadata proceeds to grant verification';
  my $snapshot = order_event('4',39001);
  ok Overnet::Authority::HostedChannel::trusted_snapshot($snapshot, [undef, [], 'a' x 64]), 'exact configured signer accepted';
  ok !Overnet::Authority::HostedChannel::trusted_snapshot($snapshot, ['b' x 64]), 'foreign signer refused';
  for my $tags ([],[['overnet_actor','bad']], [['overnet_actor','a' x 64],['overnet_authority','c' x 64],['overnet_sequence','1']], [['overnet_actor','b' x 64],['overnet_authority','c' x 64],['overnet_sequence','0']]) {
    ok !Overnet::Authority::HostedChannel::trusted_snapshot({%$metadata,tags=>$tags}, []), 'incomplete delegation is not trusted';
  }
  my @events = ($metadata,order_event('5',39002),order_event('6',9022),order_event('7',9009),order_event('8',9002));
  is order(\@events), [map {$_->{id}} @events[0,3,4,2,1]], 'deterministic phases for metadata, actions and snapshots';
  is order([$metadata,order_event('5',9021)], {'a' x 64 => 1}), ['5' x 64, '3' x 64], 'a pinned metadata snapshot stays in snapshot phase';
  my $key = Net::Nostr::Key->new;
  my $signed = $key->create_event(kind=>9000,created_at=>10,tags=>[],content=>q{});
  is Overnet::Authority::HostedChannel::ordered_events([$signed])->[0]->id,$signed->id,'native event objects also order';
};

done_testing;
