use strictures 2;
use Test2::V0;
use JSON ();
use Net::Nostr::Key;
use Overnet::Core::Nostr::Event;
use Overnet::Core::Nostr::Connection;

{
  package AuditTransport;
  use Moo;
  has callbacks => (is => 'ro', default => sub { {} });
  no Moo;
  sub on { my ($self,$name,$callback)=@_; $self->callbacks->{$name}=$callback; return; }
}
{
  package AuditFrame;
  use Moo;
  has body => (is => 'ro');
  no Moo;
}
my $key = Net::Nostr::Key->new;
my $wire = $key->create_event(kind => 1, created_at => 100, tags => [], content => q{})->to_hash;
subtest 'wire scalar types are checked before event coercion' => sub {
  for my $field (qw(id pubkey content sig)) {
    for my $invalid (undef, [], 123) {
      my $candidate = {%$wire, $field => $invalid};
      like dies { Overnet::Core::Nostr::Event->assert_wire_types($candidate) }, qr/string/, 'invalid string field refused';
    }
  }
  for my $field (qw(kind created_at)) {
    for my $invalid (undef, [], '100', -1, 1.5) {
      like dies { Overnet::Core::Nostr::Event->assert_wire_types({%$wire,$field=>$invalid}) },qr/integer/,'non-integer refused';
    }
  }
  for my $tags ({}, ['junk'], [[undef]], [[42]], [[[]]]) {
    ok dies { Overnet::Core::Nostr::Event->assert_wire_types({%$wire,tags=>$tags}) }, 'invalid tag structure refused';
  }
  ok dies { Overnet::Core::Nostr::Event->assert_wire_types([]) }, 'non-object refused';
};
subtest 'raw client connections reject malformed frames and release callbacks safely' => sub {
  my $transport = AuditTransport->new;
  my $callbacks = $transport->callbacks;
  my $wrapper = Overnet::Core::Nostr::Connection->new(connection => $transport);
  my $calls = 0;
  $wrapper->on(each_message => sub {$calls++});
  for my $raw ('null','[]','x' x 1_048_577,'["EVENT","s",{}]') {
    $callbacks->{each_message}->($transport,AuditFrame->new(body => $raw));
  }
  is $calls,0,'malformed frames never reach inherited decoder';
  $callbacks->{each_message}->($transport,AuditFrame->new(body => '["EOSE","s"]'));
  is $calls,1,'non-event valid frame delivered';
  $wrapper->on(finish => sub {$calls++});
  $callbacks->{finish}->($transport);
  is $calls,2,'lifecycle callback delivered';
  undef $wrapper;
  $callbacks->{finish}->($transport);
  is $calls,2,'released wrapper is not retained by callback';
};

done_testing;
