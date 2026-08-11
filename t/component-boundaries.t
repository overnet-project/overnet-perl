use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

use lib grep { -d $_ }
  (File::Spec->catdir($FindBin::Bin, '..', 'lib'), File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),);

use Overnet::Adapter::IRC;
use Overnet::Adapter::IRC::InputMapper;
use Overnet::Adapter::IRC::NIP29;
use Overnet::Adapter::IRC::Presence;
use JSON ();

my $adapter = Overnet::Adapter::IRC->new(overnet_version => '9.7.3');

sub _normalized_result {
  my ($result) = @_;
  my %copy = %{$result};
  if (ref($result->{event}) eq 'HASH') {
    $copy{event} = {%{$result->{event}}};
    $copy{event}{content} = JSON::decode_json($result->{event}{content});
  }
  return \%copy;
}

isa_ok $adapter->_input_mapper, ['Overnet::Adapter::IRC::InputMapper'];
isa_ok $adapter->_presence,     ['Overnet::Adapter::IRC::Presence'];
isa_ok $adapter->_nip29,        ['Overnet::Adapter::IRC::NIP29'];
is $adapter->_input_mapper->nip29, $adapter->_nip29, 'input mapping shares the facade NIP-29 collaborator';

subtest 'standard mapping is owned by the input mapper' => sub {
  my %input = (
    command    => 'PRIVMSG',
    network    => 'overnet',
    target     => '#engineering',
    nick       => 'alice',
    created_at => 123,
    text       => 'hello',
  );

  is _normalized_result($adapter->map_input(%input)), _normalized_result($adapter->_input_mapper->map_input(%input)),
    'the facade preserves the input mapper result';
  is _normalized_result($adapter->map_message(%input)), _normalized_result($adapter->map_input(%input)),
    'map_message remains an alias for map_input';
  is $adapter->map_input(%input)->{event}{tags}[0], ['overnet_v', '9.7.3'],
    'the configured Overnet version reaches the mapper';
};

subtest 'presence derivation is owned by the presence collaborator' => sub {
  my %input = (
    network    => 'overnet',
    target     => '#engineering',
    created_at => 124,
    events     => [
      {
        command    => 'JOIN',
        network    => 'overnet',
        target     => '#engineering',
        nick       => 'alice',
        created_at => 123,
      },
    ],
  );

  is _normalized_result($adapter->derive_channel_presence(%input)),
    _normalized_result($adapter->_presence->derive(%input)),
    'the facade preserves the presence result';
  is $adapter->derive_channel_presence(%input)->{event}{tags}[0], ['overnet_v', '9.7.3'],
    'the configured Overnet version reaches presence derivation';
};

subtest 'NIP-29 state and mapping share one cohesive collaborator' => sub {
  my %derive = (
    network        => 'overnet',
    target         => '#engineering',
    session_config => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
    },
    authoritative_events => [],
  );

  is $adapter->derive_authoritative_channel_view(%derive),
    $adapter->_nip29->derive_authoritative_channel_view(%derive),
    'the facade preserves the NIP-29 derivation result';

  my %mapping = (
    command        => 'PART',
    network        => 'overnet',
    target         => '#engineering',
    nick           => 'alice',
    created_at     => 125,
    actor_pubkey   => 'a' x 64,
    session_config => $derive{session_config},
  );
  is $adapter->map_input(%mapping), $adapter->_nip29->map_input(%mapping),
    'authoritative input mapping is delegated to the same NIP-29 collaborator';
};

done_testing;
