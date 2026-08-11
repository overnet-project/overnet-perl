use strictures 2;
use File::Spec;
use FindBin;
use Test2::V0;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server', 'lib');

my $module = 'Overnet::Program::IRC::Authority::Coordinator';
my $path   = $module =~ s{::}{/}gr . '.pm';
my $loaded = eval {
  require $path;
  1;
};
ok $loaded, "$module loads"
  or diag $@;

for my $method (
  qw(
  authoritative_grant_subscription_id
  authoritative_discovery_subscription_id
  authoritative_channel_subscription_ids
  ensure_authoritative_grant_subscription
  ensure_authoritative_discovery_subscription
  ensure_authoritative_channel_subscription
  read_authoritative_nip29_events
  read_authoritative_grant_events
  publish_authoritative_nip29_event
  handle_subscription_event
  )
) {
  ok $module->can($method), "$module can $method";
}

{

  package Local::MockAuthorityCoordinatorServer;

  use Moo;

  has config => (
    is      => 'ro',
    default => sub {
      return {network => 'example.test',};
    },
  );
  has authoritative_grant_subscription_id => (is => 'rw');
  has called                              => (is => 'ro', reader => '_called', default => sub { [] });

  no Moo;

  sub called {
    return $_[0]{called};
  }

  sub _authority_relay_enabled {
    return 1;
  }

  sub _authority_relay_url {
    return 'wss://relay.example.test';
  }

  sub _authority_relay_query_timeout_ms {
    return 1500;
  }

  sub _authority_grant_kind {
    return 14142;
  }

  sub _is_authoritative_channel {
    return 1;
  }

  sub _request {
    my ($self, %args) = @_;
    push @{$self->{called}}, \%args;
    return {events => []};
  }

  sub _authoritative_group_binding {
    return ('groups.example.test', 'ops');
  }

  sub _canonical_channel_name {
    return $_[1];
  }
}

my $mock        = Local::MockAuthorityCoordinatorServer->new;
my $coordinator = Overnet::Program::IRC::Authority::Coordinator->new(server => $mock,);

is(
  $coordinator->authoritative_grant_subscription_id,
  'irc.authority.grants:example.test',
  'coordinator derives the grant subscription id from the network',
);

is(
  [$coordinator->authoritative_channel_subscription_ids('#ops')],
  [
    'irc.authority.meta:example.test:groups.example.test:ops',
    'irc.authority.control:example.test:groups.example.test:ops',
  ],
  'coordinator derives deterministic authoritative channel subscription ids',
);

$mock->{called} = [];
is(
  $coordinator->load_authoritative_nip29_events('#ops', refresh => 1,),
  [], 'forced authoritative channel reads use direct relay queries',
);
is(
  [map { $_->{method} } @{$mock->called}],
  ['nostr.query_events', 'nostr.query_events'],
  'forced authoritative channel reads do not open long-lived subscriptions before publishing',
);

$mock->{called} = [];
is(
  $coordinator->ensure_authoritative_grant_subscription,
  'irc.authority.grants:example.test',
  'coordinator opens the authoritative grant subscription',
);
is(
  $mock->called,
  [
    {
      method => 'nostr.open_subscription',
      params => {
        subscription_id => 'irc.authority.grants:example.test',
        relay_url       => 'wss://relay.example.test',
        timeout_ms      => 1500,
        filters         => [
          {
            kinds => [14142],
            limit => 200,
          },
        ],
      },
    },
  ],
  'grant subscription coordination goes through the runtime Nostr service',
);

my $server_path =
  File::Spec->catfile($FindBin::Bin, '..', '..', 'irc-server', 'lib', 'Overnet', 'Program', 'IRC', 'Server.pm',);
open my $server_fh, '<', $server_path
  or die "Unable to read $server_path: $!";
my $server_source = do { local $/ = undef; <$server_fh> };
close $server_fh;

like $server_source, qr/use\ Overnet::Program::IRC::Authority::Coordinator;/mx,
  'Server.pm loads the authority coordinator module';
like $server_source, qr/has\ _authority_coordinator\ =>/mx, 'Server.pm owns one authority coordinator collaborator';
like $server_source, qr/Overnet::Program::IRC::Authority::Coordinator->new\(server\ =>\ \$self/mx,
  'Server.pm constructs the authority coordinator with a weak server dependency';
for my $method (
  qw(
  ensure_authoritative_grant_subscription
  ensure_authoritative_discovery_subscription
  ensure_authoritative_channel_subscription
  read_authoritative_nip29_events
  read_authoritative_grant_events
  publish_authoritative_nip29_event
  handle_subscription_event
  )
) {
  like $server_source, qr/=>\s*'\Q$method\E'/mx, "Server.pm delegates $method to the coordinator collaborator";
}
unlike $server_source, qr/method\ =>\ 'nostr\.open_subscription'/mx,
  'Server.pm no longer embeds raw nostr.open_subscription calls';
unlike $server_source, qr/method\ =>\ 'nostr\.read_subscription_snapshot'/mx,
  'Server.pm no longer embeds raw nostr.read_subscription_snapshot calls';
unlike $server_source, qr/method\ =>\ 'nostr\.query_events'/mx,
  'Server.pm no longer embeds raw nostr.query_events calls';
unlike $server_source, qr/method\ =>\ 'nostr\.publish_event'/mx,
  'Server.pm no longer embeds raw nostr.publish_event calls';

done_testing;
