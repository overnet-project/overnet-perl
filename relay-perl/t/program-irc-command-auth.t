use strictures 2;
use File::Spec;
use FindBin;
use Test2::V0;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'irc-server', 'lib');

my $module = 'Overnet::Program::IRC::Command::Auth';
my $path   = $module =~ s{::}{/}gr . '.pm';
my $loaded = eval {
  require $path;
  1;
};
ok $loaded, "$module loads"
  or diag $@;

for my $method (
  qw(
  handle_cap
  handle_authenticate
  handle_overnetauth
  start_sasl_nostr_exchange
  complete_sasl_exchange
  reset_sasl_state
  apply_authoritative_auth_validation
  clear_authoritative_binding
  set_authoritative_account
  ensure_authoritative_delegate_offer
  accept_authoritative_delegate_event
  )
) {
  ok $module->can($method), "$module can $method";
}

{

  package Local::MockAuthCommandServer;

  use Moo;

  has called => (is => 'ro', reader => '_called', default => sub { [] });
  has config => (
    is      => 'ro',
    default => sub {
      return {server_name => 'irc.example.test',};
    },
  );
  has clients => (
    is      => 'ro',
    default => sub {
      return {
        1 => {
          id         => 1,
          registered => 0,
          nick       => 'alice',
        },
      };
    },
  );

  no Moo;

  sub called {
    return $_[0]{called};
  }

  sub _supported_capabilities {
    return ('message-tags', 'server-time', 'account-tag', 'account-notify', 'overnet-e2ee', 'sasl');
  }

  sub _send_client_line {
    my ($self, $client_id, $line) = @_;
    push @{$self->{called}}, [client_line => $client_id, $line];
    return 1;
  }

  sub _register_client_if_ready {
    my ($self, $client) = @_;
    push @{$self->{called}}, [register => $client->{id}];
    return 1;
  }

  sub _generate_authoritative_auth_challenge {
    my ($self, $client) = @_;
    push @{$self->{called}}, [challenge => $client->{id}];
    return 'a' x 64;
  }

  sub _send_server_notice {
    my ($self, $client_id, $text) = @_;
    push @{$self->{called}}, [notice => $client_id, $text];
    return 1;
  }
}

my $mock = Local::MockAuthCommandServer->new;
ok(Overnet::Program::IRC::Command::Auth::handle_cap($mock, 1, ['LS']), 'auth command module handles CAP delegation',);
is(
  $mock->called,
  [
    [
      client_line => 1,
      ':irc.example.test CAP * LS :message-tags server-time account-tag account-notify overnet-e2ee sasl'
    ],
  ],
  'CAP delegation preserves capability advertisement rendering',
);

is(
  [Local::MockAuthCommandServer->new->_supported_capabilities],
  ['message-tags', 'server-time', 'account-tag', 'account-notify', 'overnet-e2ee', 'sasl'],
  'mock capability order matches the server capability order used by compatibility tests',
);

$mock = Local::MockAuthCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Auth::handle_cap($mock, 1, ['REQ', 'server-time']),
  'auth command module handles CAP REQ delegation for server-time',
);
is(
  $mock->called,
  [[client_line => 1, ':irc.example.test CAP * ACK :server-time'],],
  'CAP REQ acknowledges server-time',
);
ok($mock->{clients}{1}{capabilities}{'server-time'},  'server-time capability is enabled');
ok($mock->{clients}{1}{capabilities}{'message-tags'}, 'server-time also enables message-tags');

$mock = Local::MockAuthCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Auth::handle_cap($mock, 1, ['REQ', 'account-tag']),
  'auth command module handles CAP REQ delegation for account-tag',
);
is(
  $mock->called,
  [[client_line => 1, ':irc.example.test CAP * ACK :account-tag'],],
  'account-tag is ACKed when the capability is advertised',
);
ok($mock->{clients}{1}{capabilities}{'account-tag'},  'account-tag capability is enabled');
ok($mock->{clients}{1}{capabilities}{'message-tags'}, 'account-tag also enables message-tags');

$mock = Local::MockAuthCommandServer->new;
ok(
  Overnet::Program::IRC::Command::Auth::handle_overnetauth($mock, 1, ['CHALLENGE']),
  'auth command module handles OVERNETAUTH challenge delegation',
);
is(
  $mock->called,
  [[challenge => 1], [notice => 1, 'OVERNETAUTH CHALLENGE ' . ('a' x 64)],],
  'OVERNETAUTH challenge delegation preserves the server notice path',
);

my $dispatcher_path = File::Spec->catfile(
  $FindBin::Bin, '..', '..', 'irc-server', 'lib', 'Overnet', 'Program', 'IRC', 'Dispatcher.pm',
);
open my $dispatcher_fh, '<', $dispatcher_path
  or die "Unable to read $dispatcher_path: $!";
my $dispatcher_source = do { local $/ = undef; <$dispatcher_fh> };
close $dispatcher_fh;

like $dispatcher_source, qr/use\ Overnet::Program::IRC::Command::Auth;/mx,
  'Dispatcher.pm loads the focused auth command module';
like $dispatcher_source, qr/Overnet::Program::IRC::Command::Auth::handle_cap/mx,
  'Dispatcher.pm delegates CAP handling to the auth command module';
like $dispatcher_source, qr/Overnet::Program::IRC::Command::Auth::handle_authenticate/mx,
  'Dispatcher.pm delegates AUTHENTICATE handling to the auth command module';
like $dispatcher_source, qr/Overnet::Program::IRC::Command::Auth::handle_overnetauth/mx,
  'Dispatcher.pm delegates OVERNETAUTH handling to the auth command module';

done_testing;
