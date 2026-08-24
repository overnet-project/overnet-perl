use strictures 2;

use File::Spec;
use FindBin;
use JSON ();
use Test2::V0;

use Overnet::Auth::CLI;

{

  package t::auth_cli::FakeClient;

  use Moo;

  has responses => (is => 'ro', default => sub { {} });
  has calls => (is => 'ro', reader => '_calls', default => sub { [] });

  no Moo;

  sub identities_list {
    my ($self) = @_;
    push @{$self->{calls}},
      {
      method => 'identities.list',
      params => {},
      };
    return $self->{responses}{'identities.list'};
  }

  sub policies_list {
    my ($self) = @_;
    push @{$self->{calls}},
      {
      method => 'policies.list',
      params => {},
      };
    return $self->{responses}{'policies.list'};
  }

  sub policies_grant {
    my ($self, %params) = @_;
    push @{$self->{calls}},
      {
      method => 'policies.grant',
      params => \%params,
      };
    return $self->{responses}{'policies.grant'};
  }

  sub policies_revoke {
    my ($self, %params) = @_;
    push @{$self->{calls}},
      {
      method => 'policies.revoke',
      params => \%params,
      };
    return $self->{responses}{'policies.revoke'};
  }

  sub service_pins_list {
    my ($self) = @_;
    push @{$self->{calls}},
      {
      method => 'service_pins.list',
      params => {},
      };
    return $self->{responses}{'service_pins.list'};
  }

  sub service_pins_set {
    my ($self, %params) = @_;
    push @{$self->{calls}},
      {
      method => 'service_pins.set',
      params => \%params,
      };
    return $self->{responses}{'service_pins.set'};
  }

  sub service_pins_forget {
    my ($self, %params) = @_;
    push @{$self->{calls}},
      {
      method => 'service_pins.forget',
      params => \%params,
      };
    return $self->{responses}{'service_pins.forget'};
  }

  sub sessions_list {
    my ($self) = @_;
    push @{$self->{calls}},
      {
      method => 'sessions.list',
      params => {},
      };
    return $self->{responses}{'sessions.list'};
  }

  sub sessions_authorize {
    my ($self, %params) = @_;
    push @{$self->{calls}},
      {
      method => 'sessions.authorize',
      params => \%params,
      };
    return $self->{responses}{'sessions.authorize'};
  }

  sub sessions_renew {
    my ($self, %params) = @_;
    push @{$self->{calls}},
      {
      method => 'sessions.renew',
      params => \%params,
      };
    return $self->{responses}{'sessions.renew'};
  }

  sub sessions_revoke {
    my ($self, %params) = @_;
    push @{$self->{calls}},
      {
      method => 'sessions.revoke',
      params => \%params,
      };
    return $self->{responses}{'sessions.revoke'};
  }

  sub calls {
    my ($self) = @_;
    return $self->{calls};
  }
}

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-auth.pl');
my $libdir = File::Spec->catdir($FindBin::Bin, '..', 'lib');

subtest 'identities command prints the identity list result as JSON' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'identities.list' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::true,
        result => {
          identities => [
            {
              identity_id     => 'default',
              public_identity => {
                scheme => 'nostr.pubkey',
                value  => ('a' x 64),
              },
            },
          ],
        },
      },
    },
  );

  my $result = Overnet::Auth::CLI->run(
    argv   => ['identities'],
    client => $client,
  );

  is $result->{exit_code}, 0, 'identities exits successfully';
  is JSON::decode_json($result->{output}),
    {
    ok     => JSON::true,
    result => {
      identities => [
        {
          identity_id     => 'default',
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => ('a' x 64),
          },
        },
      ],
    },
    },
    'identities prints the auth-agent result payload';
  is $client->calls,
    [
    {
      method => 'identities.list',
      params => {},
    },
    ],
    'identities calls identities.list';
};

subtest 'authorize command builds the expected sessions.authorize request' => sub {
  my $artifact_file = File::Spec->catfile($FindBin::Bin, 'auth-cli-artifact.json');
  _write_file($artifact_file, <<'JSON');
{"type":"nostr.event","params":{"kind":22242,"tags":[["relay","irc://irc.example.test/overnet"],["challenge","abcd"]]} }
JSON

  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'sessions.authorize' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::true,
        result => {
          session_handle => {id => 'sess-1'},
        },
      },
    },
  );

  my $result = Overnet::Auth::CLI->run(
    argv => [
      'authorize',                      '--identity-id',
      'default',                        '--program-id',
      'irc.bridge',                     '--service-locator',
      'irc://irc.example.test/overnet', '--scope',
      'irc://irc.example.test/overnet', '--action',
      'session.authenticate',           '--challenge-type',
      'opaque',                         '--challenge-value',
      'abcd',                           '--artifact-file',
      $artifact_file,                   '--service-identity-scheme',
      'nostr.pubkey',                   '--service-identity-value',
      ('b' x 64),                       '--service-identity-display',
      'irc.example.test authority',     '--no-interactive',
    ],
    client => $client,
  );

  is $result->{exit_code}, 0, 'authorize exits successfully';
  is JSON::decode_json($result->{output}),
    {
    ok     => JSON::true,
    result => {
      session_handle => {id => 'sess-1'},
    },
    },
    'authorize prints the auth-agent result payload';
  is $client->calls,
    [
    {
      method => 'sessions.authorize',
      params => {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        service     => {
          locators         => ['irc://irc.example.test/overnet'],
          service_identity => {
            scheme  => 'nostr.pubkey',
            value   => ('b' x 64),
            display => 'irc.example.test authority',
          },
        },
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
        interactive => JSON::false,
        challenge   => {
          type  => 'opaque',
          value => 'abcd',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [['relay', 'irc://irc.example.test/overnet'], ['challenge', 'abcd'],],
            },
          },
        ],
      },
    },
    ],
    'authorize maps CLI flags onto sessions.authorize';

  unlink $artifact_file or die "unlink $artifact_file failed: $!";
};

subtest 'policies and sessions commands print daemon-managed state as JSON' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'policies.list' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::true,
        result => {
          policies => [
            {
              policy_id   => 'policy-1',
              identity_id => 'default',
              program_id  => 'irc.bridge',
              locators    => ['irc://irc.example.test/overnet'],
              scope       => 'irc://irc.example.test/overnet',
              action      => 'session.authenticate',
            },
          ],
        },
      },
      'sessions.list' => {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::true,
        result => {
          sessions => [
            {
              session_handle => {id => 'sess-1'},
              identity_id    => 'default',
              action         => 'session.authenticate',
            },
          ],
        },
      },
    },
  );

  my $policies = Overnet::Auth::CLI->run(
    argv   => ['policies'],
    client => $client,
  );
  my $sessions = Overnet::Auth::CLI->run(
    argv   => ['sessions'],
    client => $client,
  );

  is $policies->{exit_code}, 0, 'policies exits successfully';
  is $sessions->{exit_code}, 0, 'sessions exits successfully';
  is JSON::decode_json($policies->{output}),
    {
    ok     => JSON::true,
    result => {
      policies => [
        {
          policy_id   => 'policy-1',
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => ['irc://irc.example.test/overnet'],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
    },
    },
    'policies prints daemon-managed policy state';
  is JSON::decode_json($sessions->{output}),
    {
    ok     => JSON::true,
    result => {
      sessions => [
        {
          session_handle => {id => 'sess-1'},
          identity_id    => 'default',
          action         => 'session.authenticate',
        },
      ],
    },
    },
    'sessions prints daemon-managed session state';
};

subtest
  'policy-grant, policy-revoke, service-pins, service-pin-set, and service-pin-forget build the expected requests' =>
  sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'policies.grant' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::true,
        result => {
          policy => {policy_id => 'policy-1'},
        },
      },
      'policies.revoke' => {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::true,
        result => {
          policy_id => 'policy-1',
        },
      },
      'service_pins.list' => {
        type   => 'response',
        id     => 'auth-3',
        ok     => JSON::true,
        result => {
          service_pins => [],
        },
      },
      'service_pins.set' => {
        type   => 'response',
        id     => 'auth-4',
        ok     => JSON::true,
        result => {
          locator => 'wss://relay.example.test/auth',
        },
      },
      'service_pins.forget' => {
        type   => 'response',
        id     => 'auth-5',
        ok     => JSON::true,
        result => {
          locator => 'wss://relay.example.test/auth',
        },
      },
    },
  );

  my $grant = Overnet::Auth::CLI->run(
    argv => [
      'policy-grant',                   '--identity-id',
      'default',                        '--program-id',
      'irc.bridge',                     '--service-locator',
      'wss://relay.example.test/auth',  '--service-identity-scheme',
      'nostr.pubkey',                   '--service-identity-value',
      ('b' x 64),                       '--scope',
      'irc://irc.example.test/overnet', '--action',
      'session.delegate',
    ],
    client => $client,
  );
  my $revoke = Overnet::Auth::CLI->run(
    argv   => ['policy-revoke', '--policy-id', 'policy-1'],
    client => $client,
  );
  my $pins = Overnet::Auth::CLI->run(
    argv   => ['service-pins'],
    client => $client,
  );
  my $set = Overnet::Auth::CLI->run(
    argv => [
      'service-pin-set',               '--service-locator',
      'wss://relay.example.test/auth', '--service-identity-scheme',
      'nostr.pubkey',                  '--service-identity-value',
      ('c' x 64),                      '--service-identity-display',
      'relay.example.test authority',
    ],
    client => $client,
  );
  my $forget = Overnet::Auth::CLI->run(
    argv   => ['service-pin-forget', '--service-locator', 'wss://relay.example.test/auth'],
    client => $client,
  );

  is $grant->{exit_code},  0, 'policy-grant exits successfully';
  is $revoke->{exit_code}, 0, 'policy-revoke exits successfully';
  is $pins->{exit_code},   0, 'service-pins exits successfully';
  is $set->{exit_code},    0, 'service-pin-set exits successfully';
  is $forget->{exit_code}, 0, 'service-pin-forget exits successfully';
  is $client->calls,
    [
    {
      method => 'policies.grant',
      params => {
        policy => {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          service     => {
            locators         => ['wss://relay.example.test/auth'],
            service_identity => {
              scheme => 'nostr.pubkey',
              value  => ('b' x 64),
            },
          },
          scope  => 'irc://irc.example.test/overnet',
          action => 'session.delegate',
        },
      },
    },
    {
      method => 'policies.revoke',
      params => {
        policy_id => 'policy-1',
      },
    },
    {
      method => 'service_pins.list',
      params => {},
    },
    {
      method => 'service_pins.set',
      params => {
        locator          => 'wss://relay.example.test/auth',
        service_identity => {
          scheme  => 'nostr.pubkey',
          value   => ('c' x 64),
          display => 'relay.example.test authority',
        },
      },
    },
    {
      method => 'service_pins.forget',
      params => {
        locator => 'wss://relay.example.test/auth',
      },
    },
    ],
    'management commands map CLI flags to auth-agent methods';
  };

subtest 'renew and revoke commands wrap session ids as session handles' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'sessions.renew' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::true,
        result => {
          session_handle => {id => 'sess-2'},
        },
      },
      'sessions.revoke' => {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::true,
        result => {
          revoked => JSON::true,
        },
      },
    },
  );

  my $renew = Overnet::Auth::CLI->run(
    argv   => ['renew', '--session-id', 'sess-2', '--no-interactive'],
    client => $client,
  );
  my $revoke = Overnet::Auth::CLI->run(
    argv   => ['revoke', '--session-id', 'sess-2'],
    client => $client,
  );

  is $renew->{exit_code},  0, 'renew exits successfully';
  is $revoke->{exit_code}, 0, 'revoke exits successfully';
  is $client->calls,
    [
    {
      method => 'sessions.renew',
      params => {
        session_handle => {id => 'sess-2'},
        interactive    => JSON::false,
      },
    },
    {
      method => 'sessions.revoke',
      params => {
        session_handle => {id => 'sess-2'},
      },
    },
    ],
    'renew and revoke wrap the session id as a session_handle object';
};

subtest 'run handles help, invalid commands, and option errors in-process' => sub {
  my $ok_response = sub {
    return {type => 'response', id => 'auth-x', ok => JSON::true, result => {}};
  };
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      map { $_ => $ok_response->() }
        qw(
        identities.list policies.list policies.grant policies.revoke
        service_pins.list service_pins.set service_pins.forget
        sessions.list sessions.authorize sessions.renew sessions.revoke
        )
    },
  );

  my $help = Overnet::Auth::CLI->run(argv => ['--help']);
  is $help->{exit_code}, 0, 'a leading --help exits successfully';
  like $help->{output}, qr/Usage:/, 'a leading --help prints usage';

  my $late_help = Overnet::Auth::CLI->run(argv => ['identities', '--help'], client => $client);
  is $late_help->{exit_code}, 0, '--help after a command exits successfully';

  my $no_command = Overnet::Auth::CLI->run(argv => [], client => $client);
  is $no_command->{exit_code}, 1, 'a missing command exits with an error';
  like $no_command->{output}, qr/Usage:/, 'a missing command prints usage';

  like dies { Overnet::Auth::CLI->run(argv => ['bogus'], client => $client) },
    qr/Usage:/, 'unknown commands croak with usage';
  like dies { Overnet::Auth::CLI->run(argv => ['identities', 'extra'], client => $client) },
    qr/unexpected positional arguments: extra/, 'unexpected positional arguments croak';

  my $factory_sock;
  my $factory_result = Overnet::Auth::CLI->run(
    argv           => ['identities', '--auth-sock', '/tmp/example.sock'],
    client_factory => sub {
      my (%options) = @_;
      $factory_sock = $options{auth_sock};
      return $client;
    },
  );
  is $factory_result->{exit_code}, 0,                   'client factories are used';
  is $factory_sock,                '/tmp/example.sock', 'client factories receive the parsed options';

  isa_ok(
    Overnet::Auth::CLI::_client(options => {auth_sock => '/tmp/example.sock'}),
    ['Overnet::Auth::Client'],
    'without a factory an endpoint-configured client is constructed',
  );
  isa_ok(
    Overnet::Auth::CLI::_client(options => {}),
    ['Overnet::Auth::Client'],
    'without options a default client is constructed',
  );
};

subtest 'command option validation croaks with actionable messages' => sub {
  my $client = t::auth_cli::FakeClient->new(responses => {});
  my $run    = sub {
    my (@argv) = @_;
    return dies { Overnet::Auth::CLI->run(argv => \@argv, client => $client) };
  };

  like $run->('authorize'), qr/--program-id is required/, 'authorize requires a program id';
  like $run->('authorize', '--program-id', 'p'), qr/--scope is required/, 'authorize requires a scope';
  like $run->('authorize', '--program-id', 'p', '--scope', 's'),
    qr/--action is required/, 'authorize requires an action';
  like $run->('authorize', '--program-id', 'p', '--scope', 's', '--action', 'a'),
    qr/--service-locator is required/, 'authorize requires a service locator';
  like $run->(
    'authorize', '--program-id', 'p', '--scope', 's', '--action', 'a',
    '--service-locator', 'irc://x', '--artifact-json', '{}', '--challenge-type', 'opaque',
    ),
    qr/--challenge-type and --challenge-value are required together/,
    'challenge options must appear together';
  like $run->(
    'authorize', '--program-id', 'p', '--scope', 's', '--action', 'a', '--service-locator', 'irc://x',
    ),
    qr/--artifact-json or --artifact-file is required/, 'authorize requires artifacts';
  like $run->(
    'authorize', '--program-id', 'p', '--scope', 's', '--action', 'a',
    '--service-locator', 'irc://x', '--artifact-json', 'not json',
    ),
    qr/--artifact-json did not contain valid JSON/, 'artifact JSON must parse';
  like $run->(
    'authorize', '--program-id', 'p', '--scope', 's', '--action', 'a',
    '--service-locator', 'irc://x', '--artifact-json', '[1]',
    ),
    qr/--artifact-json must decode to an object/, 'artifact JSON must be an object';
  like $run->(
    'authorize', '--program-id', 'p', '--scope', 's', '--action', 'a',
    '--service-locator', 'irc://x', '--artifact-file', '/no/such/artifact.json',
    ),
    qr/open .*artifact[.]json failed/, 'missing artifact files croak';
  like $run->(
    'authorize', '--program-id', 'p', '--scope', 's', '--action', 'a',
    '--service-locator', 'irc://x', '--artifact-json', '{}', '--service-identity-value', 'v',
    ),
    qr/--service-identity-scheme and --service-identity-value are required together/,
    'a service identity value alone is refused';
  like $run->(
    'authorize', '--program-id', 'p', '--scope', 's', '--action', 'a',
    '--service-locator', 'irc://x', '--artifact-json', '{}', '--service-identity-display', 'd',
    ),
    qr/--service-identity-scheme and --service-identity-value are required together/,
    'a service identity display alone is refused';

  like $run->('policy-grant'), qr/--identity-id is required/, 'policy-grant requires an identity id';
  like $run->('policy-grant', '--identity-id', 'i'),
    qr/--program-id is required/, 'policy-grant requires a program id';
  like $run->('policy-grant', '--identity-id', 'i', '--program-id', 'p'),
    qr/--scope is required/, 'policy-grant requires a scope';
  like $run->('policy-grant', '--identity-id', 'i', '--program-id', 'p', '--scope', 's'),
    qr/--action is required/, 'policy-grant requires an action';
  like $run->('policy-revoke'), qr/--policy-id is required/, 'policy-revoke requires a policy id';

  like $run->('renew'),  qr/--session-id is required/, 'renew requires a session id';
  like $run->('revoke'), qr/--session-id is required/, 'revoke requires a session id';

  like $run->('service-pin-set'), qr/--service-locator is required/, 'service-pin-set requires a locator';
  like $run->('service-pin-set', '--service-locator', 'a', '--service-locator', 'b'),
    qr/exactly one --service-locator is required/, 'service-pin-set refuses multiple locators';
  like $run->('service-pin-set', '--service-locator', 'a'),
    qr/--service-identity-scheme and --service-identity-value are required/,
    'service-pin-set requires a service identity';
  like $run->('service-pin-forget'), qr/--service-locator is required/,
    'service-pin-forget requires a locator';
};

subtest 'responses render compactly, with errors, and with optional fields elided' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'sessions.authorize'  => {type => 'response', id => 'auth-1', ok => JSON::true, result => {}},
      'sessions.renew'      => {type => 'response', id => 'auth-2', ok => JSON::false},
      'service_pins.forget' => {type => 'response', id => 'auth-3', ok => JSON::true},
    },
  );

  my $authorized = Overnet::Auth::CLI->run(
    argv => [
      'authorize',         '--program-id', 'p', '--scope', 's', '--action', 'a',
      '--service-locator', 'irc://x',      '--artifact-json', '{"type":"opaque"}',
      '--service-identity-scheme', 'nostr.pubkey', '--service-identity-value', ('b' x 64),
      '--no-pretty',
    ],
    client => $client,
  );
  is $authorized->{exit_code}, 0, 'authorize without identity or challenge succeeds';
  unlike $authorized->{output}, qr/\n\s+"ok"/, 'compact rendering omits pretty indentation';
  my $authorize_call = $client->calls->[0];
  ok !exists $authorize_call->{params}{identity_id}, 'the identity id is omitted when not supplied';
  ok !exists $authorize_call->{params}{challenge},   'the challenge is omitted when not supplied';
  ok !exists $authorize_call->{params}{service}{service_identity}{display},
    'the service identity display is omitted when not supplied';
  is $authorize_call->{params}{interactive}, JSON::true, 'interactive defaults to true';

  my $failed = Overnet::Auth::CLI->run(argv => ['renew', '--session-id', 'sess-9'], client => $client);
  is $failed->{exit_code}, 1, 'failed responses exit non-zero';
  is JSON::decode_json($failed->{output}), {ok => JSON::false, error => {}},
    'failed responses render an error envelope even without error details';
  is $client->calls->[1]{params}{interactive}, JSON::true, 'renew defaults to interactive';

  my $forgotten = Overnet::Auth::CLI->run(
    argv   => ['service-pin-forget', '--service-locator', 'irc://x'],
    client => $client,
  );
  is JSON::decode_json($forgotten->{output}), {ok => JSON::true, result => {}},
    'successful responses render an empty result when the agent omits one';
};

subtest 'client CLI script exists and prints help' => sub {
  ok -f $script, 'auth client script exists'
    or BAIL_OUT('auth client script is required');

  my $syntax = system($^X, "-I$libdir", '-c', $script);
  is $syntax >> 8, 0, 'auth client script has valid syntax';

  my $help = qx{$^X -I$libdir $script --help 2>&1};
  is $? >> 8, 0, '--help exits cleanly';
  like $help, qr/Usage:\s+overnet-auth\.pl\ identities/mx, '--help prints the command synopsis';
  like $help, qr/overnet-auth\.pl\ policies/mx,            '--help lists policies';
  like $help, qr/overnet-auth\.pl\ service-pin-set/mx,     '--help lists service pin management';
  like $help, qr/overnet-auth\.pl\ sessions/mx,            '--help lists sessions';
};

done_testing;

sub _write_file {
  my ($path, $content) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} $content
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
  return;
}
