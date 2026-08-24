use strictures 2;

use JSON ();
use Test2::V0;

use Overnet::Auth::Agent;
use Overnet::Core::Nostr;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

{

  package t::auth_agent::CountingBackend;

  use Moo;

  has calls  => (is => 'rw', default => sub {0});
  has secret => (is => 'ro');

  no Moo;

  sub load_signing_key {
    my ($self) = @_;
    $self->{calls}++;
    return (Overnet::Core::Nostr->load_key(privkey => $self->{secret}), undef,);
  }

}

sub _direct_secret_identity {
  return {
    identity_id     => 'default',
    backend_type    => 'direct_secret',
    backend_config  => {secret => $fixture_secret},
    public_identity => {
      scheme => 'nostr.pubkey',
      value  => $fixture_pubkey,
    },
  };
}

sub _authorize_request {
  my (%overrides) = @_;
  my %params = (
    program_id  => 'irc.bridge',
    identity_id => 'default',
    service     => {
      locators => ['irc://irc.example.test/overnet'],
    },
    scope     => 'irc://irc.example.test/overnet',
    action    => 'session.authenticate',
    challenge => {
      type  => 'opaque',
      value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
    },
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => 22242,
          tags => [
            [relay     => 'irc://irc.example.test/overnet'],
            [challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'],
          ],
        },
      },
    ],
    %overrides,
  );
  return {
    type   => 'request',
    id     => 'authorize-approval-1',
    method => 'sessions.authorize',
    params => \%params,
  };
}

subtest 'sessions.authorize fails closed by default when no policy matches' => sub {
  my $agent = Overnet::Auth::Agent->new(identities => [_direct_secret_identity()],);

  my $response = $agent->dispatch(_authorize_request());

  is $response->{ok}, 0, 'unattended authorize is denied without a matching policy';
  is $response->{error}{code}, 'auth.headless_unavailable',
    'the default agent fails closed rather than signing';
};

subtest 'sessions.authorize ignores a client-supplied interactive flag' => sub {
  my $agent = Overnet::Auth::Agent->new(identities => [_direct_secret_identity()],);

  my $response = $agent->dispatch(_authorize_request(interactive => JSON::true));

  is $response->{ok}, 0, 'a client interactive flag does not grant approval';
  is $response->{error}{code}, 'auth.headless_unavailable',
    'client-asserted interactivity cannot authorize signing';
};

subtest 'sessions.authorize allows unattended approval only when the agent opts in' => sub {
  my $agent = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [_direct_secret_identity()],
  );

  my $response = $agent->dispatch(_authorize_request());

  is $response->{ok}, 1, 'an opted-in agent auto-approves without a policy';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey,
    'the opted-in authorize still signs with the identity';
};

subtest 'sessions.authorize uses the direct_secret backend type' => sub {
  my $agent = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [
      {
        identity_id    => 'default',
        backend_type   => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch(
    {
      type   => 'request',
      id     => 'auth-direct-1',
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      },
    }
  );

  is $response->{ok}, 1, 'authorize succeeds';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey,
    'authorize signs with the direct_secret backend identity';
};

subtest 'sessions.authorize uses the pass backend type' => sub {
  my @seen;
  my $agent = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [
      {
        identity_id    => 'default',
        backend_type   => 'pass',
        backend_config => {
          entry          => 'overnet-priv-key',
          command_runner => sub {
            @seen = @_;
            return ($fixture_secret . "\n", undef);
          },
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch(
    {
      type   => 'request',
      id     => 'auth-pass-1',
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      },
    }
  );

  is $response->{ok}, 1,                                    'authorize succeeds';
  is \@seen,          ['pass', 'show', 'overnet-priv-key'], 'agent routed through the pass backend';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey,
    'authorize signs with the pass backend identity';
};

subtest 'sessions.authorize reports auth.backend_unavailable for an unknown backend type' => sub {
  my $agent = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [
      {
        identity_id     => 'default',
        backend_type    => 'unknown-backend',
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch(
    {
      type   => 'request',
      id     => 'auth-unknown-1',
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      },
    }
  );

  is $response->{ok}, 0, 'authorize fails';
  is $response->{error}{code}, 'auth.backend_unavailable',
    'unknown backend type is reported as auth.backend_unavailable';
};

subtest 'sessions.authorize honors an injected backend instance' => sub {
  my $backend = t::auth_agent::CountingBackend->new(secret => $fixture_secret);
  my $agent   = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [
      {
        identity_id     => 'default',
        backend         => $backend,
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch(
    {
      type   => 'request',
      id     => 'auth-object-1',
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      },
    }
  );

  is $response->{ok}, 1, 'authorize succeeds';
  is $backend->calls, 1, 'the injected backend instance was used';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey,
    'authorize signs with the injected backend identity';
};

subtest 'sessions.authorize invokes the backend for each authorization request' => sub {
  my $backend = t::auth_agent::CountingBackend->new(secret => $fixture_secret);
  my $agent   = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [
      {
        identity_id     => 'default',
        backend         => $backend,
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  for my $id (1, 2) {
    my $response = $agent->dispatch(
      {
        type   => 'request',
        id     => "auth-repeat-$id",
        method => 'sessions.authorize',
        params => {
          program_id  => 'irc.bridge',
          identity_id => 'default',
          service     => {
            locators => ['irc://irc.example.test/overnet'],
          },
          scope     => 'irc://irc.example.test/overnet',
          action    => 'session.authenticate',
          challenge => {
            type  => 'opaque',
            value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
          },
          artifacts => [
            {
              type   => 'nostr.event',
              params => {
                kind => 22242,
                tags => [
                  [
                    relay => 'irc://irc.example.test/overnet'
                  ],
                  [
                    challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                  ],
                ],
              },
            },
          ],
        },
      }
    );

    is $response->{ok}, 1, "authorize $id succeeds";
  }

  is $backend->calls, 2, 'the backend was invoked for both authorization requests';
};

subtest 'sessions.renew propagates auth.backend_unavailable when the identity backend fails' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id    => 'default',
        backend_type   => 'pass',
        backend_config => {
          entry          => 'overnet-priv-key',
          command_runner => sub {
            return (undef, 'pass show failed');
          },
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    policies => [
      {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
        locators    => ['irc://irc.example.test/overnet'],
      },
    ],
    sessions => [
      {
        session_handle => {id => 'sess-1'},
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        renewable => 1,
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      },
    ],
  );

  my $renew = $agent->dispatch(
    {
      type   => 'request',
      id     => 'renew-backend-1',
      method => 'sessions.renew',
      params => {
        session_handle => {id => 'sess-1'},
        challenge      => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        interactive => 0,
      },
    }
  );

  is $renew->{ok},          0,                          'renew fails';
  is $renew->{error}{code}, 'auth.backend_unavailable', 'renew surfaces the backend failure';
};

subtest 'sessions.revoke drops one stored session so later renew fails' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id     => 'default',
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => '274722f14ff06e2a790322ae1cee2d28c9cb0ffcd18d78d3bc7cca3f19e9764d',
        },
      },
    ],
    sessions => [
      {
        session_handle => {id => 'sess-1'},
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators         => ['wss://relay.example.test/auth'],
          service_identity => {
            scheme => 'nostr.pubkey',
            value  => '1111111111111111111111111111111111111111111111111111111111111111',
          },
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.delegate',
        renewable => 1,
        artifacts => [],
      },
    ],
  );

  my $revoke = $agent->dispatch(
    {
      type   => 'request',
      id     => 'revoke-1',
      method => 'sessions.revoke',
      params => {
        session_handle => {id => 'sess-1'},
      },
    }
  );

  is $revoke->{ok}, 1, 'revoke succeeds';

  my $renew = $agent->dispatch(
    {
      type   => 'request',
      id     => 'renew-1',
      method => 'sessions.renew',
      params => {
        session_handle => {id => 'sess-1'},
        interactive    => 0,
      },
    }
  );

  is $renew->{ok},          0,                         'renew fails after revoke';
  is $renew->{error}{code}, 'protocol.invalid_params', 'renew reports an unknown session handle';
};

subtest 'sessions.revoke succeeds without consulting an unavailable backend' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id    => 'default',
        backend_type   => 'pass',
        backend_config => {
          entry          => 'overnet-priv-key',
          command_runner => sub {
            return (undef, 'pass show failed');
          },
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    sessions => [
      {
        session_handle => {id => 'sess-1'},
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        renewable => 1,
        artifacts => [],
      },
    ],
  );

  my $revoke = $agent->dispatch(
    {
      type   => 'request',
      id     => 'revoke-backend-1',
      method => 'sessions.revoke',
      params => {
        session_handle => {id => 'sess-1'},
      },
    }
  );

  is $revoke->{ok}, 1, 'revoke succeeds';
  is $revoke->{result}, {}, 'revoke does not depend on backend availability';
};

subtest 'policies.grant enables matching headless authorization until policies.revoke removes it' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id    => 'default',
        backend_type   => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    service_pins => {
      'wss://relay.example.test/auth' => {
        scheme => 'nostr.pubkey',
        value  => ('1' x 64),
      },
    },
  );

  my $grant = $agent->dispatch(
    {
      type   => 'request',
      id     => 'policy-grant-1',
      method => 'policies.grant',
      params => {
        policy => {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          service     => {
            locators         => ['wss://relay.example.test/auth'],
            service_identity => {
              scheme => 'nostr.pubkey',
              value  => ('1' x 64),
            },
          },
          scope  => 'irc://irc.example.test/overnet',
          action => 'session.delegate',
        },
      },
    }
  );

  is $grant->{ok},                        1,          'policy grant succeeds';
  is $grant->{result}{policy}{policy_id}, 'policy-1', 'policy ids are assigned deterministically';

  my $headless = $agent->dispatch(
    {
      type   => 'request',
      id     => 'authorize-policy-1',
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        interactive => JSON::false,
        service     => {
          locators         => ['wss://relay.example.test/auth'],
          service_identity => {
            scheme => 'nostr.pubkey',
            value  => ('1' x 64),
          },
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.delegate',
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 14142,
              tags => [
                [relay      => 'wss://relay.example.test/auth'],
                [server     => 'irc://irc.example.test/overnet'],
                [delegate   => ('d' x 64)],
                [session    => 'session-123'],
                [expires_at => '1776884345'],
              ],
            },
          },
        ],
      },
    }
  );

  is $headless->{ok}, 1, 'granted policy allows headless authorization';

  my $revoke = $agent->dispatch(
    {
      type   => 'request',
      id     => 'policy-revoke-1',
      method => 'policies.revoke',
      params => {
        policy_id => 'policy-1',
      },
    }
  );

  is $revoke->{ok}, 1, 'policy revoke succeeds';

  my $after_revoke = $agent->dispatch(
    {
      type   => 'request',
      id     => 'authorize-policy-2',
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        interactive => JSON::false,
        service     => {
          locators         => ['wss://relay.example.test/auth'],
          service_identity => {
            scheme => 'nostr.pubkey',
            value  => ('1' x 64),
          },
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.delegate',
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 14142,
              tags => [
                [relay      => 'wss://relay.example.test/auth'],
                [server     => 'irc://irc.example.test/overnet'],
                [delegate   => ('d' x 64)],
                [session    => 'session-456'],
                [expires_at => '1776884345'],
              ],
            },
          },
        ],
      },
    }
  );

  is $after_revoke->{ok},          0, 'headless authorization fails again after policy revoke';
  is $after_revoke->{error}{code}, 'auth.headless_unavailable', 'revoked policy no longer matches';
};

subtest 'policies.list and sessions.list expose stored auth state' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id    => 'default',
        backend_type   => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    policies => [
      {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        locators    => ['irc://irc.example.test/overnet'],
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
      },
    ],
    sessions => [
      {
        session_handle => {id => 'sess-1'},
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => ['irc://irc.example.test/overnet'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        renewable => 1,
        artifacts => [],
      },
    ],
  );

  my $policies = $agent->dispatch(
    {
      type   => 'request',
      id     => 'policies-list-1',
      method => 'policies.list',
      params => {},
    }
  );
  my $sessions = $agent->dispatch(
    {
      type   => 'request',
      id     => 'sessions-list-1',
      method => 'sessions.list',
      params => {},
    }
  );

  is $policies->{ok}, 1, 'policies.list succeeds';
  is $policies->{result}{policies},
    [
    {
      policy_id   => 'policy-1',
      identity_id => 'default',
      program_id  => 'irc.bridge',
      locators    => ['irc://irc.example.test/overnet'],
      scope       => 'irc://irc.example.test/overnet',
      action      => 'session.authenticate',
    },
    ],
    'policies.list returns stored policies with ids';
  is $sessions->{ok}, 1, 'sessions.list succeeds';
  is $sessions->{result}{sessions},
    [
    {
      session_handle => {id => 'sess-1'},
      identity_id    => 'default',
      program_id     => 'irc.bridge',
      service        => {
        locators => ['irc://irc.example.test/overnet'],
      },
      scope     => 'irc://irc.example.test/overnet',
      action    => 'session.authenticate',
      renewable => 1,
    },
    ],
    'sessions.list returns stored sessions';
};

subtest 'sessions.list tolerates seeded sessions with missing fields' => sub {
  my $agent = Overnet::Auth::Agent->new(
    sessions => [
      {
        session_handle => {id => 'sess-1'},
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        scope          => 'irc://irc.example.test/overnet',
        action         => 'session.authenticate',
      },
    ],
  );

  my $sessions = $agent->dispatch(
    {
      type   => 'request',
      id     => 'sessions-list-sparse-1',
      method => 'sessions.list',
      params => {},
    }
  );

  is $sessions->{ok}, 1, 'sessions.list succeeds for a session without a service field';
  is $sessions->{result}{sessions},
    [
    {
      session_handle => {id => 'sess-1'},
      identity_id    => 'default',
      program_id     => 'irc.bridge',
      service        => undef,
      scope          => 'irc://irc.example.test/overnet',
      action         => 'session.authenticate',
      renewable      => 0,
    },
    ],
    'the missing service field is reported as undef without shifting descriptor keys';
};

subtest 'service_pins.set, service_pins.list, and service_pins.forget manage pinned service identities' => sub {
  my $agent = Overnet::Auth::Agent->new;

  my $set = $agent->dispatch(
    {
      type   => 'request',
      id     => 'service-pin-set-1',
      method => 'service_pins.set',
      params => {
        locator          => 'wss://relay.example.test/auth',
        service_identity => {
          scheme  => 'nostr.pubkey',
          value   => ('1' x 64),
          display => 'relay.example.test authority',
        },
      },
    }
  );

  is $set->{ok}, 1, 'service pin set succeeds';

  my $list = $agent->dispatch(
    {
      type   => 'request',
      id     => 'service-pins-list-1',
      method => 'service_pins.list',
      params => {},
    }
  );

  is $list->{ok}, 1, 'service_pins.list succeeds';
  is $list->{result}{service_pins},
    [
    {
      locator          => 'wss://relay.example.test/auth',
      service_identity => {
        scheme  => 'nostr.pubkey',
        value   => ('1' x 64),
        display => 'relay.example.test authority',
      },
    },
    ],
    'service_pins.list returns the stored pin';

  my $forget = $agent->dispatch(
    {
      type   => 'request',
      id     => 'service-pin-forget-1',
      method => 'service_pins.forget',
      params => {
        locator => 'wss://relay.example.test/auth',
      },
    }
  );

  is $forget->{ok}, 1, 'service pin forget succeeds';

  my $empty = $agent->dispatch(
    {
      type   => 'request',
      id     => 'service-pins-list-2',
      method => 'service_pins.list',
      params => {},
    }
  );

  is $empty->{result}{service_pins}, [], 'forgotten service pins are removed';
};

subtest 'policies.grant advances policy ids past preloaded policy ids and accepts service_identity-only policies' =>
  sub {
  my $agent = Overnet::Auth::Agent->new(
    policies => [
      {
        policy_id        => 'policy-9',
        identity_id      => 'default',
        program_id       => 'irc.bridge',
        service_identity => {
          scheme => 'nostr.pubkey',
          value  => ('1' x 64),
        },
        scope  => 'irc://irc.example.test/overnet',
        action => 'session.delegate',
      },
    ],
  );

  my $grant = $agent->dispatch(
    {
      type   => 'request',
      id     => 'policy-grant-2',
      method => 'policies.grant',
      params => {
        policy => {
          identity_id      => 'default',
          program_id       => 'irc.bridge',
          service_identity => {
            scheme => 'nostr.pubkey',
            value  => ('2' x 64),
          },
          scope  => 'irc://irc.example.test/overnet',
          action => 'session.delegate',
        },
      },
    }
  );

  is $grant->{ok},                        1,           'policy grant succeeds';
  is $grant->{result}{policy}{policy_id}, 'policy-10', 'policy ids advance past preloaded ids';
  is $grant->{result}{policy}{service_identity},
    {
    scheme => 'nostr.pubkey',
    value  => ('2' x 64),
    },
    'service_identity-only policies are accepted';
  };

subtest 'state_writer persists policy and service-pin changes' => sub {
  my @writes;
  my $agent = Overnet::Auth::Agent->new(
    state_writer => sub {
      my ($state) = @_;
      push @writes, $state;
      return 1;
    },
  );

  my $grant = $agent->dispatch(
    {
      type   => 'request',
      id     => 'policy-grant-write-1',
      method => 'policies.grant',
      params => {
        policy => {
          identity_id      => 'default',
          program_id       => 'irc.bridge',
          service_identity => {
            scheme => 'nostr.pubkey',
            value  => ('1' x 64),
          },
          scope  => 'irc://irc.example.test/overnet',
          action => 'session.delegate',
        },
      },
    }
  );
  my $set = $agent->dispatch(
    {
      type   => 'request',
      id     => 'service-pin-set-write-1',
      method => 'service_pins.set',
      params => {
        locator          => 'wss://relay.example.test/auth',
        service_identity => {
          scheme => 'nostr.pubkey',
          value  => ('2' x 64),
        },
      },
    }
  );

  is $grant->{ok},                       1,          'policy grant succeeds';
  is $set->{ok},                         1,          'service pin set succeeds';
  is scalar(@writes),                    2,          'state_writer was invoked for both mutations';
  is $writes[0]{policies}[0]{policy_id}, 'policy-1', 'policy grant persisted policy state';
  is $writes[1]{service_pins}{'wss://relay.example.test/auth'}{value},
    ('2' x 64),
    'service pin set persisted service-pin state';
};

subtest 'authorize and revoke persist session state and roll back on state write failure' => sub {
  my @writes;
  my $fail  = 0;
  my $agent = Overnet::Auth::Agent->new(
    allow_unattended_autoapprove => 1,
    identities                   => [
      {
        identity_id    => 'default',
        backend_type   => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    state_writer => sub {
      my ($state) = @_;
      die "write failed\n" if $fail;
      push @writes, $state;
      return 1;
    },
  );

  my $authorize = $agent->dispatch(
    {
      type   => 'request',
      id     => 'authorize-write-1',
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators         => ['wss://relay.example.test/auth'],
          service_identity => {
            scheme => 'nostr.pubkey',
            value  => ('1' x 64),
          },
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [relay => 'irc://irc.example.test/overnet'],
                [
                  challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f'
                ],
              ],
            },
          },
        ],
      },
    }
  );

  is $authorize->{ok},                      1, 'authorize succeeds';
  is scalar(@{$writes[0]{sessions} || []}), 1, 'authorize persisted a session';
  is $writes[0]{service_pins}{'wss://relay.example.test/auth'}{value},
    ('1' x 64),
    'authorize persisted first-contact service pin state';

  my $revoke = $agent->dispatch(
    {
      type   => 'request',
      id     => 'revoke-write-1',
      method => 'sessions.revoke',
      params => {
        session_handle => {id => $authorize->{result}{session_handle}{id}},
      },
    }
  );

  is $revoke->{ok},        1,  'revoke succeeds';
  is $writes[1]{sessions}, [], 'revoke persisted session removal';

  $fail = 1;
  my $failed = $agent->dispatch(
    {
      type   => 'request',
      id     => 'policy-grant-write-fail-1',
      method => 'policies.grant',
      params => {
        policy => {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => ['irc://irc.example.test/overnet'],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      },
    }
  );
  my $policies = $agent->dispatch(
    {
      type   => 'request',
      id     => 'policies-list-after-fail-1',
      method => 'policies.list',
      params => {},
    }
  );

  is $failed->{ok},                 0,                       'failed persistence turns the mutation into an error';
  is $failed->{error}{code},        'auth.internal_failure', 'state write failure is surfaced';
  is $policies->{result}{policies}, [],                      'failed persistence rolled the in-memory mutation back';
};

subtest 'unexpected handler failures surface as auth.internal_failure responses' => sub {
  my $agent = Overnet::Auth::Agent->new;

  no warnings 'redefine';
  local *Overnet::Auth::Agent::_dispatch_sessions_list = sub { die "session store exploded\n" };
  use warnings 'redefine';

  my $response = $agent->dispatch(
    {
      type   => 'request',
      id     => 'internal-failure-1',
      method => 'sessions.list',
      params => {},
    }
  );

  is $response->{type},           'response',               'unexpected failure still yields a response';
  is $response->{id},             'internal-failure-1',     'response is correlated to the request';
  is $response->{ok},             0,                        'unexpected failure is not ok';
  is $response->{error}{code},    'auth.internal_failure',  'unexpected failure uses auth.internal_failure';
  is $response->{error}{message}, 'session store exploded', 'failure message is preserved without trailing newline';
};

sub _request {
  my ($method, $params, %overrides) = @_;
  return {
    type   => 'request',
    id     => 'edge-1',
    method => $method,
    params => $params,
    %overrides,
  };
}

sub _dispatch_error {
  my ($agent, $method, $params, %overrides) = @_;
  my $response = $agent->dispatch(_request($method, $params, %overrides));
  return $response->{error};
}

subtest 'dispatch rejects malformed request envelopes' => sub {
  my $agent = Overnet::Auth::Agent->new(identities => [_direct_secret_identity()]);

  my $not_object = $agent->dispatch('junk');
  is $not_object->{error}{code}, 'protocol.invalid_message', 'non-object requests are refused';
  is $not_object->{id}, undef, 'no id is echoed for non-object requests';

  my $no_method = $agent->dispatch({type => 'request', id => ['ref-id']});
  is $no_method->{error}{message}, 'method is required', 'a method is required';
  is $no_method->{id}, undef, 'reference ids are not echoed';

  is $agent->dispatch({type => 'request', id => 'e', method => q{}})->{error}{message},
    'method is required', 'empty methods are refused';

  like(
    dies { Overnet::Auth::Agent->new('odd') },
    qr/constructor arguments must be a hash/,
    'odd constructor arguments die',
  );
};

subtest 'constructor state ingestion skips malformed entries' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => ['junk', {identity_id => []}, {identity_id => q{}}, _direct_secret_identity()],
    policies   => [
      'junk',
      {identity_id => 'default'},
      {
        policy_id   => 'policy-7',
        identity_id => 'default',
        program_id  => 'irc.bridge',
        scope       => 's',
        action      => 'session.authenticate',
        locators    => ['irc://x'],
      },
      {
        policy_id   => 'custom-id',
        identity_id => 'default',
        program_id  => 'irc.bridge',
        scope       => 's',
        action      => 'session.authenticate',
        locator     => 'irc://y',
      },
    ],
    service_pins => {
      'irc://pinned' => {scheme => 'nostr.pubkey', value => ('a' x 64)},
      'irc://junk'   => 'junk',
    },
    sessions => [
      'junk',
      {identity_id => 'default'},
      {
        session_handle => {id => 'sess-1'},
        identity_id    => 'default',
        service        => {locators => ['irc://x']},
        renewable      => 1,
        expires_at     => 12_345,
      },
    ],
  );

  my $identities = $agent->dispatch(_request('identities.list', {}));
  is scalar(@{$identities->{result}{identities}}), 1, 'malformed identities are skipped';
  is $identities->{result}{identities}[0]{backend_type}, 'direct_secret',
    'identity backend types are reported';

  my $policies = $agent->dispatch(_request('policies.list', {}));
  is scalar(@{$policies->{result}{policies}}), 2, 'malformed policies are skipped';
  is $policies->{result}{policies}[1]{locators}, ['irc://y'],
    'single-locator policies normalize to locator lists';

  my $pins = $agent->dispatch(_request('service_pins.list', {}));
  is scalar(@{$pins->{result}{service_pins}}), 1, 'malformed service pins are skipped';

  my $sessions = $agent->dispatch(_request('sessions.list', {}));
  is scalar(@{$sessions->{result}{sessions}}), 1, 'malformed sessions are skipped';
  is $sessions->{result}{sessions}[0]{expires_at}, 12_345, 'session expirations are reported';

  my $granted = $agent->dispatch(
    _request(
      'policies.grant',
      {
        policy => {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          scope       => 's',
          action      => 'session.authenticate',
          locators    => ['irc://z'],
        },
      },
    ),
  );
  is $granted->{result}{policy}{policy_id}, 'policy-8',
    'granted policy ids continue after the highest seeded policy number';
};

subtest 'handler params validation rejects malformed inputs' => sub {
  my $agent = Overnet::Auth::Agent->new(identities => [_direct_secret_identity()]);

  for my $method (
    qw(policies.grant policies.revoke service_pins.set service_pins.forget
    sessions.renew sessions.revoke sessions.authorize)
  ) {
    is _dispatch_error($agent, $method, 'junk')->{message}, 'params must be an object',
      "$method requires object params";
  }

  is _dispatch_error($agent, 'policies.grant', {policy => {identity_id => 'default'}})->{message},
    'policy must be a valid policy object', 'incomplete policies are refused';
  is _dispatch_error(
    $agent, 'policies.grant',
    {
      policy => {
        identity_id => 'default', program_id => 'p', scope => 's', action => 'a',
        locators    => [[], q{}],
      },
    },
  )->{message}, 'policy must be a valid policy object',
    'policies whose locators normalize to nothing are refused';
  is _dispatch_error($agent, 'policies.revoke', {})->{message}, 'policy_id is required',
    'policy revocation requires a policy id';
  is _dispatch_error($agent, 'policies.revoke', {policy_id => q{}})->{message},
    'policy_id is required', 'empty policy ids are refused';

  is _dispatch_error($agent, 'service_pins.set', {locator => q{}})->{message},
    'locator is required', 'pin set requires a locator';
  is _dispatch_error($agent, 'service_pins.set', {locator => 'irc://x', service_identity => 'junk'})->{message},
    'service_identity must be a valid descriptor', 'pin set requires a descriptor object';
  is _dispatch_error(
    $agent, 'service_pins.set',
    {locator => 'irc://x', service_identity => {scheme => q{}, value => 'v'}},
  )->{message}, 'service_identity must be a valid descriptor', 'descriptors need a scheme';
  is _dispatch_error(
    $agent, 'service_pins.set',
    {locator => 'irc://x', service_identity => {scheme => 's', value => q{}}},
  )->{message}, 'service_identity must be a valid descriptor', 'descriptors need a value';
  is _dispatch_error($agent, 'service_pins.forget', {locator => q{}})->{message},
    'locator is required', 'pin forget requires a locator';

  my $pinned = $agent->dispatch(
    _request(
      'service_pins.set',
      {
        locator          => 'irc://x',
        service_identity => {scheme => 's', value => 'v', display => q{}},
      },
    ),
  );
  ok !exists $pinned->{result}{service_identity}{display},
    'empty display values are elided from stored pins';

  is _dispatch_error($agent, 'sessions.renew', {})->{message},
    'session_handle.id is required', 'renew requires a session handle';
  is _dispatch_error($agent, 'sessions.renew', {session_handle => {id => q{}}})->{message},
    'session_handle.id is required', 'empty session handles are refused';
  is _dispatch_error($agent, 'sessions.renew', {session_handle => 'junk'})->{message},
    'session_handle.id is required', 'non-object session handles are refused';
  is _dispatch_error($agent, 'sessions.revoke', {})->{message},
    'session_handle.id is required', 'revoke requires a session handle';
};

subtest 'identity resolution failures' => sub {
  my $agent = Overnet::Auth::Agent->new(identities => [_direct_secret_identity()]);
  my $error = _dispatch_error($agent, 'sessions.authorize', _authorize_request()->{params});
  isnt $error->{code}, 'auth.unknown_identity', 'sanity: the default identity resolves';

  my $unknown = $agent->dispatch(_authorize_request(identity_id => 'ghost'));
  is $unknown->{error}{code}, 'auth.unknown_identity', 'unknown identity ids are refused';

  my $two = Overnet::Auth::Agent->new(
    identities => [_direct_secret_identity(), {%{_direct_secret_identity()}, identity_id => 'second'}],
    allow_unattended_autoapprove => JSON::true,
  );
  my $ambiguous = $two->dispatch(_authorize_request(identity_id => undef));
  is $ambiguous->{error}{code}, 'auth.identity_required',
    'multiple identities require an explicit identity id';

  my $one = Overnet::Auth::Agent->new(
    identities                   => [_direct_secret_identity()],
    allow_unattended_autoapprove => JSON::true,
  );
  my $defaulted = $one->dispatch(_authorize_request(identity_id => undef));
  is $defaulted->{result}{identity_id}, 'default',
    'a single identity is used as the default';
};

subtest 'authorize parameter validation' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities                   => [_direct_secret_identity()],
    allow_unattended_autoapprove => JSON::true,
  );
  my $authorize_error = sub {
    my (%overrides) = @_;
    return $agent->dispatch(_authorize_request(%overrides))->{error};
  };

  is $authorize_error->(program_id => q{})->{message}, 'program_id is required',
    'a program id is required';
  is $authorize_error->(scope => q{})->{message}, 'scope is required', 'a scope is required';
  is $authorize_error->(service => 'junk')->{message}, 'service must be an object',
    'the service must be an object';
  is $authorize_error->(service => {locators => []})->{message},
    'service.locators must be a non-empty array', 'service locators are required';
  my $unsupported = $authorize_error->(action => 'session.other');
  is $unsupported->{code}, 'auth.unsupported_action', 'unsupported actions are refused';
  is $authorize_error->(artifacts => [])->{message}, 'artifacts must be a non-empty array',
    'artifacts are required';
  is $authorize_error->(artifacts => ['junk'])->{message}, 'artifact must be an object',
    'artifacts must be objects';
  is $authorize_error->(artifacts => [{type => 'opaque'}])->{code}, 'auth.unsupported_artifact',
    'non-nostr artifacts are refused';
  is $authorize_error->(artifacts => [{type => 'nostr.event', params => 'junk'}])->{message},
    'artifact params must be an object', 'artifact params must be objects';
  is $authorize_error->(challenge => undef)->{message},
    'challenge.value is required for session.authenticate', 'a challenge is required';
  is $authorize_error->(challenge => {value => q{}})->{message},
    'challenge.value is required for session.authenticate', 'empty challenge values are refused';
  is $authorize_error->(artifacts => [{type => 'nostr.event', params => {kind => 1}}])->{message},
    'session.authenticate requires kind 22242 nostr.event artifact',
    'authenticate artifacts must be kind 22242';

  my $backendless = Overnet::Auth::Agent->new(
    identities                   => [{identity_id => 'default', backend_type => 'gpg'}],
    allow_unattended_autoapprove => JSON::true,
  );
  is $backendless->dispatch(_authorize_request())->{error}{message},
    'unsupported backend_type: gpg', 'unsupported backend types are refused';

  my $empty_backend_type = Overnet::Auth::Agent->new(
    identities => [{%{_direct_secret_identity()}, backend_type => q{}}],
    allow_unattended_autoapprove => JSON::true,
  );
  ok $empty_backend_type->dispatch(_authorize_request())->{ok},
    'an empty backend type defaults to direct_secret';
};

subtest 'session delegation artifacts validate their tags' => sub {
  my $delegate_tags = sub {
    my (%tags) = @_;
    my %all = (
      relay      => 'wss://relay.example',
      server     => 'irc://irc.example.test/overnet',
      delegate   => ('d' x 64),
      session    => 'sess-remote',
      expires_at => '12345',
      %tags,
    );
    return [map { [$_, $all{$_}] } grep { defined $all{$_} } sort keys %all];
  };
  my $agent = Overnet::Auth::Agent->new(
    identities                   => [_direct_secret_identity()],
    allow_unattended_autoapprove => JSON::true,
  );
  my $delegate = sub {
    my ($tags, %artifact) = @_;
    return $agent->dispatch(
      _authorize_request(
        action    => 'session.delegate',
        challenge => undef,
        artifacts => [{type => 'nostr.event', params => {kind => 14_142, tags => $tags, %artifact}}],
      ),
    );
  };

  ok $delegate->($delegate_tags->())->{ok}, 'a fully-tagged delegation artifact authorizes';

  is $delegate->($delegate_tags->(), kind => 1)->{error}{message},
    'session.delegate requires kind 14142 nostr.event artifact',
    'delegation artifacts must be kind 14142';
  like $delegate->($delegate_tags->(relay => undef))->{error}{message},
    qr/relay tag is required/, 'the relay tag is required';
  like $delegate->($delegate_tags->(server => 'irc://other'))->{error}{message},
    qr/server tag must match/, 'the server tag must match the scope';
  like $delegate->($delegate_tags->(delegate => 'short'))->{error}{message},
    qr/delegate tag/, 'the delegate tag must be a pubkey';
  like $delegate->($delegate_tags->(session => q{}))->{error}{message},
    qr/session tag is required/, 'the session tag is required';
  like $delegate->($delegate_tags->(expires_at => 'soon'))->{error}{message},
    qr/expires_at tag/, 'the expiration tag must be numeric';
};

subtest 'authenticate artifacts must match the requested scope and challenge' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities                   => [_direct_secret_identity()],
    allow_unattended_autoapprove => JSON::true,
  );
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';

  my $wrong_relay = $agent->dispatch(
    _authorize_request(
      artifacts => [
        {
          type   => 'nostr.event',
          params => {kind => 22_242, tags => [[relay => 'irc://other'], [challenge => $challenge]]},
        },
      ],
    ),
  );
  like $wrong_relay->{error}{message}, qr/relay tag must match/,
    'mismatched relay tags are refused';

  my $wrong_challenge = $agent->dispatch(
    _authorize_request(
      artifacts => [
        {
          type   => 'nostr.event',
          params => {
            kind => 22_242,
            tags => [[relay => 'irc://irc.example.test/overnet'], [challenge => 'other'], 'junk', ['solo']],
          },
        },
      ],
    ),
  );
  like $wrong_challenge->{error}{message}, qr/challenge tag must match/,
    'mismatched challenge tags are refused';
};

subtest 'service pins guard authorization' => sub {
  my $service_identity = {scheme => 'nostr.pubkey', value => ('b' x 64)};
  my $agent            = Overnet::Auth::Agent->new(
    identities                   => [_direct_secret_identity()],
    allow_unattended_autoapprove => JSON::true,
    service_pins                 => {
      'irc://pinned' => {scheme => 'nostr.pubkey', value => ('c' x 64)},
    },
  );

  my $mismatch = $agent->dispatch(
    _authorize_request(
      service => {locators => ['irc://pinned'], service_identity => $service_identity},
    ),
  );
  is $mismatch->{error}{code}, 'auth.service_identity_mismatch',
    'a mismatched pinned identity refuses authorization';

  my $known = $agent->dispatch(
    _authorize_request(
      service => {
        locators         => ['irc://pinned'],
        service_identity => {scheme => 'nostr.pubkey', value => ('c' x 64)},
      },
    ),
  );
  is $known->{result}{service_pin_state}, 'known', 'a matching pin reports known state';

  my $first = $agent->dispatch(
    _authorize_request(
      service => {locators => ['irc://fresh', q{}], service_identity => $service_identity},
    ),
  );
  is $first->{result}{service_pin_state}, 'first_contact',
    'an unpinned service identity reports first contact';
  my $pins = $agent->dispatch(_request('service_pins.list', {}));
  ok((grep { $_->{locator} eq 'irc://fresh' } @{$pins->{result}{service_pins}}),
    'first contact pins the presented identity');
  ok !(grep { $_->{locator} eq q{} } @{$pins->{result}{service_pins}}),
    'empty locators are never pinned';

  my $provisional = $agent->dispatch(_authorize_request());
  is $provisional->{result}{service_pin_state}, 'provisional',
    'no service identity reports provisional state';
};

subtest 'policy matching covers locator and identity comparisons' => sub {
  my %policy_base = (
    identity_id => 'default',
    program_id  => 'irc.bridge',
    scope       => 'irc://irc.example.test/overnet',
    action      => 'session.authenticate',
  );
  my $match_with = sub {
    my ($policy, %service) = @_;
    my $agent = Overnet::Auth::Agent->new(
      identities => [_direct_secret_identity()],
      policies   => [$policy],
    );
    return $agent->dispatch(_authorize_request(%service));
  };

  ok $match_with->({%policy_base, locators => ['irc://irc.example.test/overnet']})->{ok},
    'matching locators authorize';
  is $match_with->({%policy_base, program_id => 'other'})->{error}{code},
    'auth.headless_unavailable', 'a base field mismatch fails closed';
  is $match_with->({%policy_base, locators => ['irc://other']})->{error}{code},
    'auth.headless_unavailable', 'a locator mismatch fails closed';
  is $match_with->(
    {%policy_base, service_identity => {scheme => 's', value => 'v'}},
  )->{error}{code}, 'auth.headless_unavailable',
    'an identity-pinned policy does not match a locator-only request';
  ok $match_with->(
    {%policy_base, service_identity => {scheme => 's', value => 'v'}},
    service => {
      locators         => ['irc://irc.example.test/overnet'],
      service_identity => {scheme => 's', value => 'v'},
    },
  )->{ok}, 'matching service identities authorize';
  is $match_with->(
    {%policy_base, service_identity => {scheme => 's', value => 'v'}},
    service => {
      locators         => ['irc://irc.example.test/overnet'],
      service_identity => {scheme => 's', value => 'other'},
    },
  )->{error}{code}, 'auth.headless_unavailable', 'mismatched identity values fail closed';
  is $match_with->(
    {%policy_base, locators => ['irc://irc.example.test/overnet']},
    service => {
      locators         => ['irc://irc.example.test/overnet'],
      service_identity => {scheme => 's', value => 'v'},
    },
  )->{error}{code}, 'auth.headless_unavailable',
    'a locator-only policy does not vouch for a presented service identity';
};

subtest 'session renewal edge paths' => sub {
  my %session_base = (
    identity_id => 'default',
    program_id  => 'irc.bridge',
    service     => {locators => ['irc://irc.example.test/overnet']},
    scope       => 'irc://irc.example.test/overnet',
    action      => 'session.authenticate',
  );
  my %policy = (
    identity_id => 'default',
    program_id  => 'irc.bridge',
    scope       => 'irc://irc.example.test/overnet',
    action      => 'session.authenticate',
    locators    => ['irc://irc.example.test/overnet'],
  );

  my $renew = sub {
    my ($session, %agent_args) = @_;
    my $agent = Overnet::Auth::Agent->new(
      identities => [_direct_secret_identity()],
      sessions   => [$session],
      %agent_args,
    );
    return $agent->dispatch(
      _request(
        'sessions.renew',
        {
          session_handle => {id => 'sess-1'},
          challenge      => {type => 'opaque', value => 'renewed-challenge'},
        },
      ),
    );
  };

  is $renew->({})->{error}{message}, 'unknown session_handle', 'unknown sessions are refused';
  is $renew->({session_handle => {id => 'sess-1'}, %session_base})->{error}{code},
    'auth.policy_denied', 'non-renewable sessions are refused';
  is $renew->(
    {session_handle => {id => 'sess-1'}, %session_base, renewable => 1, identity_id => 'ghost'},
  )->{error}{code}, 'auth.unknown_identity', 'sessions for unknown identities are refused';
  is $renew->({session_handle => {id => 'sess-1'}, %session_base, renewable => 1})->{error}{code},
    'auth.policy_denied', 'sessions without a matching policy are refused';

  my $renewed = $renew->(
    {session_handle => {id => 'sess-1'}, %session_base, renewable => 1},
    policies => [\%policy],
  );
  ok $renewed->{ok}, 'a policy-backed session renews';
  is $renewed->{result}{artifacts}, [], 'sessions without artifacts renew with none';

  my $weird_action = $renew->(
    {
      session_handle => {id => 'sess-1'},
      %session_base,
      action    => 'session.wat',
      renewable => 1,
      artifacts => [{type => 'nostr.event', params => {kind => 22_242, tags => []}}],
    },
    policies => [{%policy, action => 'session.wat'}],
  );
  is $weird_action->{error}{code}, 'auth.unsupported_action',
    'stored sessions with unsupported actions cannot rebuild artifacts';
};

subtest 'state persistence failures roll back mutations' => sub {
  my %grant_params = (
    policy => {
      identity_id => 'default',
      program_id  => 'irc.bridge',
      scope       => 's',
      action      => 'session.authenticate',
      locators    => ['irc://x'],
    },
  );

  my $failing = Overnet::Auth::Agent->new(
    identities                   => [_direct_secret_identity()],
    allow_unattended_autoapprove => JSON::true,
    sessions                     => [{session_handle => {id => 'sess-1'}, service => {locators => ['irc://x']}}],
    state_writer                 => sub { die "disk exploded\n" },
  );

  for my $case (
    ['policies.grant',      {%grant_params}],
    ['policies.revoke',     {policy_id => 'policy-1'}],
    ['service_pins.set',    {locator => 'irc://x', service_identity => {scheme => 's', value => 'v'}}],
    ['service_pins.forget', {locator => 'irc://x'}],
    ['sessions.revoke',     {session_handle => {id => 'sess-1'}}],
  ) {
    my ($method, $params) = @{$case};
    my $error = _dispatch_error($failing, $method, $params);
    is $error->{code},    'auth.internal_failure', "$method reports the persistence failure";
    is $error->{message}, 'disk exploded',         "$method surfaces the writer error";
  }

  my $authorize_error = $failing->dispatch(_authorize_request());
  is $authorize_error->{error}{code}, 'auth.internal_failure',
    'authorize reports the persistence failure';

  is scalar(@{$failing->dispatch(_request('policies.list', {}))->{result}{policies}}), 0,
    'failed grants are rolled back';
  ok $failing->dispatch(_request('sessions.list', {}))->{result}{sessions}[0],
    'failed revocations are rolled back';

  my $false_writer = Overnet::Auth::Agent->new(
    identities   => [_direct_secret_identity()],
    state_writer => sub { return 0 },
  );
  is _dispatch_error($false_writer, 'policies.grant', {%grant_params})->{message},
    'auth state write failed', 'a writer returning false reports a generic failure';
};

done_testing;
