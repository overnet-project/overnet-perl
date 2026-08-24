use strictures 2;
use Test::More;
use JSON ();

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::SecretProvider;
use Overnet::Program::Services;

sub _structured_error (&) {
  my ($code) = @_;
  my $error;
  eval {
    $code->();
    1;
  } or $error = $@;
  return $error;
}

sub _random_bytes_cb {
  my $counter = 0;
  return sub {
    my ($length) = @_;
    $counter++;
    return chr(64 + $counter) x $length;
  };
}

subtest 'services issue opaque secret handles instead of raw values' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
    now_cb => sub {1_700_000_000_000},
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $result = $services->dispatch_request(
    'secrets.get',
    {name => 'api-token'},
    permissions => ['secrets.read'],
    session_id  => 'session-1',
    program_id  => 'secrets.program',
  );

  is $result->{name}, 'api-token', 'secrets.get returns the requested secret name';
  ok !exists $result->{value}, 'secrets.get does not expose the raw secret value';
  like $result->{secret_handle}{id}, qr/\Ash_[0-9a-f]{64}\z/mx, 'secret handle id is opaque';
  is $result->{secret_handle}{expires_at}, 1_700_000_300, 'secret handle expiry is returned';
};

subtest 'runtime resolves issued handles only inside the owning audience and before expiry' => sub {
  my $now     = 1_700_000_000_000;
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
    now_cb               => sub {$now},
    secret_handle_ttl_ms => 1_000,
    random_bytes_cb      => _random_bytes_cb(),
  );

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'secrets.program',
    name       => 'api-token',
    purpose    => 'adapters.open_session:secure.adapter:server_password',
  );
  my $handle_id = $issued->{secret_handle}{id};

  my $resolved = $runtime->resolve_secret_handle(
    session_id  => 'session-1',
    program_id  => 'secrets.program',
    handle_id   => $handle_id,
    method      => 'adapters.open_session',
    adapter_id  => 'secure.adapter',
    secret_slot => 'server_password',
    purpose     => 'adapters.open_session:secure.adapter:server_password',
  );
  is_deeply(
    $resolved,
    {
      name  => 'api-token',
      value => 'top-secret',
    },
    'runtime can resolve the handle internally for the owning audience',
  );

  my $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id  => 'session-2',
      program_id  => 'secrets.program',
      handle_id   => $handle_id,
      method      => 'adapters.open_session',
      adapter_id  => 'secure.adapter',
      secret_slot => 'server_password',
      purpose     => 'adapters.open_session:secure.adapter:server_password',
    );
  };
  is ref($error),       'HASH',                                'wrong-session resolution error is structured';
  is $error->{code},    'protocol.invalid_params',             'wrong-session handle use is invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'wrong-session handle use is redacted';

  $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id  => 'session-1',
      program_id  => 'secrets.program',
      handle_id   => $handle_id,
      method      => 'adapters.open_session',
      adapter_id  => 'secure.adapter',
      secret_slot => 'server_password',
      purpose     => 'adapters.open_session:secure.adapter:sasl_password',
    );
  };
  is ref($error),       'HASH',                                'wrong-purpose resolution error is structured';
  is $error->{code},    'protocol.invalid_params',             'wrong-purpose handle use is invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'wrong-purpose handle use is redacted';

  $now += 1_001;
  $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id  => 'session-1',
      program_id  => 'secrets.program',
      handle_id   => $handle_id,
      method      => 'adapters.open_session',
      adapter_id  => 'secure.adapter',
      secret_slot => 'server_password',
      purpose     => 'adapters.open_session:secure.adapter:server_password',
    );
  };
  is ref($error),    'HASH',                    'expired handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'expired handle is no longer resolvable';
};

subtest 'abnormal session teardown revokes outstanding secret handles' => sub {
  my $now     = 1_700_000_000_000;
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
    now_cb               => sub {$now},
    secret_handle_ttl_ms => 300_000,
    random_bytes_cb      => _random_bytes_cb(),
  );

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'secrets.program',
    name       => 'api-token',
    purpose    => 'adapters.open_session:secure.adapter:server_password',
  );
  my $handle_id = $issued->{secret_handle}{id};

  my $resolved = $runtime->resolve_secret_handle(
    session_id  => 'session-1',
    program_id  => 'secrets.program',
    handle_id   => $handle_id,
    method      => 'adapters.open_session',
    adapter_id  => 'secure.adapter',
    secret_slot => 'server_password',
    purpose     => 'adapters.open_session:secure.adapter:server_password',
  );
  is $resolved->{value}, 'top-secret', 'handle resolves before teardown';

  # A program that dies without an orderly runtime.shutdown is reaped through
  # release_session_resources. Outstanding secret handles for the session must
  # be revoked here, not left resolvable until their TTL expires. The TTL is
  # long and time does not advance, so revocation is the only thing that can
  # invalidate the handle.
  my $released = $runtime->release_session_resources(session_id => 'session-1');
  is $released->{secret_handles_revoked}, 1, 'teardown reports the revoked handle';

  my $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id  => 'session-1',
      program_id  => 'secrets.program',
      handle_id   => $handle_id,
      method      => 'adapters.open_session',
      adapter_id  => 'secure.adapter',
      secret_slot => 'server_password',
      purpose     => 'adapters.open_session:secure.adapter:server_password',
    );
  };
  is ref($error),    'HASH',                    'revoked handle resolution error is structured';
  is $error->{code}, 'protocol.invalid_params', 'handle is no longer resolvable after abnormal teardown';
};

subtest 'services reject invalid or unavailable secrets.get params without name enumeration' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error = _structured_error {
    $services->dispatch_request(
      'secrets.get',
      {},
      permissions => ['secrets.read'],
      session_id  => 'session-1',
      program_id  => 'secrets.program',
    );
  };
  is ref($error),    'HASH',                    'missing name error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing name is invalid params';

  $error = _structured_error {
    $services->dispatch_request(
      'secrets.get',
      {name => 'missing-token'},
      permissions => ['secrets.read'],
      session_id  => 'session-1',
      program_id  => 'secrets.program',
    );
  };
  is ref($error),              'HASH',                                'unknown secret name error is structured';
  is $error->{code},           'protocol.invalid_params',             'unknown secret name is invalid params';
  is $error->{message},        'Secret access denied or unavailable', 'unknown secret name error is redacted';
  is $error->{details}{param}, 'name', 'unknown secret name only identifies the request field';
};

subtest 'services enforce secrets.read permission' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error = _structured_error {
    $services->dispatch_request(
      'secrets.get',
      {name => 'api-token'},
      permissions => [],
      session_id  => 'session-1',
      program_id  => 'secrets.program',
    );
  };
  is ref($error),                            'HASH',                      'permission error is structured';
  is $error->{code},                         'runtime.permission_denied', 'secrets.get requires permission';
  is $error->{details}{required_permission}, 'secrets.read',              'required permission is reported';
};

subtest 'secret-provider-backed secrets enforce per-secret ACLs and keep audit output redacted' => sub {
  my $secret_provider = Overnet::Program::SecretProvider->new(
    secrets => {
      'server-token' => 'top-secret',
    },
    secret_policies => {
      'server-token' => {
        allowed_program_ids  => ['allowed.program'],
        allowed_methods      => ['adapters.open_session'],
        allowed_adapter_ids  => ['secure.adapter'],
        allowed_secret_slots => ['server_password'],
        allowed_purposes     => ['adapters.open_session:secure.adapter:server_password'],
      },
    },
    now_cb          => sub {1_700_000_000_000},
    random_bytes_cb => _random_bytes_cb(),
  );
  my $runtime = Overnet::Program::Runtime->new(
    secret_provider => $secret_provider,
    now_cb          => sub {1_700_000_000_000},
  );

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'allowed.program',
    name       => 'server-token',
    purpose    => 'adapters.open_session:secure.adapter:server_password',
  );

  my $resolved = $runtime->resolve_secret_handle(
    session_id  => 'session-1',
    program_id  => 'allowed.program',
    handle_id   => $issued->{secret_handle}{id},
    method      => 'adapters.open_session',
    adapter_id  => 'secure.adapter',
    secret_slot => 'server_password',
    purpose     => 'adapters.open_session:secure.adapter:server_password',
  );
  is $resolved->{value}, 'top-secret', 'secret-provider-backed runtime resolves an allowed handle';

  my $error = _structured_error {
    $runtime->issue_secret_handle(
      session_id => 'session-1',
      program_id => 'other.program',
      name       => 'server-token',
      purpose    => 'adapters.open_session:secure.adapter:server_password',
    );
  };
  is ref($error),       'HASH',                                'policy denial is structured';
  is $error->{code},    'protocol.invalid_params',             'policy denial uses invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'policy denial is redacted';

  my $audit_json = JSON::encode_json($secret_provider->audit_events);
  unlike $audit_json, qr/top-secret/mx,                       'audit log never includes plaintext secret material';
  unlike $audit_json, qr/\Q$issued->{secret_handle}{id}\E/mx, 'audit log never includes raw handle ids';
  like $audit_json,   qr/secret_handle\.issue/mx,             'audit log records issue attempts';
  like $audit_json,   qr/secret_handle\.resolve/mx,           'audit log records resolve attempts';
};

subtest 'rotation and session revocation invalidate previously issued handles' => sub {
  my $secret_provider = Overnet::Program::SecretProvider->new(
    secrets => {
      'api-token' => 'v1-secret',
    },
    now_cb          => sub {1_700_000_000_000},
    random_bytes_cb => _random_bytes_cb(),
  );
  my $runtime = Overnet::Program::Runtime->new(
    secret_provider => $secret_provider,
    now_cb          => sub {1_700_000_000_000},
  );

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'rotate.program',
    name       => 'api-token',
  );
  my $handle_id = $issued->{secret_handle}{id};

  my $rotated = $runtime->rotate_secret(
    name  => 'api-token',
    value => 'v2-secret',
  );
  is $rotated->{revoked}, 1, 'rotating a secret revokes outstanding handles for that secret';

  my $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id => 'session-1',
      program_id => 'rotate.program',
      handle_id  => $handle_id,
    );
  };
  is ref($error),    'HASH',                    'rotated handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'rotated handle can no longer be resolved';

  my $reissued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'rotate.program',
    name       => 'api-token',
  );
  my $resolved = $runtime->resolve_secret_handle(
    session_id => 'session-1',
    program_id => 'rotate.program',
    handle_id  => $reissued->{secret_handle}{id},
  );
  is $resolved->{value}, 'v2-secret', 'reissued handles resolve the rotated secret value';

  is $runtime->revoke_secret_handles_for_session(session_id => 'session-1'), 1,
    'explicit session revocation removes outstanding handles';
  $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id => 'session-1',
      program_id => 'rotate.program',
      handle_id  => $reissued->{secret_handle}{id},
    );
  };
  is ref($error),    'HASH',                    'revoked session handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'session-revoked handle is no longer resolvable';
};

subtest 'runtime validates secret constructor params' => sub {
  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          secrets => {
            'api-token' => {},
          },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/secret\ api-token\ must\ be\ a\ string/mx,
    'runtime rejects non-string secret values',
  );

  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(secret_handle_ttl_ms => 0,);
        1;
      } or $error = $@;
      $error;
    },
    qr/secret_handle_ttl_ms\ must\ be\ a\ positive\ integer/mx,
    'runtime rejects invalid secret handle ttl',
  );

  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          secret_policies => {
            'api-token' => {
              allowed_program_ids => [''],
            },
          },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/secret\ policy\ api-token\.allowed_program_ids\ must\ be\ an\ array\ of\ non-empty\ strings/mx,
    'runtime rejects invalid secret policy shapes',
  );
};

subtest 'instance issues secret handles through protocol without returning plaintext and revokes them on shutdown' =>
  sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
    now_cb          => sub {1_700_000_000_000},
    random_bytes_cb => _random_bytes_cb(),
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['secrets.read'],
    service_handler             => $services,
  );

  my $hello = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'secrets.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  my $response = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'secret-1',
      method => 'secrets.get',
      params => {name => 'api-token'},
    )
  );

  ok $response->{send}{ok}, 'secrets.get succeeds through protocol';
  is $response->{send}{result}{name}, 'api-token', 'protocol response returns requested secret name';
  ok !exists $response->{send}{result}{value}, 'protocol response does not expose the secret plaintext';
  like $response->{send}{result}{secret_handle}{id},
    qr/\Ash_[0-9a-f]{64}\z/mx,
    'protocol response returns opaque handle';

  my $resolved = $runtime->resolve_secret_handle(
    session_id => 'instance-1',
    program_id => 'secrets.example',
    handle_id  => $response->{send}{result}{secret_handle}{id},
  );
  is $resolved->{value}, 'top-secret', 'runtime can resolve the protocol-issued handle internally';

  my $shutdown = $instance->request_shutdown(reason => 'done');
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $shutdown->{send}{id}
    )
  );

  my $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id => 'instance-1',
      program_id => 'secrets.example',
      handle_id  => $response->{send}{result}{secret_handle}{id},
    );
  };
  is ref($error),    'HASH',                    'shutdown-revoked handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'instance shutdown revokes outstanding secret handles';
  };

sub _secrets_error (&) {
  my ($code) = @_;
  return eval { $code->(); 1 } ? undef : $@;
}

subtest 'secret provider construction validates its collaborators' => sub {
  like(_secrets_error { Overnet::Program::SecretProvider->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(_secrets_error { Overnet::Program::SecretProvider->new(now_cb => 'junk') },
    qr/now_cb must be a code reference/, 'now_cb must be code');
  like(_secrets_error { Overnet::Program::SecretProvider->new(random_bytes_cb => 'junk') },
    qr/random_bytes_cb must be a code reference/, 'random_bytes_cb must be code');
  like(_secrets_error { Overnet::Program::SecretProvider->new(secrets => 'junk') },
    qr/secrets must be an object/, 'secrets must be an object');
  like(_secrets_error { Overnet::Program::SecretProvider->new(secret_policies => 'junk') },
    qr/secret_policies must be an object/, 'secret policies must be an object');
  like(_secrets_error { Overnet::Program::SecretProvider->new(secret_handle_ttl_ms => 0) },
    qr/secret_handle_ttl_ms/, 'handle TTLs must be positive');
  like(_secrets_error { Overnet::Program::SecretProvider->new(secrets => {q{} => 'v'}) },
    qr/secret names must be non-empty strings/, 'secret names must be non-empty');
  like(_secrets_error { Overnet::Program::SecretProvider->new(secrets => {name => []}) },
    qr/secret values must be non-empty strings|secret/, 'secret values must be strings');
  like(
    _secrets_error {
      Overnet::Program::SecretProvider->new(secret_policies => {q{} => {}})
    },
    qr/secret policy names must be non-empty strings/,
    'policy names must be non-empty',
  );
  like(
    _secrets_error {
      Overnet::Program::SecretProvider->new(secret_policies => {name => 'junk'})
    },
    qr/secret policy name must be an object/,
    'policies must be objects',
  );
  like(
    _secrets_error {
      Overnet::Program::SecretProvider->new(
        secret_policies => {name => {allowed_session_ids => [q{}]}},
      )
    },
    qr/allowed_session_ids/,
    'policy allow lists must hold non-empty strings',
  );

  my $now_source = Overnet::Program::SecretProvider->new(
    {secrets => {'irc.password' => 'hunter2'}},
  );
  ok($now_source->has_secret(name => 'irc.password'), 'has_secret reports stored secrets');
  ok(!$now_source->has_secret(name => 'absent'),      'has_secret rejects unknown names');

  my $bad_clock = Overnet::Program::SecretProvider->new(now_cb => sub { return 'noon' });
  like(
    _secrets_error { $bad_clock->issue_secret_handle(session_id => 's', name => 'x') },
    qr/now_cb must return an integer millisecond timestamp/,
    'non-integer clocks croak',
  );
};

subtest 'secret handle lifecycle covers policy and expiry checks' => sub {
  my $now      = 1_000;
  my $provider = Overnet::Program::SecretProvider->new(
    now_cb          => sub { return $now },
    secrets         => {'irc.password' => 'hunter2', 'other' => 'value'},
    secret_policies => {
      'irc.password' => {
        allowed_session_ids => ['session-1'],
        allowed_program_ids => ['irc.bridge'],
        allowed_purposes    => ['login'],
        allowed_methods     => ['adapters.open_session'],
        allowed_adapter_ids => ['irc'],
        allowed_secret_slots => ['password'],
      },
    },
    secret_handle_ttl_ms => 500,
  );

  my %issue_args = (
    session_id => 'session-1',
    name       => 'irc.password',
    program_id => 'irc.bridge',
    purpose    => 'login',
  );
  is(
    _secrets_error { $provider->issue_secret_handle(%issue_args, name => 'absent') }->{code},
    'protocol.invalid_params',
    'unknown secrets refuse to issue',
  );
  like(
    _secrets_error { $provider->issue_secret_handle(%issue_args, session_id => 'other') },
    qr/./,
    'sessions outside the allow list refuse to issue',
  );
  like(
    _secrets_error { $provider->issue_secret_handle(%issue_args, program_id => 'other') },
    qr/./,
    'programs outside the allow list refuse to issue',
  );
  like(
    _secrets_error { $provider->issue_secret_handle(%issue_args, purpose => 'other') },
    qr/./,
    'purposes outside the allow list refuse to issue',
  );

  my $issued = $provider->issue_secret_handle(%issue_args);
  my $handle_id = $issued->{secret_handle}{id};
  ok(defined $handle_id, 'a policy-satisfying issue succeeds');

  my %resolve_args = (
    session_id  => 'session-1',
    handle_id   => $handle_id,
    program_id  => 'irc.bridge',
    purpose     => 'login',
    method      => 'adapters.open_session',
    adapter_id  => 'irc',
    secret_slot => 'password',
  );
  is($provider->resolve_secret_handle(%resolve_args)->{value}, 'hunter2',
    'a fully-matching resolve returns the secret');

  for my $case (
    [session_id  => 'other'],
    [program_id  => 'other'],
    [program_id  => undef],
    [purpose     => 'other'],
    [purpose     => undef],
    [method      => 'other'],
    [adapter_id  => 'other'],
    [secret_slot => 'other'],
  ) {
    my ($field, $value) = @{$case};
    like(
      _secrets_error {
        $provider->resolve_secret_handle(%resolve_args, $field => $value, error_param => $field)
      },
      qr/./,
      "a mismatched $field refuses to resolve",
    );
  }
  like(
    _secrets_error { $provider->resolve_secret_handle(%resolve_args, handle_id => 'absent') },
    qr/./,
    'unknown handles refuse to resolve',
  );

  ok(!$provider->revoke_secret_handle(handle_id => 'absent'), 'revoking unknown handles is a no-op');
  ok($provider->revoke_secret_handle(handle_id => $handle_id), 'revoking a live handle succeeds');
  like(
    _secrets_error { $provider->resolve_secret_handle(%resolve_args) },
    qr/./,
    'revoked handles refuse to resolve',
  );

  my $expiring = $provider->issue_secret_handle(%issue_args);
  $now += 10_000;
  like(
    _secrets_error { $provider->resolve_secret_handle(%resolve_args, handle_id => $expiring->{secret_handle}{id}) },
    qr/./,
    'expired handles refuse to resolve',
  );

  my $rotated_none = $provider->rotate_secret(name => 'other', value => 'new-value');
  is($rotated_none->{revoked}, 0, 'rotating a secret without handles revokes none');
  my $before_rotate = $provider->issue_secret_handle(%issue_args);
  my $rotated       = $provider->rotate_secret(name => 'irc.password', value => 'hunter3');
  is($rotated->{revoked}, 1, 'rotating a secret revokes its outstanding handles');

  is($provider->revoke_secret_handles_for_session(session_id => 'session-none'), 0,
    'revoking for an idle session revokes nothing');
  my $session_handle = $provider->issue_secret_handle(%issue_args);
  ok($provider->revoke_secret_handles_for_session(session_id => 'session-1') >= 1,
    'revoking for a session revokes its handles');

  ok(scalar(@{$provider->audit_events}) > 0, 'audit events were recorded');
};

subtest 'random handle generation validates its sources' => sub {
  my $fixed = Overnet::Program::SecretProvider->new(
    secrets         => {name => 'value'},
    random_bytes_cb => sub { my ($length) = @_; return 'a' x $length },
  );
  my $issued = $fixed->issue_secret_handle(session_id => 's', name => 'name');
  ok(defined $issued->{secret_handle}{id}, 'a deterministic random source issues handles');
  my $broken_error = _secrets_error {
    Overnet::Program::SecretProvider->new(
      secrets         => {name => 'value'},
      random_bytes_cb => sub { return 'short' },
    )->issue_secret_handle(session_id => 's', name => 'name');
  };
  is(
    ref($broken_error) eq 'HASH' ? $broken_error->{code} : "$broken_error",
    'runtime.service_unavailable',
    'a broken random source is rejected',
  );
};

subtest 'resolve policy rows and helper internals' => sub {
  my $provider = Overnet::Program::SecretProvider->new(
    secrets         => {'irc.password' => 'hunter2', 'other' => 'value'},
    secret_policies => {
      'irc.password' => {
        allowed_session_ids  => ['session-2'],
        allowed_program_ids  => ['irc.bridge'],
        allowed_purposes     => ['login'],
        allowed_methods      => ['adapters.open_session'],
        allowed_adapter_ids  => ['irc'],
        allowed_secret_slots => ['password'],
      },
    },
  );

  my $may_resolve = sub {
    my (%args) = @_;
    return $provider->_may_resolve_secret_handle(
      handle      => {name => 'irc.password', session_id => 'session-2'},
      session_id  => 'session-2',
      program_id  => 'irc.bridge',
      purpose     => 'login',
      method      => 'adapters.open_session',
      adapter_id  => 'irc',
      secret_slot => 'password',
      %args,
    );
  };
  ok($may_resolve->(), 'a fully matching context may resolve');
  ok(!$may_resolve->(handle => {name => 'absent', session_id => 'session-2'}),
    'handles for removed secrets may not resolve');
  ok(!$may_resolve->(session_id => 'session-3',
      handle => {name => 'irc.password', session_id => 'session-3'}),
    'sessions outside the policy allow list may not resolve');
  ok(!$may_resolve->(program_id => 'ghost'),  'programs outside the allow list may not resolve');
  ok(!$may_resolve->(purpose    => 'ghost'),  'purposes outside the allow list may not resolve');
  ok(!$may_resolve->(method     => 'ghost'),  'methods outside the allow list may not resolve');

  ok(!$provider->_matches_allowed_list(allowed => [], value => 'x'),
    'an empty allow list matches nothing');
  ok(!$provider->_matches_allowed_list(allowed => ['x'], value => undef),
    'an undefined value never matches an allow list');

  my $length_error = eval { $provider->_secure_random_bytes(0); 1 } ? undef : $@;
  like($length_error, qr/length must be a positive integer/, 'random byte lengths are validated');

  my $collider = Overnet::Program::SecretProvider->new(
    secrets         => {name => 'value'},
    random_bytes_cb => sub { my ($length) = @_; return 'a' x $length },
  );
  ok($collider->issue_secret_handle(session_id => 's', name => 'name'),
    'the first deterministic handle issues');
  my $collision_error = eval {
    $collider->issue_secret_handle(session_id => 's', name => 'name');
    1;
  } ? undef : $@;
  is(ref($collision_error) eq 'HASH' ? $collision_error->{code} : "$collision_error",
    'runtime.service_unavailable', 'exhausted handle ids report service unavailability');

  my $mixed = Overnet::Program::SecretProvider->new(
    secrets => {'a.secret' => 'v1', 'b.secret' => 'v2'},
  );
  $mixed->issue_secret_handle(session_id => 'session-a', name => 'a.secret');
  $mixed->issue_secret_handle(session_id => 'session-b', name => 'b.secret');
  is($mixed->revoke_secret_handles_for_session(session_id => 'session-a'), 1,
    'revoking a session skips other sessions');
  is($mixed->rotate_secret(name => 'a.secret', value => 'v3')->{revoked}, 0,
    'rotating skips handles for other secrets');
};

done_testing;
