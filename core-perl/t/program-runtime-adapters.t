use strictures 2;
use Test2::V0;
use File::Spec;
use FindBin;

use Overnet::Program::Runtime;
use Overnet::Program::Services;

my $IRC_ADAPTER_LIB
  = File::Spec->rel2abs(File::Spec->catdir($FindBin::Bin, '..', '..', 'adapter-irc-perl', 'lib'));

sub _random_bytes_cb {
  my ($start_ord) = @_;
  my $counter = 0;
  return sub {
    my ($length) = @_;
    $counter++;
    return chr($start_ord + $counter) x $length;
  };
}

{

  package Local::MockAdapter;

  use Moo;
  no Moo;

  sub map_input {
    my ($self, %args) = @_;
    return {
      events => [
        {
          kind    => 7800,
          adapter => 'mock',
          input   => $args{command},
        },
      ],
    };
  }

  sub derive {
    my ($self, %args) = @_;
    return {
      state => [
        {
          kind      => 37800,
          operation => $args{operation},
          input     => $args{input},
        },
      ],
    };
  }
}

{

  package Local::SessionConfigAdapter;

  use Moo;
  no Moo;

  sub map_input {
    my ($self, %args) = @_;
    return {
      valid => 1,
      event => {
        kind         => 7800,
        session_mode => $args{session_config}{mode},
        command      => $args{command},
      },
    };
  }

  sub derive {
    my ($self, %args) = @_;
    return {
      valid => 1,
      event => {
        kind         => 37800,
        session_mode => $args{session_config}{mode},
        operation    => $args{operation},
      },
    };
  }
}

{

  package Local::CapabilityAdapter;

  use Moo;
  no Moo;

  sub map_input {
    return {
      capabilities => [
        {
          name    => 'adapter.mock.capability',
          version => '1.0',
          details => {source => 'map_input'},
        },
      ],
    };
  }

  sub derive {
    return {
      capabilities => [
        {
          name    => 'adapter.mock.derived',
          version => '2.0',
        },
      ],
    };
  }
}

{

  package Local::BadCapabilityAdapter;

  use Moo;
  no Moo;

  sub map_input {
    return {
      capabilities => [
        {
          details => {broken => 1},
        },
      ],
    };
  }

  sub derive {
    return {
      capabilities => [
        {
          name    => 'adapter.mock.broken',
          version => [],
        },
      ],
    };
  }
}

{

  package Local::SecretAwareAdapter;

  use Moo;

  has opened_sessions => (is => 'ro', default => sub { {} });
  has closed_sessions => (is => 'ro', default => sub { [] });

  no Moo;

  sub supported_secret_slots {
    return ['server_password', 'nickserv_password', 'sasl_password',];
  }

  sub open_session {
    my ($self, %args) = @_;
    $self->{opened_sessions}{$args{adapter_session_id}} = {
      secret_values      => {%{$args{secret_values}  || {}}},
      session_config     => {%{$args{session_config} || {}}},
      program_session_id => $args{program_session_id},
      program_id         => $args{program_id},
    };
    return {accepted => 1};
  }

  sub close_session {
    my ($self, %args) = @_;
    push @{$self->{closed_sessions}}, $args{adapter_session_id};
    delete $self->{opened_sessions}{$args{adapter_session_id}};
    return 1;
  }

  sub map_input {
    my ($self, %args) = @_;
    return {
      valid => 1,
      event => {
        kind         => 7800,
        session_mode => $args{session_config}{mode},
      },
    };
  }
}

{

  package Local::UnsupportedSecretAdapter;

  use Moo;
  no Moo;
}

subtest 'runtime registers adapters and opens sessions' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $adapter = Local::MockAdapter->new;

  ok $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => $adapter,
    ),
    'adapter registered';

  my $session = $runtime->open_adapter_session(
    adapter_id => 'mock.adapter',
    config     => {mode => 'test'},
  );

  is $session->adapter_id,          'mock.adapter',         'session records adapter id';
  is $runtime->adapter_session_ids, [$session->session_id], 'runtime tracks session';
};

subtest 'runtime can instantiate adapters from class definitions' => sub {
  my $runtime = Overnet::Program::Runtime->new;

  ok $runtime->register_adapter_definition(
    adapter_id => 'mock.class',
    definition => {
      kind             => 'class',
      class            => 'Local::MockAdapter',
      constructor_args => {},
    },
    ),
    'class adapter definition registered';

  my $session = $runtime->open_adapter_session(adapter_id => 'mock.class',);

  my $mapped = $session->map_input({command => 'NOTICE'});
  is $mapped->{events}[0]{input}, 'NOTICE', 'class adapter was instantiated and used';
};

subtest 'runtime can load the real IRC adapter implementation path' => sub {
  plan skip_all => "adapter-irc-perl checkout not found at $IRC_ADAPTER_LIB"
    unless -d $IRC_ADAPTER_LIB;

  my $runtime = Overnet::Program::Runtime->new;
  my $irc_lib = $IRC_ADAPTER_LIB;

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
    ),
    'real IRC adapter definition registered';

  my $session = $runtime->open_adapter_session(adapter_id => 'irc.real',);

  my $mapped = $session->map_input(
    {
      command    => 'PRIVMSG',
      network    => 'irc.libera.chat',
      target     => '#overnet',
      nick       => 'alice',
      text       => 'Hello from runtime',
      created_at => 1744301000,
    }
  );

  ok $mapped->{valid}, 'real adapter returned valid mapping result';
  is $mapped->{event}{kind}, 7800, 'real adapter returned mapped event';
};

subtest 'services normalize real IRC adapter outputs and support derive operations' => sub {
  plan skip_all => "adapter-irc-perl checkout not found at $IRC_ADAPTER_LIB"
    unless -d $IRC_ADAPTER_LIB;

  my $runtime = Overnet::Program::Runtime->new;
  my $irc_lib = $IRC_ADAPTER_LIB;

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
    ),
    'real IRC adapter definition registered';

  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $opened =
    $services->dispatch_request('adapters.open_session', {adapter_id => 'irc.real'}, permissions => ['adapters.use'],);
  my $session_id = $opened->{adapter_session_id};

  my $mapped = $services->dispatch_request(
    'adapters.map_input',
    {
      adapter_session_id => $session_id,
      input              => {
        command    => 'PRIVMSG',
        network    => 'irc.libera.chat',
        target     => '#overnet',
        nick       => 'alice',
        text       => 'Hello from runtime',
        created_at => 1744301000,
      },
    },
    permissions => ['adapters.use'],
  );
  is $mapped->{events}[0]{kind}, 7800, 'real adapter event is normalized to events array';
  ok !exists $mapped->{valid}, 'adapter-local validity flag is not exposed through service result';
  ok !exists $mapped->{event}, 'adapter-local singular event shape is normalized';

  my $derived = $services->dispatch_request(
    'adapters.derive',
    {
      adapter_session_id => $session_id,
      operation          => 'channel_presence',
      input              => {
        network    => 'irc.libera.chat',
        target     => '#overnet',
        created_at => 1744300900,
        events     => [
          {
            command    => 'JOIN',
            network    => 'irc.libera.chat',
            target     => '#overnet',
            nick       => 'alice',
            created_at => 1744300870,
          },
        ],
      },
    },
    permissions => ['adapters.use'],
  );
  is $derived->{state}[0]{kind}, 37800, 'real adapter derived state is normalized to state array';
};

subtest 'services open, use, derive, and close adapter sessions' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $opened = $services->open_adapter_session(
    adapter_id => 'mock.adapter',
    config     => {source => 'example'},
  );
  my $session_id = $opened->{adapter_session_id};
  ok defined $session_id && length $session_id, 'session id returned';

  my $mapped = $services->map_input(
    adapter_session_id => $session_id,
    input              => {command => 'PRIVMSG'},
  );
  is $mapped->{events}[0]{input}, 'PRIVMSG', 'mapped adapter output returned';

  my $derived = $services->derive(
    adapter_session_id => $session_id,
    operation          => 'channel_presence',
    input              => {channel => '#overnet'},
  );
  is $derived->{state}[0]{operation}, 'channel_presence', 'derived adapter output returned';

  is $services->close_adapter_session(adapter_session_id => $session_id), {}, 'close returns empty result';
  is $runtime->adapter_session_ids, [], 'session removed after close';
};

subtest 'dispatch_request enforces adapters.use permission' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'adapters.open_session',
      {adapter_id => 'mock.adapter', config => {}},
      permissions => [],
    );
    1;
  } or $error = $@;

  is ref($error),                            'HASH',                      'permission denial is structured';
  is $error->{code},                         'runtime.permission_denied', 'permission denial code returned';
  is $error->{details}{required_permission}, 'adapters.use',              'required permission is reported';
  is $runtime->adapter_session_ids,          [],                          'session is not opened without permission';

  my $opened = $services->dispatch_request(
    'adapters.open_session',
    {adapter_id => 'mock.adapter', config => {}},
    permissions => ['adapters.use'],
  );
  ok defined $opened->{adapter_session_id}
    && length $opened->{adapter_session_id},
    'dispatch_request succeeds when adapters.use is granted';
};

subtest 'dispatch_request reports invalid secret and adapter params with structured errors' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
  );
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'secrets.get',
      {name => 'missing-token'},
      permissions => ['secrets.read'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'invalid secret params error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown secret is reported as invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'adapters.map_input',
      {adapter_session_id => 'missing'},
      permissions => ['adapters.use'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'invalid adapter params error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown adapter session is reported as invalid params';
};

subtest 'adapter session config is forwarded to adapter methods' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'session.config',
    adapter    => Local::SessionConfigAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $opened = $services->dispatch_request(
    'adapters.open_session',
    {
      adapter_id => 'session.config',
      config     => {mode => 'session-test'},
    },
    permissions => ['adapters.use'],
  );
  my $session_id = $opened->{adapter_session_id};

  my $mapped = $services->dispatch_request(
    'adapters.map_input',
    {
      adapter_session_id => $session_id,
      input              => {command => 'NOTICE'},
    },
    permissions => ['adapters.use'],
  );
  is $mapped->{events}[0]{session_mode}, 'session-test', 'session config is available during map_input';

  my $derived = $services->dispatch_request(
    'adapters.derive',
    {
      adapter_session_id => $session_id,
      operation          => 'derive-test',
      input              => {},
    },
    permissions => ['adapters.use'],
  );
  is $derived->{state}[0]{session_mode}, 'session-test', 'session config is available during derive';
};

subtest
  'adapters.open_session resolves secret handles inside the runtime and passes plaintext only to adapter open_session'
  => sub {
  my $adapter = Local::SecretAwareAdapter->new;
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'server-password'   => 'server-secret',
      'nickserv-password' => 'nickserv-secret',
    },
    random_bytes_cb => _random_bytes_cb(64),
  );
  $runtime->register_adapter(
    adapter_id => 'secret.adapter',
    adapter    => $adapter,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $server_handle = $services->dispatch_request(
    'secrets.get',
    {
      name    => 'server-password',
      purpose => 'adapters.open_session:secret.adapter:server_password',
    },
    permissions => ['secrets.read'],
    session_id  => 'session-1',
    program_id  => 'adapter.program',
  );
  my $nickserv_handle = $services->dispatch_request(
    'secrets.get',
    {
      name    => 'nickserv-password',
      purpose => 'adapters.open_session:secret.adapter:nickserv_password',
    },
    permissions => ['secrets.read'],
    session_id  => 'session-1',
    program_id  => 'adapter.program',
  );

  my $opened = $services->dispatch_request(
    'adapters.open_session',
    {
      adapter_id     => 'secret.adapter',
      config         => {mode => 'secure'},
      secret_handles => {
        server_password   => $server_handle->{secret_handle},
        nickserv_password => $nickserv_handle->{secret_handle},
      },
    },
    permissions => ['adapters.use'],
    session_id  => 'session-1',
    program_id  => 'adapter.program',
  );

  my $session = $runtime->get_adapter_session($opened->{adapter_session_id});
  is $session->config, {mode => 'secure'}, 'adapter session stores only non-secret config';
  is $adapter->{opened_sessions}{$opened->{adapter_session_id}}
    {secret_values}{server_password},
    'server-secret',
    'adapter open_session receives resolved server_password plaintext';
  is $adapter->{opened_sessions}{$opened->{adapter_session_id}}
    {secret_values}{nickserv_password},
    'nickserv-secret',
    'adapter open_session receives resolved nickserv_password plaintext';

  my $mapped = $services->dispatch_request(
    'adapters.map_input',
    {
      adapter_session_id => $opened->{adapter_session_id},
      input              => {},
    },
    permissions => ['adapters.use'],
  );
  is $mapped->{events}[0]{session_mode}, 'secure', 'non-secret session config still flows through session methods';

  is $services->dispatch_request(
    'adapters.close_session',
    {
      adapter_session_id => $opened->{adapter_session_id},
    },
    permissions => ['adapters.use'],
    ),
    {}, 'secure adapter session closes cleanly';
  is scalar @{$adapter->{closed_sessions}}, 1, 'adapter close_session hook was called';
  };

subtest 'adapters.open_session rejects invalid or unsupported secret handle consumption paths' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'server-password' => 'server-secret',
    },
    random_bytes_cb => _random_bytes_cb(70),
  );
  $runtime->register_adapter(
    adapter_id => 'secret.adapter',
    adapter    => Local::SecretAwareAdapter->new,
  );
  $runtime->register_adapter(
    adapter_id => 'unsupported.secret.adapter',
    adapter    => Local::UnsupportedSecretAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $handle = $services->dispatch_request(
    'secrets.get',
    {
      name    => 'server-password',
      purpose => 'adapters.open_session:secret.adapter:server_password',
    },
    permissions => ['secrets.read'],
    session_id  => 'session-1',
    program_id  => 'adapter.program',
  );

  my $error;
  eval {
    $services->dispatch_request(
      'adapters.open_session',
      {
        adapter_id     => 'secret.adapter',
        secret_handles => {
          unsupported_slot => $handle->{secret_handle},
        },
      },
      permissions => ['adapters.use'],
      session_id  => 'session-1',
      program_id  => 'adapter.program',
    );
    1;
  } or $error = $@;
  is ref($error),              'HASH',                            'unsupported secret slot error is structured';
  is $error->{code},           'protocol.invalid_params',         'unsupported secret slot is invalid params';
  is $error->{details}{param}, 'secret_handles.unsupported_slot', 'unsupported slot identifies the request field';

  $error = undef;
  eval {
    $services->dispatch_request(
      'adapters.open_session',
      {
        adapter_id     => 'secret.adapter',
        secret_handles => {
          server_password => $handle->{secret_handle},
        },
      },
      permissions => ['adapters.use'],
      session_id  => 'session-2',
      program_id  => 'adapter.program',
    );
    1;
  } or $error = $@;
  is ref($error),       'HASH',                                'wrong-session secret handle error is structured';
  is $error->{code},    'protocol.invalid_params',             'wrong-session secret handle is invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'wrong-session secret handle is redacted';
  unlike $error->{message}, qr/server-password/mx,                  'secret name is not exposed in consumer error';
  unlike $error->{message}, qr/\Q$handle->{secret_handle}{id}\E/mx, 'handle id is not exposed in consumer error';

  $error = undef;
  eval {
    $services->dispatch_request(
      'adapters.open_session',
      {
        adapter_id     => 'unsupported.secret.adapter',
        secret_handles => {
          server_password => $handle->{secret_handle},
        },
      },
      permissions => ['adapters.use'],
      session_id  => 'session-1',
      program_id  => 'adapter.program',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                        'adapter without secret-slot declaration error is structured';
  is $error->{code}, 'runtime.service_unavailable', 'secret handle consumption requires declared adapter support';
};

subtest 'services validate adapter capability outputs against baseline capability shape' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'capability.adapter',
    adapter    => Local::CapabilityAdapter->new,
  );
  $runtime->register_adapter(
    adapter_id => 'bad.capability.adapter',
    adapter    => Local::BadCapabilityAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $opened = $services->dispatch_request(
    'adapters.open_session',
    {adapter_id => 'capability.adapter'},
    permissions => ['adapters.use'],
  );
  my $mapped = $services->dispatch_request(
    'adapters.map_input',
    {
      adapter_session_id => $opened->{adapter_session_id},
      input              => {},
    },
    permissions => ['adapters.use'],
  );
  is $mapped->{capabilities}[0]{name},            'adapter.mock.capability', 'valid adapter capability is returned';
  is $mapped->{capabilities}[0]{details}{source}, 'map_input',               'capability details are preserved';

  my $derived = $services->dispatch_request(
    'adapters.derive',
    {
      adapter_session_id => $opened->{adapter_session_id},
      operation          => 'anything',
      input              => {},
    },
    permissions => ['adapters.use'],
  );
  is $derived->{capabilities}[0]{version}, '2.0', 'valid derived capability is returned';

  my $bad_opened = $services->dispatch_request(
    'adapters.open_session',
    {adapter_id => 'bad.capability.adapter'},
    permissions => ['adapters.use'],
  );

  my $error;
  eval {
    $services->dispatch_request(
      'adapters.map_input',
      {
        adapter_session_id => $bad_opened->{adapter_session_id},
        input              => {},
      },
      permissions => ['adapters.use'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                        'invalid adapter map_input capability error is structured';
  is $error->{code}, 'runtime.service_unavailable', 'invalid adapter capability map_input is service_unavailable';
  like $error->{message}, qr/capabilities\[0\]\.name/mx, 'invalid capability error identifies missing name';

  $error = undef;
  eval {
    $services->dispatch_request(
      'adapters.derive',
      {
        adapter_session_id => $bad_opened->{adapter_session_id},
        operation          => 'anything',
        input              => {},
      },
      permissions => ['adapters.use'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                        'invalid adapter derive capability error is structured';
  is $error->{code}, 'runtime.service_unavailable', 'invalid adapter capability derive is service_unavailable';
  like $error->{message}, qr/capabilities\[0\]\.version/mx, 'invalid capability error identifies bad version';
};

subtest 'unknown adapters and sessions are rejected' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->open_adapter_session(adapter_id => 'missing.adapter');
    1;
  } or $error = $@;
  is ref($error),    'HASH',                        'unknown adapter error is structured';
  is $error->{code}, 'runtime.service_unavailable', 'unknown adapter is treated as unavailable runtime service';

  $error = undef;
  eval {
    $services->map_input(
      adapter_session_id => 'adapter-999',
      input              => {},
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'unknown session error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown session is treated as invalid params';
};

subtest 'real IRC adapter declares secure secret slots and accepts secret-backed session opens' => sub {
  plan skip_all => "adapter-irc-perl checkout not found at $IRC_ADAPTER_LIB"
    unless -d $IRC_ADAPTER_LIB;

  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'irc-sasl-password' => 'sasl-secret',
    },
    random_bytes_cb => _random_bytes_cb(80),
  );
  my $irc_lib = $IRC_ADAPTER_LIB;

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
    ),
    'real IRC adapter definition registered';

  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $handle   = $services->dispatch_request(
    'secrets.get',
    {
      name    => 'irc-sasl-password',
      purpose => 'adapters.open_session:irc.real:sasl_password',
    },
    permissions => ['secrets.read'],
    session_id  => 'session-irc',
    program_id  => 'irc.program',
  );

  my $opened = $services->dispatch_request(
    'adapters.open_session',
    {
      adapter_id => 'irc.real',
      config     => {
        network => 'irc.libera.chat',
        nick    => 'overnet-bot',
      },
      secret_handles => {
        sasl_password => $handle->{secret_handle},
      },
    },
    permissions => ['adapters.use'],
    session_id  => 'session-irc',
    program_id  => 'irc.program',
  );
  ok defined $opened->{adapter_session_id}
    && length $opened->{adapter_session_id},
    'real IRC adapter opens a session with secret handles';
};

subtest 'adapter session construction and dispatch validation' => sub {
  require Overnet::Program::AdapterSession;

  {

    package Local::DeriveOnlyAdapter;

    sub new { my ($class) = @_; return bless {}, $class }

    sub derive_presence {
      my ($self, %args) = @_;
      return {operation => 'presence', args => \%args};
    }
  }

  my %valid = (
    session_id => 'adapter-session-1',
    adapter_id => 'mock',
    adapter    => Local::MockAdapter->new,
  );

  like(dies { Overnet::Program::AdapterSession->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(dies { Overnet::Program::AdapterSession->new(%valid, session_id => q{}) },
    qr/session_id is required/, 'a session id is required');
  like(dies { Overnet::Program::AdapterSession->new(%valid, adapter_id => q{}) },
    qr/adapter_id is required/, 'an adapter id is required');
  like(dies { Overnet::Program::AdapterSession->new(%valid, adapter => 'junk') },
    qr/adapter is required/, 'an adapter object is required');
  like(dies { Overnet::Program::AdapterSession->new(%valid, config => 'junk') },
    qr/config must be an object/, 'session config must be an object');
  like(dies { Overnet::Program::AdapterSession->new(%valid, program_session_id => q{}) },
    qr/program_session_id must be a non-empty string/, 'program session ids must be non-empty');
  like(dies { Overnet::Program::AdapterSession->new(%valid, program_id => q{}) },
    qr/program_id must be a non-empty string/, 'program ids must be non-empty');

  my $contextual = Overnet::Program::AdapterSession->new(
    {%valid, program_session_id => 'program-session-9', program_id => 'irc.example'},
  );
  my $mapped = $contextual->map_input({command => 'PRIVMSG'});
  is($mapped->{events}[0]{input}, 'PRIVMSG', 'map_input forwards the input');

  like(dies { $contextual->derive(operation => q{}) },
    qr/operation is required/, 'derive requires an operation');
  like(dies { $contextual->derive(operation => 'presence', input => 'junk') },
    qr/input must be an object/, 'derive input must be an object');

  my $derive_only = Overnet::Program::AdapterSession->new(
    %valid,
    adapter            => Local::DeriveOnlyAdapter->new,
    program_session_id => 'program-session-9',
    program_id         => 'irc.example',
  );
  like(dies { $derive_only->map_input({}) },
    qr/adapter does not support map_input/, 'adapters without map_input croak');
  my $derived = $derive_only->derive(operation => 'presence', input => {channel => '#ops'});
  is($derived->{operation}, 'presence', 'operation-specific derive methods dispatch');
  is($derived->{args}{program_id}, 'irc.example', 'program context is forwarded to derive methods');
  like(dies { $derive_only->derive(operation => 'unknown') },
    qr/adapter does not support derive/, 'underivable operations croak');
  ok($derive_only->close_session, 'adapters without close_session close trivially');
};

done_testing;
