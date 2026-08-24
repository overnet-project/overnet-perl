use strictures 2;
use JSON ();
use Test2::V0;

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

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

subtest 'program.hello negotiates version and emits runtime.init' => sub {
  my $instance = Overnet::Program::Instance->new(
    instance_id                 => 'instance-42',
    runtime_program_id          => 'overnet.runtime',
    supported_protocol_versions => ['0.2', '0.1'],
    config                      => {mode => 'test'},
    permissions                 => ['config.read'],
    services                    => {config => {available => JSON::true}},
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
      program_version             => '1.0.0',
    )
  );

  is $instance->current_state,             'awaiting_init_response', 'state advanced after hello';
  is $instance->selected_protocol_version, '0.1',                    'compatible version selected';
  is $instance->peer_program_id,           'irc.example',            'peer program id recorded';
  is $result->{send}{method},              'runtime.init',           'runtime.init request emitted';
  is $result->{send}{params}{instance_id}, 'instance-42',            'instance id included';
  is $result->{send}{params}{program_id},  'irc.example',            'runtime.init identifies the supervised program';
};

subtest 'runtime.init uses configured canonical program id when provided' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    program_id                  => 'irc.canonical',
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.asserted',
      supported_protocol_versions => ['0.1'],
    )
  );

  is $result->{send}{params}{program_id}, 'irc.canonical', 'configured canonical id is sent in runtime.init';
};

subtest 'successful init response moves session to awaiting_ready' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'],);

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );

  my $init_id = $hello_result->{send}{id};
  my $result  = $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $init_id,
    )
  );

  ok $result->{accepted}, 'init accepted';
  is $instance->current_state, 'awaiting_ready', 'state advanced to awaiting_ready';
};

subtest 'program.ready moves session to ready' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'],);

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello_result->{send}{id}
    )
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready(
      params => {phase => 'done'},
    )
  );

  ok $result->{ready},    'ready acknowledged';
  ok $instance->is_ready, 'instance is ready';
};

subtest 'request_shutdown emits runtime.shutdown and tracks state' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'],);

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello_result->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  my $result = $instance->request_shutdown(reason => 'operator-requested');
  is $instance->current_state, 'shutdown_requested', 'shutdown state recorded';
  is $result->{send}{method},  'runtime.shutdown',   'runtime.shutdown emitted';

  my $shutdown_id = $result->{send}{id};
  my $shutdown_result =
    $instance->process_program_message(Overnet::Program::Protocol::build_response_ok(id => $shutdown_id));

  ok $shutdown_result->{shutdown_complete}, 'shutdown completed';
  is $instance->current_state, 'shutdown_complete', 'session reached shutdown_complete';
};

subtest 'no compatible protocol version emits runtime.fatal and fails the session' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.2'],);

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );

  ok $result->{fatal}, 'hello mismatch produces a fatal runtime result';
  is $result->{send}{type},          'notification',              'fatal result sends a notification';
  is $result->{send}{method},        'runtime.fatal',             'fatal result uses runtime.fatal';
  is $result->{send}{params}{code},  'protocol.version_mismatch', 'fatal code identifies version mismatch';
  is $result->{send}{params}{phase}, 'handshake',                 'fatal notification identifies handshake phase';
  is $instance->current_state,       'failed',                    'session enters failed state after version mismatch';
};

subtest 'unknown response ids are fatal protocol.unknown_request_id errors' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'],);

  my $hello = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message(
          Overnet::Program::Protocol::build_response_ok(
            id => 'unknown-init-id'
          )
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.unknown_request_id/mx,
    'unexpected runtime.init response id is a protocol.unknown_request_id error',
  );

  $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'],);
  $hello    = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message(
          Overnet::Program::Protocol::build_response_ok(
            id => 'unknown-ready-id'
          )
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.unknown_request_id/mx,
    'unexpected ready-state response id is a protocol.unknown_request_id error',
  );
};

subtest 'ready session dispatches adapter service requests through protocol' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['adapters.use'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello_result->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  my $open = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-1',
      method => 'adapters.open_session',
      params => {adapter_id => 'mock.adapter', config => {}},
    )
  );
  is $open->{send}{type}, 'response', 'open_session yields response';
  ok $open->{send}{ok}, 'open_session succeeded';
  my $adapter_session_id = $open->{send}{result}{adapter_session_id};
  ok defined $adapter_session_id && length $adapter_session_id, 'adapter session id returned';

  my $mapped = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-2',
      method => 'adapters.map_input',
      params => {
        adapter_session_id => $adapter_session_id,
        input              => {command => 'NOTICE'},
      },
    )
  );
  ok $mapped->{send}{ok}, 'map_input succeeded';
  is $mapped->{send}{result}{events}[0]{input}, 'NOTICE', 'mapped output returned in response';

  my $closed = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-3',
      method => 'adapters.close_session',
      params => {
        adapter_session_id => $adapter_session_id,
      },
    )
  );
  ok $closed->{send}{ok}, 'close_session succeeded';
};

subtest 'ready session rejects adapter service requests without adapters.use' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['config.read'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello_result->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  my $open = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-denied',
      method => 'adapters.open_session',
      params => {adapter_id => 'mock.adapter', config => {}},
    )
  );

  ok !$open->{send}{ok}, 'open_session is denied';
  is $open->{send}{error}{code},                         'runtime.permission_denied', 'permission error code returned';
  is $open->{send}{error}{details}{required_permission}, 'adapters.use',              'required permission is reported';
  is $runtime->adapter_session_ids,                      [],                          'no adapter session is created';
};

subtest 'ready session rejects runtime-originated notifications from program' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'],);

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello_result->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message(
          {
            type   => 'notification',
            method => 'runtime.timer_fired',
            params => {
              timer_id => 'timer-1',
              fired_at => 1744301000,
            },
          }
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.unknown_method/mx,
    'runtime-originated notifications are rejected from the program side',
  );
};

subtest 'ready session returns protocol.unknown_method for runtime-only requests from program' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello_result->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-runtime-shutdown',
      method => 'runtime.shutdown',
      params => {},
    )
  );

  ok !$result->{send}{ok}, 'runtime-only request is rejected';
  is $result->{send}{error}{code}, 'protocol.unknown_method', 'wrong-direction request gets protocol.unknown_method';
};

subtest 'ready session reports unknown secret as invalid params' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['secrets.read'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello_result->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'cfg-1',
      method => 'secrets.get',
      params => {name => 'missing-token'},
    )
  );

  ok !$result->{send}{ok}, 'secrets.get rejects unknown name';
  is $result->{send}{error}{code}, 'protocol.invalid_params', 'unknown secret is typed as invalid params';
};

subtest 'malformed program.hello is rejected as invalid params' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'],);

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message(
          {
            type   => 'notification',
            method => 'program.hello',
            params => {
              program_id => 'irc.example',
            },
          }
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.invalid_params/mx,
    'malformed hello is rejected before version negotiation',
  );
};

sub _ready_instance {
  my (%args) = @_;
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'], %args,);
  my $hello    = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_response_ok(id => $hello->{send}{id}));
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());
  return $instance;
}

subtest 'instance construction validates its collaborators' => sub {
  my %valid = (supported_protocol_versions => ['0.1']);
  like(dies { Overnet::Program::Instance->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(dies { Overnet::Program::Instance->new(%valid, protocol => bless {}, 'Local::NotProtocol') },
    qr/protocol must be an Overnet::Program::Protocol instance/, 'foreign protocols are refused');
  like(dies { Overnet::Program::Instance->new(supported_protocol_versions => []) },
    qr/supported_protocol_versions must be a non-empty array/, 'protocol versions are required');
  like(dies { Overnet::Program::Instance->new(%valid, config => 'junk') },
    qr/config must be an object/, 'config must be an object');
  like(dies { Overnet::Program::Instance->new(%valid, instance_id => q{}) },
    qr/instance_id is required/, 'explicitly empty instance ids are refused');
  like(dies { Overnet::Program::Instance->new(%valid, runtime_program_id => q{}) },
    qr/runtime_program_id is required/, 'explicitly empty runtime program ids are refused');

  my $zero_ids = Overnet::Program::Instance->new(%valid, instance_id => '0', runtime_program_id => '0');
  is($zero_ids->instance_id, '0', 'a literal 0 instance id is preserved, not replaced by the default');

  my $defaulted = Overnet::Program::Instance->new(%valid, instance_id => undef, runtime_program_id => undef);
  is($defaulted->instance_id, 'instance-1', 'undef instance ids fall back to the default');
};

subtest 'state machine rejections outside the ready state' => sub {
  my $instance = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1']);
  is($instance->inflight_request_ids, [], 'a new instance has no inflight requests');
  like(dies { $instance->drain_runtime_notifications },
    qr/notifications can only be drained from ready state/, 'draining requires the ready state');
  like(dies { $instance->request_shutdown },
    qr/Shutdown can only be requested from ready state/, 'shutdown requires the ready state');
  like(
    dies { $instance->process_program_message(Overnet::Program::Protocol::build_response_ok(id => 'x')) },
    qr/Expected notification in awaiting_hello state/,
    'responses are rejected before hello',
  );
  like(
    dies {
      $instance->process_program_message(
        Overnet::Program::Protocol::build_notification(
          method => 'program.log',
          params => {level => 'info', message => 'early'},
        ),
      )
    },
    qr/Expected program[.]hello notification/,
    'other notifications are rejected before hello',
  );

  my $no_versions = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1']);
  my $refused     = $no_versions->process_program_message(
    {
      type   => 'notification',
      method => 'program.hello',
      params => {program_id => 'irc.example', supported_protocol_versions => ['9.9']},
    },
  );
  is($refused->{error}{code}, 'protocol.version_mismatch',
    'a hello without a compatible version is fatal');
  ok($refused->{fatal}, 'the version mismatch is fatal');

  my $hello_first = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1']);
  my $hello       = $hello_first->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  like(
    dies {
      $hello_first->process_program_message(
        Overnet::Program::Protocol::build_notification(
          method => 'program.log',
          params => {level => 'info', message => 'waiting'},
        ),
      )
    },
    qr/Expected response while awaiting runtime[.]init response/,
    'notifications are rejected while awaiting the init response',
  );

  my $failed_init = $hello_first->process_program_message(
    Overnet::Program::Protocol::build_response_error(
      id      => $hello->{send}{id},
      code    => 'program.boom',
      message => 'exploded',
    ),
  );
  is($hello_first->current_state, 'failed', 'a failed init response fails the instance');

  my $awaiting_ready = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1']);
  my $ready_hello    = $awaiting_ready->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $awaiting_ready->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $ready_hello->{send}{id}));
  like(
    dies {
      $awaiting_ready->process_program_message(Overnet::Program::Protocol::build_response_ok(id => 'x'))
    },
    qr/Expected notification while awaiting program[.]ready/,
    'responses are rejected while awaiting program.ready',
  );
  like(
    dies {
      $awaiting_ready->process_program_message(
        Overnet::Program::Protocol::build_program_hello(
          program_id                  => 'irc.example',
          supported_protocol_versions => ['0.1'],
        ),
      )
    },
    qr/Unexpected notification while awaiting program[.]ready/,
    'unexpected notifications are rejected while awaiting program.ready',
  );
};

subtest 'ready state handles unexpected and service messages' => sub {
  my $instance = _ready_instance(program_id => 'irc.canonical');
  is($instance->drain_runtime_notifications, [], 'no service handler drains nothing');

  like(
    dies {
      $instance->process_program_message(Overnet::Program::Protocol::build_response_ok(id => 'stray'))
    },
    qr/protocol[.]unknown_request_id/,
    'stray responses are rejected in ready state',
  );

  my $unavailable = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(id => 'r-1', method => 'storage.put', params => {}),
  );
  is($unavailable->{send}{error}{code}, 'runtime.service_unavailable',
    'service requests without a handler are refused');
};

subtest 'shutdown lifecycle handles every message shape' => sub {
  my $instance = _ready_instance();
  my $shutdown = $instance->request_shutdown;
  is($instance->current_state, 'shutdown_requested', 'shutdown was requested');
  my $shutdown_id = $shutdown->{send}{id};

  is(
    $instance->process_program_message(
      Overnet::Program::Protocol::build_notification(
        method => 'program.log',
        params => {level => 'info', message => 'closing'},
      ),
    )->{observed},
    'program.log',
    'log notifications are observed during shutdown',
  );
  like(
    dies {
      $instance->process_program_message(
        Overnet::Program::Protocol::build_program_hello(
          program_id                  => 'irc.example',
          supported_protocol_versions => ['0.1'],
        ),
      )
    },
    qr/protocol[.]unknown_method/,
    'unexpected notifications are rejected during shutdown',
  );
  is(
    $instance->process_program_message(
      Overnet::Program::Protocol::build_request(id => 'r-9', method => 'storage.put', params => {}),
    ),
    {},
    'requests are ignored during shutdown',
  );
  like(
    dies {
      $instance->process_program_message(Overnet::Program::Protocol::build_response_ok(id => 'stray'))
    },
    qr/protocol[.]unknown_request_id/,
    'stray responses are rejected during shutdown',
  );

  $instance->process_program_message(Overnet::Program::Protocol::build_response_ok(id => $shutdown_id));
  is($instance->current_state, 'shutdown_complete', 'a shutdown response completes the shutdown');

  is(
    $instance->process_program_message(
      Overnet::Program::Protocol::build_notification(
        method => 'program.health',
        params => {status => 'ok'},
      ),
    )->{observed},
    'program.health',
    'health notifications are observed after shutdown',
  );
  is(
    $instance->process_program_message(
      Overnet::Program::Protocol::build_program_hello(
        program_id                  => 'irc.example',
        supported_protocol_versions => ['0.1'],
      ),
    ),
    {},
    'other notifications are ignored after shutdown',
  );
  ok(
    defined $instance->process_program_message(
      Overnet::Program::Protocol::build_response_ok(id => 'post-shutdown'),
    ),
    'responses are tolerated after shutdown',
  );
  is(
    $instance->process_program_message(
      Overnet::Program::Protocol::build_request(id => 'r-10', method => 'storage.put', params => {}),
    ),
    {},
    'requests are ignored after shutdown',
  );

  my $failing = _ready_instance();
  my $failing_shutdown = $failing->request_shutdown;
  $failing->process_program_message(
    Overnet::Program::Protocol::build_response_error(
      id      => $failing_shutdown->{send}{id},
      code    => 'program.boom',
      message => 'exploded',
    ),
  );
  is($failing->current_state, 'failed', 'a failed shutdown response fails the instance');
};

subtest 'ready instances expose accessors and drain runtime notifications' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    instance_id     => 'instance-drain',
    program_id      => 'irc.canonical',
    permissions     => ['timers.write'],
    service_handler => $services,
  );

  is($instance->instance_id, 'instance-drain', 'the instance id accessor reports the id');
  ok($instance->is_ready, 'ready instances report readiness');
  ok(!Overnet::Program::Instance->new(supported_protocol_versions => ['0.1'])->is_ready,
    'new instances are not ready');

  is($instance->drain_runtime_notifications, [], 'an idle runtime drains no notifications');

  my $set = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-timer',
      method => 'timers.schedule',
      params => {timer_id => 'timer-1', delay_ms => 0},
    ),
  );
  ok($set->{send}{ok}, 'a timer can be scheduled through the instance');
  my $drained = $instance->drain_runtime_notifications;
  is(scalar(@{$drained}), 1, 'fired timers drain as notifications');
  is($drained->[0]{method}, 'runtime.timer_fired', 'the drained notification is a timer firing');

  my $hello_with_metadata = Overnet::Program::Instance->new(supported_protocol_versions => ['0.1']);
  $hello_with_metadata->process_program_message(
    {
      type   => 'notification',
      method => 'program.hello',
      params => {
        program_id                  => 'irc.example',
        supported_protocol_versions => ['0.1'],
        metadata                    => {build => 'test'},
      },
    },
  );
  is($hello_with_metadata->_peer_metadata, {build => 'test'}, 'hello metadata is recorded');
};

subtest 'failed instances refuse further messages' => sub {
  my $instance = Overnet::Program::Instance->new({supported_protocol_versions => ['0.1']});
  $instance->process_program_message(
    {
      type   => 'notification',
      method => 'program.hello',
      params => {program_id => 'irc.example', supported_protocol_versions => ['9.9']},
    },
  );
  is($instance->current_state, 'failed', 'the version mismatch failed the instance');
  like(
    dies {
      $instance->process_program_message(
        Overnet::Program::Protocol::build_notification(
          method => 'program.log',
          params => {level => 'info', message => 'late'},
        ),
      )
    },
    qr/Cannot process messages in state failed/,
    'failed instances refuse further messages',
  );

  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $ready    = _ready_instance(permissions => ['adapters.use'], service_handler => $services);
  my $missing  = $ready->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-missing',
      method => 'adapters.map_input',
      params => {adapter_session_id => 'absent', input => {}},
    ),
  );
  ok(!$missing->{send}{ok}, 'requests against unknown adapter sessions fail');
  ok(defined $missing->{send}{error}{code}, 'the failure carries an error code');
};

subtest 'explicit config exposes the service handler type guard' => sub {
  like(
    dies {
      Overnet::Program::Instance->new(
        supported_protocol_versions => ['0.1'],
        config                      => {},
        service_handler             => bless({}, 'Local::NotServices'),
      )
    },
    qr/service_handler must be an Overnet::Program::Services instance/,
    'foreign service handlers are refused when config is explicit',
  );

  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $ready    = _ready_instance(permissions => ['storage.read'], service_handler => $services);
  my $refused  = $ready->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-invalid',
      method => 'storage.get',
      params => {key => 'absent'},
    ),
  );
  ok(!$refused->{send}{ok}, 'reading an unknown storage key fails');
  is($refused->{send}{error}{details}{key}, 'absent', 'the error details identify the missing key');
};

done_testing;
