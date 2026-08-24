use strictures 2;
use JSON ();
use Test2::V0;

use Overnet::Program::Protocol;

sub dies_with (&) {
  my ($code) = @_;
  my $error;
  eval { $code->(); 1 } or $error = $@;
  return $error;
}

subtest 'encodes framed JSON messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.hello',
      params => {
        program_id                  => 'irc.example',
        supported_protocol_versions => ['0.1'],
      },
    }
  );

  like $frame, qr/\A\d+\n\{/mx, 'frame has length prefix and JSON payload';
  is $protocol->buffered_bytes, 0, 'encoding does not change decoder buffer';
};

subtest 'decodes a complete frame' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.ready',
      params => {},
    }
  );

  my $messages = $protocol->feed($frame);
  is scalar(@{$messages}), 1, 'one message decoded';
  is $messages->[0],
    {
    type   => 'notification',
    method => 'program.ready',
    params => {},
    },
    'decoded message matches original';
};

subtest 'handles partial frames across multiple chunks' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'request',
      id     => '1',
      method => 'runtime.init',
      params => {
        protocol_version => '0.1',
      },
    }
  );

  my $mid    = int(length($frame) / 2);
  my $first  = substr($frame, 0, $mid);
  my $second = substr($frame, $mid);

  my $messages = $protocol->feed($first);
  is scalar(@{$messages}), 0, 'no message decoded from partial frame';
  ok $protocol->buffered_bytes > 0, 'partial bytes retained';

  $messages = $protocol->feed($second);
  is scalar(@{$messages}),   1,              'message decoded after second chunk';
  is $messages->[0]{method}, 'runtime.init', 'decoded expected request';
};

subtest 'decodes multiple frames from one chunk' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame_a  = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.log',
      params => {
        level   => 'info',
        message => 'a',
      },
    }
  );
  my $frame_b = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.health',
      params => {
        status => 'ready',
      },
    }
  );

  my $messages = $protocol->feed($frame_a . $frame_b);
  is scalar(@{$messages}),   2,                'two messages decoded';
  is $messages->[0]{method}, 'program.log',    'first message preserved';
  is $messages->[1]{method}, 'program.health', 'second message preserved';
};

subtest 'rejects non-numeric length prefixes' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  like dies_with { $protocol->feed("abc\n{}") }, qr/non-numeric\ length\ prefix/mx, 'non-numeric prefix is rejected';
};

subtest 'rejects oversized frames' => sub {
  my $protocol = Overnet::Program::Protocol->new(max_frame_size => 10);
  my $frame    = "11\n" . ('x' x 11);

  like dies_with { $protocol->feed($frame) }, qr/frame\ exceeds\ maximum\ size/mx, 'oversized frame is rejected';
};

subtest 'rejects an unterminated length prefix that exceeds the maximum' => sub {
  my $protocol = Overnet::Program::Protocol->new(max_frame_size => 1000);

  # A canonical length prefix for a <= 1000-byte frame is at most 4 digits.
  # A longer run of bytes with no newline can never begin a valid frame, so
  # it must be rejected rather than buffered without bound.
  like dies_with { $protocol->feed('1' x 4096) },
    qr/length\ prefix\ exceeds\ maximum\ size/mx,
    'an over-long unterminated length prefix is rejected instead of buffered without bound';
};

subtest 'retains a short partial length prefix awaiting its newline' => sub {
  my $protocol = Overnet::Program::Protocol->new(max_frame_size => 1000);

  my $messages = $protocol->feed('12');
  is scalar(@{$messages}), 0, 'no complete frame yet';
  ok $protocol->buffered_bytes > 0, 'a short in-progress length prefix is still retained';
};

subtest 'rejects invalid JSON payloads' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = "4\nnope";

  like dies_with { $protocol->feed($frame) }, qr/invalid\ JSON\ payload/mx, 'invalid JSON payload is rejected';
};

subtest 'rejects truncated frames at end of stream' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = "10\n{\"type\":1";

  is scalar(@{$protocol->feed($frame)}), 0, 'truncated frame remains buffered until stream end';
  like dies_with { $protocol->finish },
    qr/payload\ shorter\ than\ declared\ length|incomplete\ frame\ at\ end\ of\ stream/mx,
    'end-of-stream validation rejects truncated frame';
};

subtest 'rejects trailing bytes at end of stream after valid frames' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.ready',
      params => {},
    }
  );

  is scalar(@{$protocol->feed($frame . 'x')}), 1, 'valid frame is decoded before trailing bytes';
  like dies_with { $protocol->finish },
    qr/incomplete\ frame\ at\ end\ of\ stream|trailing\ payload\ bytes\ do\ not\ begin\ a\ valid\ next\ frame/mx,
    'end-of-stream validation rejects trailing garbage';
};

subtest 'rejects JSON payloads that are not objects' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = "2\n[]";

  like dies_with { $protocol->feed($frame) },
    qr/payload\ must\ decode\ to\ a\ JSON\ object/mx,
    'non-object payload is rejected';
};

subtest 'encode_message rejects non-object messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;

  like dies_with { $protocol->encode_message([]) }, qr/hash\ reference/mx, 'non-hash messages are rejected';
};

subtest 'constructor rejects invalid max_frame_size values' => sub {
  like dies_with { Overnet::Program::Protocol->new(max_frame_size => 'not-a-number') },
    qr/max_frame_size\ must\ be\ a\ positive\ integer/mx,
    'non-numeric max_frame_size is rejected at construction';

  like dies_with { Overnet::Program::Protocol->new(max_frame_size => 0) },
    qr/max_frame_size\ must\ be\ a\ positive\ integer/mx,
    'zero max_frame_size is rejected at construction';
};

subtest 'validates baseline request messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'request',
      id     => '1',
      method => 'runtime.shutdown',
      params => {reason => 'test'},
    }
  );

  ok $ok,               'request is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects unknown notification methods' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'program.unknown',
      params => {},
    }
  );

  ok !$ok, 'notification is invalid';
  is $code, 'protocol.unknown_method', 'returns protocol.unknown_method';
  like $message, qr/Unknown\ notification\ method/mx, 'error message is informative';
};

subtest 'validates runtime.fatal notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    Overnet::Program::Protocol::build_runtime_fatal(
      code    => 'protocol.version_mismatch',
      message => 'No compatible protocol version',
      phase   => 'handshake',
      details => {
        runtime_supported_protocol_versions => ['0.1'],
      },
    )
  );

  ok $ok,               'runtime.fatal notification is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects malformed runtime.fatal notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.fatal',
      params => {
        code => 'protocol.version_mismatch',
      },
    }
  );

  ok !$ok, 'runtime.fatal notification is invalid';
  is $code, 'protocol.invalid_params', 'runtime.fatal validation uses invalid params';
  like $message, qr/runtime\.fatal\ params\.message\ is\ required/mx, 'validation error identifies missing field';
};

subtest 'accepts baseline runtime.subscription_event item types' => sub {
  my $protocol = Overnet::Program::Protocol->new;

  for my $item_type (qw(event state capability)) {
    my ($ok, $code, $message) = $protocol->validate_message(
      {
        type   => 'notification',
        method => 'runtime.subscription_event',
        params => {
          subscription_id => 'sub-1',
          item_type       => $item_type,
          data            => {},
        },
      }
    );

    ok $ok, "runtime.subscription_event accepts item_type $item_type"
      or diag "code=$code message=$message";
  }
};

subtest 'accepts runtime.subscription_event private_message item type' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'private_message',
        data            => {
          transport    => {kind => 1059},
          private_type => 'chat.message',
          object_type  => 'chat.channel',
          object_id    => 'group:abc',
        },
      },
    }
  );

  ok $ok,               'private_message subscription event is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'accepts runtime.subscription_event nostr.event item type' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'nostr.event',
        data            => {id => 'abc', kind => 1},
      },
    }
  );

  ok $ok,               'nostr.event subscription event is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects private_message subscription events missing required data' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'private_message',
        data            => {
          private_type => 'chat.message',
          object_type  => 'chat.channel',
          object_id    => 'group:abc',
        },
      },
    }
  );

  ok !$ok, 'private_message missing transport is invalid';
  is $code, 'protocol.invalid_params', 'uses invalid params code';
  like $message, qr/private_message\ data\.transport/mx, 'error identifies missing transport';
};

subtest 'rejects runtime.subscription_event with unknown item type' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'bogus',
        data            => {},
      },
    }
  );

  ok !$ok, 'unknown item_type is invalid';
  is $code, 'protocol.invalid_params', 'uses invalid params code';
  like $message, qr/item_type\ is\ invalid/mx, 'error identifies invalid item_type';
};

subtest 'rejects malformed responses' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type  => 'response',
      id    => '1',
      ok    => JSON::true,
      error => {code => 'x', message => 'y'},
    }
  );

  ok !$ok, 'response is invalid';
  is $code, 'protocol.invalid_message', 'returns protocol.invalid_message';
  like $message, qr/must\ not\ include\ error/mx, 'error message is informative';
};

subtest 'rejects response ok values that are not booleans' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type  => 'response',
      id    => '1',
      ok    => '0',
      error => {code => 'x', message => 'y'},
    }
  );

  ok !$ok, 'response is invalid';
  is $code, 'protocol.invalid_message', 'returns protocol.invalid_message';
  like $message, qr/ok\ field\ must\ be\ a\ boolean/mx, 'error message is informative';
};

subtest 'rejects malformed program.hello notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'program.hello',
      params => {
        program_id => 'irc.example',
      },
    }
  );

  ok !$ok, 'notification is invalid';
  is $code, 'protocol.invalid_params', 'returns protocol.invalid_params';
  like $message, qr/supported_protocol_versions/mx, 'error message identifies missing field';
};

subtest 'builds baseline handshake messages' => sub {
  my $hello = Overnet::Program::Protocol::build_program_hello(
    program_id                  => 'irc.example',
    supported_protocol_versions => ['0.1'],
    program_version             => '1.2.3',
  );
  is $hello->{type},   'notification',  'hello is notification';
  is $hello->{method}, 'program.hello', 'hello method is correct';

  my $init = Overnet::Program::Protocol::build_runtime_init(
    id               => 'init-1',
    protocol_version => '0.1',
    instance_id      => 'instance-1',
    program_id       => 'irc.example',
    config           => {},
    permissions      => ['config.read'],
    services         => {},
  );
  is $init->{type},   'request',      'runtime.init is request';
  is $init->{method}, 'runtime.init', 'runtime.init method is correct';

  my $ready = Overnet::Program::Protocol::build_program_ready(params => {phase => 'startup-complete'},);
  is $ready->{method}, 'program.ready', 'program.ready method is correct';

  my $shutdown = Overnet::Program::Protocol::build_runtime_shutdown(
    id     => 'shutdown-1',
    reason => 'operator-requested',
  );
  is $shutdown->{method}, 'runtime.shutdown', 'runtime.shutdown method is correct';
};

subtest 'encodes request helper output as framed messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_request(
    id     => 'cfg-1',
    method => 'config.get',
    params => {},
  );

  my $messages = $protocol->feed($frame);
  is scalar(@{$messages}),   1,            'one helper-built request decoded';
  is $messages->[0]{method}, 'config.get', 'helper-built request survives roundtrip';
};

subtest 'method classification helpers' => sub {
  ok(Overnet::Program::Protocol->is_program_notification_method('program.hello'),
    'program.hello is a program notification');
  ok(!Overnet::Program::Protocol->is_program_notification_method('runtime.timer_fired'),
    'runtime methods are not program notifications');
  ok(!Overnet::Program::Protocol->is_program_notification_method(undef),
    'undef is not a program notification');
  ok(Overnet::Program::Protocol->is_runtime_notification_method('runtime.timer_fired'),
    'runtime.timer_fired is a runtime notification');
  ok(!Overnet::Program::Protocol->is_runtime_notification_method(['ref']),
    'references are not runtime notifications');
  ok(Overnet::Program::Protocol->is_runtime_request_method('runtime.init'),
    'runtime.init is a runtime request');
  ok(!Overnet::Program::Protocol->is_runtime_request_method('storage.put'),
    'service methods are not runtime requests');
  ok(Overnet::Program::Protocol->is_service_request_method('storage.put'),
    'storage.put is a service request');
  ok(!Overnet::Program::Protocol->is_service_request_method('runtime.init'),
    'runtime requests are not service requests');
  ok(
    (grep { $_ eq 'storage.put' } Overnet::Program::Protocol->service_request_methods),
    'service_request_methods lists the service surface',
  );
};

subtest 'encode wrappers frame their message kinds' => sub {
  my $protocol = Overnet::Program::Protocol->new;

  my $ok_frame = $protocol->encode_response_ok(id => 'r-1', result => {done => JSON::true});
  is($protocol->feed($ok_frame)->[0]{id}, 'r-1', 'encode_response_ok round-trips');

  my $error_frame = $protocol->encode_response_error(id => 'r-2', code => 'x.y', message => 'boom');
  is($protocol->feed($error_frame)->[0]{error}{code}, 'x.y', 'encode_response_error round-trips');

  my $note_frame = $protocol->encode_notification(
    method => 'program.log',
    params => {level => 'info', message => 'hi'},
  );
  is($protocol->feed($note_frame)->[0]{method}, 'program.log', 'encode_notification round-trips');
};

subtest 'validate_message rejects malformed messages one rule at a time' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $reject   = sub {
    my ($message, $code, $description) = @_;
    my ($ok, $got_code, $got_error) = $protocol->validate_message($message);
    ok(!$ok, "$description is rejected") or return;
    is($got_code, $code, "$description reports $code");
    return;
  };
  my $accept = sub {
    my ($message, $description) = @_;
    my ($ok, $got_code, $got_error) = $protocol->validate_message($message);
    ok($ok, $description) or diag "$got_code: $got_error";
    return;
  };

  $reject->({type => q{}},        'protocol.invalid_message',      'an empty type');
  $reject->({type => 'mystery'},  'protocol.unknown_message_type', 'an unknown type');

  $reject->({type => 'request', id => q{}}, 'protocol.invalid_message', 'a request without an id');
  $reject->({type => 'request', id => 'r', method => q{}},
    'protocol.invalid_message', 'a request without a method');
  $reject->({type => 'request', id => 'r', method => 'storage.put', params => 'junk'},
    'protocol.invalid_params', 'a request with non-object params');
  $reject->({type => 'request', id => 'r', method => 'no.such'},
    'protocol.unknown_method', 'a request with an unknown method');

  my %init = (
    protocol_version => '0.1',
    instance_id      => 'i-1',
    program_id       => 'p-1',
    permissions      => ['storage.read'],
    config           => {},
    services         => {},
  );
  my $init_request = sub {
    my (%override) = @_;
    return {type => 'request', id => 'r', method => 'runtime.init', params => {%init, %override}};
  };
  $accept->($init_request->(), 'a complete runtime.init request is accepted');
  $reject->($init_request->(protocol_version => q{}),
    'protocol.invalid_params', 'runtime.init without a protocol version');
  $reject->($init_request->(instance_id => q{}),
    'protocol.invalid_params', 'runtime.init without an instance id');
  $reject->($init_request->(program_id => q{}),
    'protocol.invalid_params', 'runtime.init without a program id');
  $reject->($init_request->(permissions => 'junk'),
    'protocol.invalid_params', 'runtime.init with non-array permissions');
  $reject->($init_request->(permissions => [q{}]),
    'protocol.invalid_params', 'runtime.init with empty permission entries');
  $reject->($init_request->(config => 'junk'),
    'protocol.invalid_params', 'runtime.init with non-object config');
  $reject->($init_request->(services => 'junk'),
    'protocol.invalid_params', 'runtime.init with non-object services');

  $accept->(
    {type => 'request', id => 'r', method => 'runtime.shutdown', params => {reason => 'done'}},
    'runtime.shutdown with a reason is accepted',
  );
  $reject->(
    {type => 'request', id => 'r', method => 'runtime.shutdown', params => {reason => q{}}},
    'protocol.invalid_params', 'runtime.shutdown with an empty reason',
  );

  $reject->({type => 'response', id => q{}}, 'protocol.invalid_message', 'a response without an id');
  $reject->({type => 'response', id => 'r'},
    'protocol.invalid_message', 'a response without an ok field');
  $reject->({type => 'response', id => 'r', ok => JSON::true, result => 'junk'},
    'protocol.invalid_params', 'a successful response with a non-object result');
  $reject->({type => 'response', id => 'r', ok => JSON::false},
    'protocol.invalid_message', 'an error response without an error object');
  $reject->({type => 'response', id => 'r', ok => JSON::false, error => {code => q{}}},
    'protocol.invalid_message', 'an error response without a code');
  $reject->(
    {type => 'response', id => 'r', ok => JSON::false, error => {code => 'x', message => q{}}},
    'protocol.invalid_message', 'an error response without a message',
  );
  $reject->(
    {
      type  => 'response',
      id    => 'r',
      ok    => JSON::false,
      error => {code => 'x', message => 'm', details => 'junk'},
    },
    'protocol.invalid_message', 'an error response with non-object details',
  );
  $accept->(
    {
      type  => 'response',
      id    => 'r',
      ok    => JSON::false,
      error => {code => 'x', message => 'm', details => {}},
    },
    'an error response with object details is accepted',
  );

  $reject->({type => 'notification', method => q{}},
    'protocol.invalid_message', 'a notification without a method');
  $reject->({type => 'notification', method => 'program.hello', id => 'n'},
    'protocol.invalid_message', 'a notification with an id');
  $reject->({type => 'notification', method => 'program.hello', params => 'junk'},
    'protocol.invalid_params', 'a notification with non-object params');

  my $hello = sub {
    my (%params) = @_;
    return {
      type   => 'notification',
      method => 'program.hello',
      params => {program_id => 'p', supported_protocol_versions => ['0.1'], %params},
    };
  };
  $reject->($hello->(program_id => q{}),
    'protocol.invalid_params', 'program.hello without a program id');
  $reject->($hello->(program_version => q{}),
    'protocol.invalid_params', 'program.hello with an empty program version');
  $reject->($hello->(metadata => 'junk'),
    'protocol.invalid_params', 'program.hello with non-object metadata');
  $accept->($hello->(program_version => '1.0', metadata => {}),
    'program.hello with version and metadata is accepted');

  my $log = sub {
    my (%params) = @_;
    return {
      type   => 'notification',
      method => 'program.log',
      params => {level => 'info', message => 'm', %params},
    };
  };
  $reject->($log->(level => q{}), 'protocol.invalid_params', 'program.log without a level');
  $reject->($log->(message => q{}), 'protocol.invalid_params', 'program.log without a message');
  $reject->($log->(context => 'junk'),
    'protocol.invalid_params', 'program.log with non-object context');
  $accept->($log->(context => {}), 'program.log with an object context is accepted');

  my $health = sub {
    my (%params) = @_;
    return {type => 'notification', method => 'program.health', params => {status => 'ok', %params}};
  };
  $reject->($health->(status => q{}), 'protocol.invalid_params', 'program.health without a status');
  $reject->($health->(message => q{}),
    'protocol.invalid_params', 'program.health with an empty message');
  $reject->($health->(details => 'junk'),
    'protocol.invalid_params', 'program.health with non-object details');
  $accept->($health->(message => 'fine', details => {}),
    'program.health with message and details is accepted');

  my $fatal = sub {
    my (%params) = @_;
    return {
      type   => 'notification',
      method => 'runtime.fatal',
      params => {code => 'x', message => 'm', %params},
    };
  };
  $reject->($fatal->(code => q{}), 'protocol.invalid_params', 'runtime.fatal without a code');
  $reject->($fatal->(phase => q{}),
    'protocol.invalid_params', 'runtime.fatal with an empty phase');
  $reject->($fatal->(details => 'junk'),
    'protocol.invalid_params', 'runtime.fatal with non-object details');
  $accept->($fatal->(phase => 'handshake', details => {}),
    'runtime.fatal with phase and details is accepted');

  my $subscription = sub {
    my (%params) = @_;
    return {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {subscription_id => 's-1', item_type => 'private_message', data => {}, %params},
    };
  };
  $reject->($subscription->(subscription_id => q{}),
    'protocol.invalid_params', 'subscription events without a subscription id');
  $reject->($subscription->(item_type => q{}),
    'protocol.invalid_params', 'subscription events without an item type');
  $reject->($subscription->(data => 'junk'),
    'protocol.invalid_params', 'subscription events with non-object data');
  $reject->($subscription->(item_type => 'mystery'),
    'protocol.invalid_params', 'subscription events with unknown item types');
  $reject->($subscription->(data => {transport => 'junk'}),
    'protocol.invalid_params', 'private message items without a transport object');
  $reject->($subscription->(data => {transport => {}, private_type => q{}}),
    'protocol.invalid_params', 'private message items without a private type');
  $accept->(
    $subscription->(
      data => {transport => {}, private_type => 't', object_type => 'o', object_id => 'i'},
    ),
    'complete private message items are accepted',
  );
  $accept->($subscription->(item_type => 'event', data => {}),
    'event subscription items pass structural validation');

  my $timer = sub {
    my (%params) = @_;
    return {
      type   => 'notification',
      method => 'runtime.timer_fired',
      params => {timer_id => 't-1', fired_at => -5, %params},
    };
  };
  $accept->($timer->(payload => {}), 'runtime.timer_fired with an object payload is accepted');
  $reject->($timer->(timer_id => q{}),
    'protocol.invalid_params', 'runtime.timer_fired without a timer id');
  $reject->($timer->(fired_at => 'soon'),
    'protocol.invalid_params', 'runtime.timer_fired with a non-integer fired_at');
  $reject->($timer->(payload => 'junk'),
    'protocol.invalid_params', 'runtime.timer_fired with a non-object payload');
};

subtest 'builders croak on malformed fields' => sub {
  like(dies_with { Overnet::Program::Protocol->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  ok(Overnet::Program::Protocol->new({max_frame_size => 128}), 'hashref constructor arguments work');

  like(dies_with { Overnet::Program::Protocol::build_request(id => q{}, method => 'm') },
    qr/id is required/, 'requests require an id');
  like(
    dies_with {
      Overnet::Program::Protocol::build_request(id => 'r', method => 'm', params => 'junk')
    },
    qr/params must be an object/,
    'request params must be an object',
  );
  like(
    dies_with {
      Overnet::Program::Protocol::build_response_error(
        id => 'r', code => 'c', message => 'm', details => 'junk',
      )
    },
    qr/details must be an object/,
    'error details must be an object',
  );
  like(
    dies_with {
      Overnet::Program::Protocol::build_program_hello(
        program_id                  => 'p',
        supported_protocol_versions => undef,
      )
    },
    qr/supported_protocol_versions is required/,
    'hello versions are required',
  );
  like(
    dies_with {
      Overnet::Program::Protocol::build_program_hello(
        program_id                  => 'p',
        supported_protocol_versions => 'junk',
      )
    },
    qr/supported_protocol_versions must be an array of strings/,
    'hello versions must be an array',
  );
  like(
    dies_with {
      Overnet::Program::Protocol::build_program_hello(
        program_id                  => 'p',
        supported_protocol_versions => [q{}],
      )
    },
    qr/supported_protocol_versions must be an array of strings/,
    'hello version entries must be non-empty strings',
  );
  like(
    dies_with {
      Overnet::Program::Protocol::build_program_hello(
        program_id                  => 'p',
        supported_protocol_versions => ['0.1'],
        program_version             => q{},
      )
    },
    qr/program_version must be a non-empty string/,
    'hello program versions must be non-empty',
  );

  my $with_metadata = Overnet::Program::Protocol::build_program_hello(
    program_id                  => 'p',
    supported_protocol_versions => ['0.1'],
    metadata                    => {build => 'x'},
  );
  is($with_metadata->{params}{metadata}, {build => 'x'}, 'hello metadata is included when given');

  my $minimal_fatal = Overnet::Program::Protocol::build_runtime_fatal(code => 'c', message => 'm');
  ok(!exists $minimal_fatal->{params}{phase},   'runtime.fatal omits an absent phase');
  ok(!exists $minimal_fatal->{params}{details}, 'runtime.fatal omits absent details');
};

subtest 'framing edge paths' => sub {
  my $small = Overnet::Program::Protocol->new(max_frame_size => 32);
  like(
    dies_with {
      $small->encode_message(
        {type => 'notification', method => 'program.log', params => {blob => ('x' x 100)}},
      )
    },
    qr/frame exceeds maximum size/i,
    'oversized frames refuse to encode',
  );
  like(dies_with { $small->feed('999999:{}') },
    qr/length prefix exceeds maximum size/i, 'oversized frames refuse to decode');
  like(dies_with { Overnet::Program::Protocol->new->feed("junk\n") },
    qr/non-numeric length prefix/, 'garbage prefixes are refused');
  like(dies_with { Overnet::Program::Protocol->new->feed("\n") },
    qr/missing length prefix/, 'empty prefixes are refused');
  like(dies_with { Overnet::Program::Protocol->new(max_frame_size => 32)->feed("999999\n") },
    qr/frame exceeds maximum size/, 'oversized framed lengths are refused');
  like(dies_with { Overnet::Program::Protocol->new(max_frame_size => 'lots') },
    qr/max_frame_size must be a positive integer/, 'frame sizes are validated');

  my $partial = Overnet::Program::Protocol->new;
  is($partial->feed(undef), [], 'feeding nothing yields no messages');
  $partial->feed('12');
  like(dies_with { $partial->finish }, qr/incomplete frame at end of stream/,
    'finishing with a dangling prefix croaks');

  my $trailing = Overnet::Program::Protocol->new;
  my $frame    = $trailing->encode_message(
    {type => 'notification', method => 'program.log', params => {level => 'l', message => 'm'}},
  );
  $trailing->feed($frame . '12');
  like(dies_with { $trailing->finish }, qr/incomplete frame at end of stream/,
    'finishing with a partial trailing frame croaks');
};

done_testing;
