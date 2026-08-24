use strictures 2;
use Test::More;

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

sub _ready_instance {
  my (%args) = @_;

  my $instance = Overnet::Program::Instance->new(%args);
  my $hello    = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'timers.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  return $instance;
}

subtest 'services schedule, fire, repeat, and cancel timers' => sub {
  my $now_ms   = 1_700_000_000_000;
  my $runtime  = Overnet::Program::Runtime->new(now_cb => sub {$now_ms},);
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $scheduled = $services->dispatch_request(
    'timers.schedule',
    {
      timer_id  => 'timer-delay',
      delay_ms  => 1000,
      payload   => {source => 'delay'},
      repeat_ms => 1000,
    },
    permissions => ['timers.write'],
    session_id  => 'session-1',
  );
  is $scheduled->{timer_id}, 'timer-delay', 'timers.schedule returns timer id';

  is scalar @{$runtime->drain_runtime_notifications('session-1')}, 0, 'timer does not fire before due time';

  $now_ms += 1000;
  my $first_firing = $runtime->drain_runtime_notifications('session-1');
  is scalar @{$first_firing},              1,                     'repeating timer fires once at first due time';
  is $first_firing->[0]{method},           'runtime.timer_fired', 'timer notification method is runtime.timer_fired';
  is $first_firing->[0]{params}{timer_id}, 'timer-delay',         'timer notification records timer id';
  is $first_firing->[0]{params}{fired_at}, 1_700_000_001,         'timer notification records fired_at';
  is $first_firing->[0]{params}{payload}{source}, 'delay',        'timer notification includes payload';

  $now_ms += 1000;
  my $second_firing = $runtime->drain_runtime_notifications('session-1');
  is scalar @{$second_firing},              1,             'repeating timer fires again after repeat interval';
  is $second_firing->[0]{params}{timer_id}, 'timer-delay', 'repeated timer notification records timer id';

  my $scheduled_at = $services->dispatch_request(
    'timers.schedule',
    {
      timer_id => 'timer-at',
      at       => 1_700_000_005,
      payload  => {source => 'absolute'},
    },
    permissions => ['timers.write'],
    session_id  => 'session-1',
  );
  is $scheduled_at->{timer_id}, 'timer-at', 'absolute timer schedule returns timer id';

  $services->dispatch_request(
    'timers.cancel',
    {timer_id => 'timer-delay'},
    permissions => ['timers.write'],
    session_id  => 'session-1',
  );

  $now_ms = 1_700_000_005_000;
  my $after_cancel = $runtime->drain_runtime_notifications('session-1');
  is scalar @{$after_cancel},                     1,          'cancelled repeating timer no longer fires';
  is $after_cancel->[0]{params}{timer_id},        'timer-at', 'remaining absolute timer fires';
  is $after_cancel->[0]{params}{payload}{source}, 'absolute', 'absolute timer payload is preserved';

  is scalar @{$runtime->drain_runtime_notifications('session-1')}, 0, 'one-shot timer is removed after firing';
};

subtest 'repeating timers coalesce overdue intervals into one notification per drain' => sub {
  my $now_ms   = 0;
  my $runtime  = Overnet::Program::Runtime->new(now_cb => sub {$now_ms},);
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  $services->dispatch_request(
    'timers.schedule',
    {
      timer_id  => 'timer-repeat',
      delay_ms  => 100,
      repeat_ms => 100,
    },
    permissions => ['timers.write'],
    session_id  => 'session-repeat',
  );

  $now_ms = 450;
  my $first_drain = $runtime->drain_runtime_notifications('session-repeat');
  is scalar @{$first_drain},              1, 'overdue repeating timer emits one notification for the drain';
  is $first_drain->[0]{params}{timer_id}, 'timer-repeat', 'coalesced notification records timer id';

  $now_ms = 499;
  is scalar @{$runtime->drain_runtime_notifications('session-repeat')}, 0,
    'timer does not immediately replay missed historical intervals';

  $now_ms = 500;
  my $second_drain = $runtime->drain_runtime_notifications('session-repeat');
  is scalar @{$second_drain},              1, 'timer resumes on the next scheduled boundary after coalescing';
  is $second_drain->[0]{params}{timer_id}, 'timer-repeat', 'subsequent notification records timer id';
};

subtest 'services reject invalid timer params and unknown timers' => sub {
  my $now_ms   = 1_700_000_000_000;
  my $runtime  = Overnet::Program::Runtime->new(now_cb => sub {$now_ms},);
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'timers.schedule',
      {timer_id => 'missing-schedule'},
      permissions => ['timers.write'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'missing schedule fields error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing at/delay is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'timers.schedule',
      {
        timer_id => 'ambiguous-schedule',
        at       => 1_700_000_005,
        delay_ms => 1000,
      },
      permissions => ['timers.write'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'ambiguous schedule error is structured';
  is $error->{code}, 'protocol.invalid_params', 'supplying both at and delay is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'timers.schedule',
      {
        timer_id  => 'bad-repeat',
        delay_ms  => 1000,
        repeat_ms => 0,
      },
      permissions => ['timers.write'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'bad repeat error is structured';
  is $error->{code}, 'protocol.invalid_params', 'non-positive repeat is invalid params';

  $services->dispatch_request(
    'timers.schedule',
    {
      timer_id => 'dup-timer',
      delay_ms => 1000,
    },
    permissions => ['timers.write'],
    session_id  => 'session-1',
  );

  $error = undef;
  eval {
    $services->dispatch_request(
      'timers.schedule',
      {
        timer_id => 'dup-timer',
        delay_ms => 2000,
      },
      permissions => ['timers.write'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'duplicate timer id error is structured';
  is $error->{code}, 'protocol.invalid_params', 'duplicate timer id is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'timers.cancel',
      {timer_id => 'missing'},
      permissions => ['timers.write'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'unknown cancel error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown timer cancel is invalid params';
};

subtest 'instance drains runtime.timer_fired notifications' => sub {
  my $now_ms   = 1_700_000_000_000;
  my $runtime  = Overnet::Program::Runtime->new(now_cb => sub {$now_ms},);
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    instance_id                 => 'instance-timers',
    supported_protocol_versions => ['0.1'],
    permissions                 => ['timers.write'],
    service_handler             => $services,
  );

  my $scheduled = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'timer-1',
      method => 'timers.schedule',
      params => {
        timer_id => 'timer-instance',
        delay_ms => 1000,
        payload  => {source => 'instance'},
      },
    )
  );
  ok $scheduled->{send}{ok}, 'timers.schedule succeeds through instance';
  is $scheduled->{send}{result}{timer_id}, 'timer-instance', 'scheduled timer id returned through protocol';

  is scalar @{$instance->drain_runtime_notifications}, 0, 'instance has no timer notifications before due time';

  $now_ms += 1000;
  my $notifications = $instance->drain_runtime_notifications;
  is scalar @{$notifications},                     1,                     'instance drains one timer notification';
  is $notifications->[0]{type},                    'notification',        'drained message is a notification';
  is $notifications->[0]{method},                  'runtime.timer_fired', 'drained method is runtime.timer_fired';
  is $notifications->[0]{params}{timer_id},        'timer-instance',      'timer notification records timer id';
  is $notifications->[0]{params}{fired_at},        1_700_000_001,         'timer notification records fired_at';
  is $notifications->[0]{params}{payload}{source}, 'instance',            'timer notification includes payload';

  my $cancelled = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'timer-2',
      method => 'timers.schedule',
      params => {
        timer_id => 'timer-cancelled',
        delay_ms => 1000,
      },
    )
  );
  ok $cancelled->{send}{ok}, 'second timer schedule succeeds through instance';

  my $cancel = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'timer-3',
      method => 'timers.cancel',
      params => {
        timer_id => 'timer-cancelled',
      },
    )
  );
  ok $cancel->{send}{ok}, 'timers.cancel succeeds through instance';

  $now_ms += 1000;
  is scalar @{$instance->drain_runtime_notifications}, 0, 'cancelled timer produces no runtime notification';
};

sub _timer_error (&) {
  my ($code) = @_;
  return eval { $code->(); 1 } ? undef : $@;
}

subtest 'timer construction and helpers validate their inputs' => sub {
  my %valid = (
    session_id => 'session-1',
    timer_id   => 'timer-1',
    due_at_ms  => 1_000,
  );

  like(_timer_error { Overnet::Program::Timer->new('odd') },
    qr/constructor arguments must be a hash/, 'odd constructor arguments die');
  like(_timer_error { Overnet::Program::Timer->new(%valid, session_id => q{}) },
    qr/session_id is required/, 'a session id is required');
  like(_timer_error { Overnet::Program::Timer->new(%valid, timer_id => q{}) },
    qr/timer_id is required/, 'a timer id is required');
  like(_timer_error { Overnet::Program::Timer->new(%valid, due_at_ms => 'soon') },
    qr/due_at_ms must be an integer/, 'due_at_ms must be an integer');
  like(_timer_error { Overnet::Program::Timer->new(%valid, repeat_ms => 0) },
    qr/repeat_ms must be a positive integer/, 'repeat_ms must be positive');
  like(_timer_error { Overnet::Program::Timer->new(%valid, payload => 'junk') },
    qr/payload must be an object/, 'payloads must be objects');

  my $timer = Overnet::Program::Timer->new({%valid, payload => {note => 'hi'}});
  is_deeply($timer->payload, {note => 'hi'}, 'payloads round-trip through the accessor');
  my $bare = Overnet::Program::Timer->new(%valid);
  is($bare->payload, undef, 'timers without a payload return none');

  like(_timer_error { $bare->is_due(now_ms => 'soon') },
    qr/now_ms must be an integer/, 'is_due requires an integer time');
  like(_timer_error { $bare->advance_after_fire },
    qr/Timer is not repeating/, 'advance_after_fire requires a repeating timer');
  like(_timer_error { $bare->advance_after_fire_until_after(now_ms => 1) },
    qr/Timer is not repeating/, 'advance_after_fire_until_after requires a repeating timer');
  like(_timer_error { $bare->build_notification_params(fired_at => 'soon') },
    qr/fired_at must be an integer/, 'notification params require an integer time');

  my $repeating = Overnet::Program::Timer->new(%valid, repeat_ms => 250);
  like(
    _timer_error { $repeating->advance_after_fire_until_after(now_ms => 'soon') },
    qr/now_ms must be an integer/,
    'catch-up advancement requires an integer time',
  );
};

done_testing;
