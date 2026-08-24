use strictures 2;
use Test::More;
use JSON           ();
use File::Basename qw(dirname);
use File::Spec;

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

sub _load_fixture_input {
  my ($name) = @_;

  my $path = File::Spec->catfile(dirname(__FILE__), 'fixtures', $name);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;

  return JSON::decode_json($json)->{input};
}

sub _ready_instance {
  my (%args) = @_;

  my $instance = Overnet::Program::Instance->new(%args);
  my $hello    = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'emitter.example',
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

subtest 'services accept valid emitted event and state candidates' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $event = _load_fixture_input('valid-native-event.json');
  my $emit_event =
    $services->dispatch_request('overnet.emit_event', {event => $event}, permissions => ['overnet.emit_event'],);
  ok $emit_event->{accepted}, 'event candidate accepted';
  is $emit_event->{event_id}, $event->{id}, 'event id returned';

  my $state = _load_fixture_input('valid-state-event.json');
  my $emit_state =
    $services->dispatch_request('overnet.emit_state', {state => $state}, permissions => ['overnet.emit_state'],);
  ok $emit_state->{accepted}, 'state candidate accepted';
  is $emit_state->{event_id}, $state->{id}, 'state id returned';

  my $emitted = $runtime->emitted_items;
  is scalar @{$emitted},       2,       'runtime recorded both accepted outputs';
  is $emitted->[0]{item_type}, 'event', 'event item type recorded';
  is $emitted->[1]{item_type}, 'state', 'state item type recorded';
};

subtest 'services accept valid emitted capability advertisements' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $result = $services->dispatch_request(
    'overnet.emit_capabilities',
    {
      capabilities => [
        {
          name    => 'adapter.irc.presence',
          version => '1.0',
          details => {scope => 'channel'},
        },
        {
          name    => 'adapter.irc.identity',
          version => '1.0',
        },
      ],
    },
    permissions => ['overnet.emit_capabilities'],
  );
  ok $result->{accepted},         'capability advertisements accepted';
  ok !exists $result->{event_id}, 'capability advertisement result does not expose event_id';

  my $emitted = $runtime->emitted_items;
  is scalar @{$emitted},        2,                      'runtime recorded each accepted capability advertisement';
  is $emitted->[0]{item_type},  'capability',           'first capability item type recorded';
  is $emitted->[1]{data}{name}, 'adapter.irc.identity', 'second capability payload recorded';
};

subtest 'services reject invalid emission params and candidate outputs' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request('overnet.emit_event', {}, permissions => ['overnet.emit_event'],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'missing event error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing event is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'overnet.emit_state',
      {state => _load_fixture_input('valid-native-event.json')},
      permissions => ['overnet.emit_state'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                      'wrong-kind state error is structured';
  is $error->{code}, 'runtime.validation_failed', 'wrong kind is reported as validation failure';
  like $error->{details}{errors}[0],
    qr/overnet\.emit_state\ requires\ kind\ 37800/mx,
    'method-specific validation error is included';

  $error = undef;
  eval {
    $services->dispatch_request(
      'overnet.emit_event',
      {event => _load_fixture_input('invalid-missing-provenance.json')},
      permissions => ['overnet.emit_event'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                      'invalid candidate error is structured';
  is $error->{code}, 'runtime.validation_failed', 'invalid candidate is reported as validation failure';
  ok(
    grep({/Missing\ required\ provenance\ field\ in\ content/mx} @{$error->{details}{errors} || []}),
    'core validation errors are surfaced',
  );

  $error = undef;
  eval {
    $services->dispatch_request('overnet.emit_capabilities', {}, permissions => ['overnet.emit_capabilities'],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'missing capabilities error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing capabilities is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'overnet.emit_capabilities',
      {
        capabilities => [
          {
            name    => 'adapter.irc.presence',
            details => 'not-an-object',
          },
        ],
      },
      permissions => ['overnet.emit_capabilities'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                      'invalid capability candidate error is structured';
  is $error->{code}, 'runtime.validation_failed', 'invalid capability advertisement is reported as validation failure';
  ok(
    grep({/capabilities\[0\]\.version\ must\ be\ a\ non-empty\ string/mx} @{$error->{details}{errors} || []}),
    'missing capability version is reported',
  );
  ok(
    grep({/capabilities\[0\]\.details\ must\ be\ an\ object/mx} @{$error->{details}{errors} || []}),
    'invalid capability details are reported',
  );
};

subtest 'instance dispatches emission requests through protocol' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['overnet.emit_event', 'overnet.emit_state', 'overnet.emit_capabilities'],
    service_handler             => $services,
  );

  my $event   = _load_fixture_input('valid-native-event.json');
  my $emitted = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'emit-1',
      method => 'overnet.emit_event',
      params => {event => $event},
    )
  );
  ok $emitted->{send}{ok},               'emit_event succeeds through instance';
  ok $emitted->{send}{result}{accepted}, 'accepted result returned through protocol';
  is $emitted->{send}{result}{event_id}, $event->{id}, 'event id returned through protocol';

  my $invalid = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'emit-2',
      method => 'overnet.emit_state',
      params => {state => $event},
    )
  );
  ok !$invalid->{send}{ok}, 'invalid state candidate fails through instance';
  is $invalid->{send}{error}{code}, 'runtime.validation_failed', 'validation failure code preserved';
  ok(
    grep({/overnet\.emit_state\ requires\ kind\ 37800/mx} @{$invalid->{send}{error}{details}{errors} || []}),
    'method-specific validation failure is preserved through protocol',
  );

  my $capabilities = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'emit-3',
      method => 'overnet.emit_capabilities',
      params => {
        capabilities => [
          {
            name    => 'adapter.irc.presence',
            version => '1.0',
          },
        ],
      },
    )
  );
  ok $capabilities->{send}{ok},               'emit_capabilities succeeds through instance';
  ok $capabilities->{send}{result}{accepted}, 'accepted capability result returned through protocol';
};

done_testing;
