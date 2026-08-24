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
      program_id                  => 'store.example',
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

subtest 'services append and read event streams' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $first = $services->dispatch_request(
    'events.append',
    {
      stream => 'program.journal',
      event  => {step => 1, action => 'start'},
    },
    permissions => ['events.append'],
  );
  is $first->{stream}, 'program.journal', 'append returns stream name';
  is $first->{offset}, 0,                 'first append gets offset 0';

  my $second = $services->dispatch_request(
    'events.append',
    {
      stream => 'program.journal',
      event  => {step => 2, action => 'finish'},
    },
    permissions => ['events.append'],
  );
  is $second->{offset}, 1, 'second append gets offset 1';

  my $read_all =
    $services->dispatch_request('events.read', {stream => 'program.journal'}, permissions => ['events.read'],);
  is $read_all->{stream},                    'program.journal', 'read returns stream name';
  is scalar @{$read_all->{entries}},         2,                 'read returns appended entries';
  is $read_all->{entries}[0]{offset},        0,                 'first entry offset returned';
  is $read_all->{entries}[1]{event}{action}, 'finish',          'second event payload returned';

  my $read_tail = $services->dispatch_request(
    'events.read',
    {
      stream       => 'program.journal',
      after_offset => 0,
      limit        => 1,
    },
    permissions => ['events.read'],
  );
  is scalar @{$read_tail->{entries}},  1, 'after_offset and limit are applied';
  is $read_tail->{entries}[0]{offset}, 1, 'tail read starts after exclusive lower bound';
};

subtest 'services reject invalid event store params' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request('events.append', {event => {ok => 1}}, permissions => ['events.append'],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'missing stream error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing stream is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'events.append',
      {stream => 'program.journal', event => 'not-an-object'},
      permissions => ['events.append'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'non-object event error is structured';
  is $error->{code}, 'protocol.invalid_params', 'non-object appended event is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'events.read',
      {stream => 'program.journal', limit => 'many'},
      permissions => ['events.read'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'invalid limit error is structured';
  is $error->{code}, 'protocol.invalid_params', 'invalid limit is invalid params';
};

subtest 'services provide document storage CRUD and listing' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $put_profile = $services->dispatch_request(
    'storage.put',
    {
      key   => 'profiles/alice',
      value => {
        display_name => 'Alice',
        preferences  => {theme => 'light'},
      },
    },
    permissions => ['storage.write'],
  );
  is $put_profile->{key}, 'profiles/alice', 'storage.put returns stored key';

  my $put_room = $services->dispatch_request(
    'storage.put',
    {
      key   => 'rooms/general',
      value => {
        topic => 'General chat',
      },
    },
    permissions => ['storage.write'],
  );
  is $put_room->{key}, 'rooms/general', 'second storage.put returns stored key';

  my $get_profile =
    $services->dispatch_request('storage.get', {key => 'profiles/alice'}, permissions => ['storage.read'],);
  is $get_profile->{key},                 'profiles/alice', 'storage.get returns requested key';
  is $get_profile->{value}{display_name}, 'Alice',          'storage.get returns stored document';

  my $list_all = $services->dispatch_request('storage.list', {}, permissions => ['storage.read'],);
  is_deeply($list_all->{keys}, ['profiles/alice', 'rooms/general'], 'storage.list returns sorted keys',);

  my $list_profiles =
    $services->dispatch_request('storage.list', {prefix => 'profiles/'}, permissions => ['storage.read'],);
  is_deeply($list_profiles->{keys}, ['profiles/alice'], 'storage.list applies prefix filtering',);

  my $delete_profile =
    $services->dispatch_request('storage.delete', {key => 'profiles/alice'}, permissions => ['storage.write'],);
  is_deeply $delete_profile, {}, 'storage.delete returns empty result';

  my $list_after_delete = $services->dispatch_request('storage.list', {}, permissions => ['storage.read'],);
  is_deeply($list_after_delete->{keys}, ['rooms/general'], 'deleted document is removed from listings',);
};

subtest 'services reject invalid document storage params' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request('storage.put', {value => {ok => 1}}, permissions => ['storage.write'],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'missing storage.put key error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing storage.put key is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'storage.put',
      {
        key   => 'profiles/alice',
        value => 'not-an-object',
      },
      permissions => ['storage.write'],
    );
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'non-object storage.put value error is structured';
  is $error->{code}, 'protocol.invalid_params', 'non-object storage.put value is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request('storage.get', {key => 'missing/document'}, permissions => ['storage.read'],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'unknown storage.get key error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown storage.get key is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request('storage.delete', {key => 'missing/document'}, permissions => ['storage.write'],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'unknown storage.delete key error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown storage.delete key is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request('storage.list', {prefix => {}}, permissions => ['storage.read'],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                    'non-string storage.list prefix error is structured';
  is $error->{code}, 'protocol.invalid_params', 'non-string storage.list prefix is invalid params';
};

subtest 'document storage isolates stored values from caller mutation' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $input    = {
    display_name => 'Carol',
    preferences  => {theme => 'light'},
  };

  $services->dispatch_request(
    'storage.put',
    {
      key   => 'profiles/carol',
      value => $input,
    },
    permissions => ['storage.write'],
  );

  $input->{display_name} = 'Changed';
  $input->{preferences}{theme} = 'dark';

  my $stored = $services->dispatch_request('storage.get', {key => 'profiles/carol'}, permissions => ['storage.read'],);
  is $stored->{value}{display_name},       'Carol', 'stored document is isolated from input mutation';
  is $stored->{value}{preferences}{theme}, 'light', 'nested input mutation does not affect stored document';

  $stored->{value}{display_name} = 'Mutated read result';
  $stored->{value}{preferences}{theme} = 'solarized';

  my $reloaded =
    $services->dispatch_request('storage.get', {key => 'profiles/carol'}, permissions => ['storage.read'],);
  is $reloaded->{value}{display_name},       'Carol', 'stored document is isolated from returned value mutation';
  is $reloaded->{value}{preferences}{theme}, 'light', 'nested returned value mutation does not affect stored document';
};

subtest 'services enforce storage permissions' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'storage.put',
      {
        key   => 'profiles/dave',
        value => {display_name => 'Dave'},
      },
      permissions => [],
    );
    1;
  } or $error = $@;
  is ref($error),                            'HASH',                      'storage.put permission error is structured';
  is $error->{code},                         'runtime.permission_denied', 'storage.put requires permission';
  is $error->{details}{required_permission}, 'storage.write',             'storage.put reports required permission';

  $services->dispatch_request(
    'storage.put',
    {
      key   => 'profiles/dave',
      value => {display_name => 'Dave'},
    },
    permissions => ['storage.write'],
  );

  $error = undef;
  eval {
    $services->dispatch_request('storage.get', {key => 'profiles/dave'}, permissions => [],);
    1;
  } or $error = $@;
  is ref($error),                            'HASH',                      'storage.get permission error is structured';
  is $error->{code},                         'runtime.permission_denied', 'storage.get requires permission';
  is $error->{details}{required_permission}, 'storage.read',              'storage.get reports required permission';
};

subtest 'accepted emitted outputs are exposed through runtime event streams' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $event      = _load_fixture_input('valid-native-event.json');
  my $state      = _load_fixture_input('valid-state-event.json');
  my $capability = {
    name    => 'adapter.irc.presence',
    version => '1.0',
    details => {scope => 'channel'},
  };

  $services->dispatch_request('overnet.emit_event', {event => $event}, permissions => ['overnet.emit_event'],);
  $services->dispatch_request('overnet.emit_state', {state => $state}, permissions => ['overnet.emit_state'],);
  $services->dispatch_request(
    'overnet.emit_capabilities',
    {capabilities => [$capability]},
    permissions => ['overnet.emit_capabilities'],
  );

  my $event_stream      = $runtime->emitted_stream_name('event');
  my $state_stream      = $runtime->emitted_stream_name('state');
  my $capability_stream = $runtime->emitted_stream_name('capability');

  my $event_entries =
    $services->dispatch_request('events.read', {stream => $event_stream}, permissions => ['events.read'],);
  is scalar @{$event_entries->{entries}},     1,            'accepted emitted event is available via events.read';
  is $event_entries->{entries}[0]{event}{id}, $event->{id}, 'accepted emitted event payload is stored';

  my $state_entries =
    $services->dispatch_request('events.read', {stream => $state_stream}, permissions => ['events.read'],);
  is scalar @{$state_entries->{entries}},     1,            'accepted emitted state is available via events.read';
  is $state_entries->{entries}[0]{event}{id}, $state->{id}, 'accepted emitted state payload is stored';

  my $capability_entries =
    $services->dispatch_request('events.read', {stream => $capability_stream}, permissions => ['events.read'],);
  is scalar @{$capability_entries->{entries}}, 1, 'accepted emitted capability is available via events.read';
  is $capability_entries->{entries}[0]{event}{name}, $capability->{name},
    'accepted emitted capability payload is stored';
};

subtest 'instance can read emitted stream entries through protocol' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['overnet.emit_event', 'events.read'],
    service_handler             => $services,
  );

  my $event = _load_fixture_input('valid-native-event.json');
  my $emit  = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'emit-store-1',
      method => 'overnet.emit_event',
      params => {event => $event},
    )
  );
  ok $emit->{send}{ok}, 'emit_event succeeds before stream read';

  my $stream = $runtime->emitted_stream_name('event');
  my $read   = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'emit-store-2',
      method => 'events.read',
      params => {stream => $stream},
    )
  );
  ok $read->{send}{ok}, 'events.read succeeds through instance';
  is $read->{send}{result}{entries}[0]{event}{id}, $event->{id}, 'protocol read returns emitted event payload';
};

subtest 'instance can use document storage through protocol' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['storage.read', 'storage.write'],
    service_handler             => $services,
  );

  my $put = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'storage-1',
      method => 'storage.put',
      params => {
        key   => 'profiles/bob',
        value => {display_name => 'Bob'},
      },
    )
  );
  ok $put->{send}{ok}, 'storage.put succeeds through instance';
  is $put->{send}{result}{key}, 'profiles/bob', 'storage.put response includes key';

  my $get = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'storage-2',
      method => 'storage.get',
      params => {key => 'profiles/bob'},
    )
  );
  ok $get->{send}{ok}, 'storage.get succeeds through instance';
  is $get->{send}{result}{value}{display_name}, 'Bob', 'storage.get returns stored value';

  my $list = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'storage-3',
      method => 'storage.list',
      params => {prefix => 'profiles/'},
    )
  );
  ok $list->{send}{ok}, 'storage.list succeeds through instance';
  is_deeply $list->{send}{result}{keys}, ['profiles/bob'], 'storage.list returns matching keys';

  my $delete = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'storage-4',
      method => 'storage.delete',
      params => {key => 'profiles/bob'},
    )
  );
  ok $delete->{send}{ok}, 'storage.delete succeeds through instance';
  is_deeply $delete->{send}{result}, {}, 'storage.delete returns empty result';
};

subtest 'services normalize unstructured handler failures' => sub {
  my $runtime  = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  no warnings 'redefine';
  local *Overnet::Program::Runtime::put_document = sub { die "storage backend exploded\n" };
  use warnings 'redefine';

  my $error;
  eval {
    $services->dispatch_request(
      'storage.put',
      {key => 'profiles/alice', value => {ok => 1}},
      permissions => ['storage.write'],
    );
    1;
  } or $error = $@;

  is ref($error),       'HASH',                     'unstructured handler failure is structured';
  is $error->{code},    'program.operation_failed', 'unstructured failure uses the fallback code';
  is $error->{message}, 'storage backend exploded', 'failure message is preserved without trailing newline';
};

sub _store_error (&) {
  my ($code) = @_;
  return eval { $code->(); 1 } ? undef : $@;
}

subtest 'store validation rejects malformed inputs' => sub {
  my $store = Overnet::Program::Store->new({});
  like(_store_error { Overnet::Program::Store->new('odd') }, qr/constructor arguments must be a hash/, 'odd constructor arguments die');

  like(_store_error { $store->has_document(key => q{}) },    qr/key is required/, 'has_document requires a key');
  like(_store_error { $store->put_document(key => q{}) },    qr/key is required/, 'put_document requires a key');
  like(_store_error { $store->put_document(key => 'k', value => 'junk') }, qr/value must be an object/, 'put_document requires an object value');
  like(_store_error { $store->get_document(key => q{}) },    qr/key is required/, 'get_document requires a key');
  like(_store_error { $store->get_document(key => 'nope') }, qr/Unknown key: nope/, 'get_document rejects unknown keys');
  like(_store_error { $store->delete_document(key => q{}) }, qr/key is required/, 'delete_document requires a key');
  like(_store_error { $store->delete_document(key => 'nope') }, qr/Unknown key: nope/, 'delete_document rejects unknown keys');
  like(_store_error { $store->list_documents(prefix => []) }, qr/prefix must be a string/, 'list_documents requires a scalar prefix');

  like(_store_error { $store->append_event(stream => q{}) }, qr/stream is required/,
    'append_event requires a stream');
  like(_store_error { $store->append_event(stream => 's', event => 'junk') }, qr/event must be an object/, 'append_event requires an object event');
  like(_store_error { $store->read_events(stream => q{}) }, qr/stream is required/,
    'read_events requires a stream');
  like(_store_error { $store->read_events(stream => 's', after_offset => 'soon') },
    qr/after_offset must be an integer/, 'after_offset must be an integer');
  like(_store_error { $store->read_events(stream => 's', limit => -1) },
    qr/limit must be a non-negative integer/, 'limit must be a non-negative integer');
  is_deeply($store->read_events(stream => 'empty')->{entries}, [], 'reading an unknown stream returns nothing');
};

done_testing;
