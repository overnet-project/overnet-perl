use strictures 2;
use Test::More;
use File::Spec;
use FindBin;
use JSON ();
use JSON::Schema::Modern;

use Overnet::Core::ProfileContract;

my $spec_dir     = _spec_root();
my $schema_path  = File::Spec->catfile($spec_dir, 'schemas',  'profile-contract-v1.schema.json');
my $fixture_path = File::Spec->catfile($spec_dir, 'fixtures', 'profile-contracts', 'valid-chat-message-contract.json');
my $event_path =
  File::Spec->catfile($spec_dir, 'fixtures', 'profile-contracts', 'valid-profile-event-chat-message.json');

plan skip_all => "profile contract schema not found at $schema_path"
  unless -f $schema_path && -f $fixture_path && -f $event_path;

my $json_schema = JSON::Schema::Modern->new(
  specification_version => 'draft2020-12',
  output_format         => 'flag',
);

my $schema        = _load_json($schema_path);
my $base_contract = _load_json($fixture_path)->{input}{contract};
my $base_event    = _load_json($event_path)->{input}{event};

subtest 'contract validator matches profile contract JSON schema' => sub {
  my @cases = (
    ['valid base contract', sub { }], _missing_top_level_cases(),
    _missing_nested_cases(),          _mutated_contract_cases(),
    _reference_contract_cases(),
  );

  plan tests => scalar @cases;

  for my $case (@cases) {
    my ($name, $mutate) = @{$case};
    my $contract = _clone($base_contract);
    $mutate->($contract);

    my $oracle = _schema_valid($contract, $schema);
    my $result = Overnet::Core::ProfileContract::validate_contract($contract);

    is($result->{valid} ? 1 : 0, $oracle ? 1 : 0, $name,)
      or diag explain {
      validator_errors => $result->{errors},
      contract         => $contract,
      };
  }
};

subtest 'profile event body validation matches JSON Schema evaluation' => sub {
  my @cases = (
    [
      'maxLength invalid',
      {
        type       => 'object',
        required   => ['text'],
        properties => {
          text => {
            type      => 'string',
            maxLength => 3,
          },
        },
      },
      {
        text => 'hello',
      },
    ],
    [
      'maxLength valid',
      {
        type       => 'object',
        required   => ['text'],
        properties => {
          text => {
            type      => 'string',
            maxLength => 5,
          },
        },
      },
      {
        text => 'hello',
      },
    ],
    [
      'pattern invalid',
      {
        type       => 'object',
        required   => ['text'],
        properties => {
          text => {
            type    => 'string',
            pattern => '^[a-z]+$',
          },
        },
      },
      {
        text => 'HELLO',
      },
    ],
    [
      'minimum invalid',
      {
        type       => 'object',
        required   => ['count'],
        properties => {
          count => {
            type    => 'integer',
            minimum => 5,
          },
        },
      },
      {
        count => 3,
      },
    ],
    [
      'array items invalid',
      {
        type       => 'object',
        required   => ['items'],
        properties => {
          items => {
            type  => 'array',
            items => {
              type => 'integer',
            },
          },
        },
      },
      {
        items => [1, 'x'],
      },
    ],
    [
      'anyOf invalid',
      {
        type       => 'object',
        required   => ['value'],
        properties => {
          value => {
            anyOf => [{type => 'integer'}, {const => 'ok'},],
          },
        },
      },
      {
        value => 'bad',
      },
    ],
    [
      'anyOf valid',
      {
        type       => 'object',
        required   => ['value'],
        properties => {
          value => {
            anyOf => [{type => 'integer'}, {const => 'ok'},],
          },
        },
      },
      {
        value => 'ok',
      },
    ],
    [
      'oneOf invalid',
      {
        type       => 'object',
        required   => ['value'],
        properties => {
          value => {
            oneOf => [{type => 'integer'}, {type => 'number'},],
          },
        },
      },
      {
        value => 3,
      },
    ],
    [
      'not invalid',
      {
        type       => 'object',
        required   => ['value'],
        properties => {
          value => {
            not => {
              const => 'bad',
            },
          },
        },
      },
      {
        value => 'bad',
      },
    ],
    [
      'boolean valid',
      {
        type       => 'object',
        required   => ['ok'],
        properties => {
          ok => {
            type => 'boolean',
          },
        },
      },
      {
        ok => JSON::true,
      },
    ],
    [
      'boolean invalid',
      {
        type       => 'object',
        required   => ['ok'],
        properties => {
          ok => {
            type => 'boolean',
          },
        },
      },
      {
        ok => 'true',
      },
    ],
  );

  plan tests => scalar @cases;

  for my $case (@cases) {
    my ($name, $body_schema, $body) = @{$case};
    my $contract = _clone($base_contract);
    $contract->{event_types}{'chat.message'}{body_schema} = $body_schema;

    my $oracle = _schema_valid($body, $body_schema);
    my $result = Overnet::Core::ProfileContract::validate_profile_event(
      event    => _event_with_body($body),
      contract => $contract,
    );

    is($result->{valid} ? 1 : 0, $oracle ? 1 : 0, $name,)
      or diag explain {
      validator_errors => $result->{errors},
      body_schema      => $body_schema,
      body             => $body,
      };
  }
};

done_testing;

sub _missing_top_level_cases {
  return map {
    my $field = $_;
    ["missing top-level $field", sub { delete $_[0]->{$field} }];
  } qw(contract_version profile profile_version status description capabilities object_types event_types fixtures extensions);
}

sub _missing_nested_cases {
  my @paths = (
    [qw(object_types chat.channel description)],        [qw(object_types chat.channel id)],
    [qw(object_types chat.channel id scheme)],          [qw(object_types chat.channel id pattern)],
    [qw(object_types chat.channel id examples)],        [qw(object_types chat.channel state)],
    [qw(object_types chat.channel state derivation)],   [qw(object_types chat.channel state state_event_type)],
    [qw(object_types chat.channel extensions)],         [qw(event_types chat.message description)],
    [qw(event_types chat.message kind)],                [qw(event_types chat.message object_type)],
    [qw(event_types chat.message required_tags)],       [qw(event_types chat.message body_schema)],
    [qw(event_types chat.message body_schema type)],    [qw(event_types chat.message references)],
    [qw(event_types chat.message state_effect)],        [qw(event_types chat.message authorization)],
    [qw(event_types chat.message authorization model)], [qw(event_types chat.message authorization description)],
    [qw(event_types chat.message privacy)],             [qw(event_types chat.message extensions)],
    [qw(fixtures valid)],                               [qw(fixtures invalid)],
  );

  return map {
    my @path = @{$_};
    ['missing ' . join('.', @path), sub { _delete_path($_[0], @path) }];
  } @paths;
}

sub _mutated_contract_cases {
  my @cases = (
    ['contract_version string',  [qw(contract_version)], '1'],
    ['profile number',           [qw(profile)],          1],
    ['profile_version number',   [qw(profile_version)],  1],
    ['status array',             [qw(status)],           []],
    ['description array',        [qw(description)],      []],
    ['capabilities item number', [qw(capabilities)],     [1]],
    ['depends_on item string',   [qw(depends_on)],       ['identity']],
    ['depends_on extra field',   [qw(depends_on)],       [{profile => 'identity', version => '1.0.0', x => 1}]],
    ['object_types array',       [qw(object_types)],     []],
    ['object_types empty',       [qw(object_types)],     {}],
    [
      'object type bad property name',
      [qw(object_types)],
      {
        Chat => _clone($base_contract->{object_types}{'chat.channel'})
      }
    ],
    ['object def array',         [qw(object_types chat.channel)],                        []],
    ['object def extra',         [qw(object_types chat.channel x)],                      1],
    ['id array',                 [qw(object_types chat.channel id)],                     []],
    ['id extra',                 [qw(object_types chat.channel id x)],                   1],
    ['id scheme invalid',        [qw(object_types chat.channel id scheme)],              'slug'],
    ['id pattern empty',         [qw(object_types chat.channel id pattern)],             ''],
    ['id examples string',       [qw(object_types chat.channel id examples)],            'channel:general'],
    ['id example empty',         [qw(object_types chat.channel id examples)],            ['']],
    ['state array',              [qw(object_types chat.channel state)],                  []],
    ['state extra',              [qw(object_types chat.channel state x)],                1],
    ['state derivation invalid', [qw(object_types chat.channel state derivation)],       'latest'],
    ['state_event_type empty',   [qw(object_types chat.channel state state_event_type)], ''],
    ['object extensions array',  [qw(object_types chat.channel extensions)],             []],
    ['event_types array',        [qw(event_types)],                                      []],
    ['event_types empty',        [qw(event_types)],                                      {}],
    [
      'event type bad property name', [qw(event_types)], {Chat => _clone($base_contract->{event_types}{'chat.message'})}
    ],
    ['event def array',       [qw(event_types chat.message)],               []],
    ['event def extra',       [qw(event_types chat.message x)],             1],
    ['event kind string',     [qw(event_types chat.message kind)],          '7800'],
    ['event kind bad',        [qw(event_types chat.message kind)],          7802],
    ['event object type bad', [qw(event_types chat.message object_type)],   'channel'],
    ['required_tags string',  [qw(event_types chat.message required_tags)], 'overnet_v'],
    [
      'required_tags bad item',
      [qw(event_types chat.message required_tags)],
      [qw(overnet_v), 'bad tag', qw(overnet_et overnet_ot overnet_oid v t o d)]
    ],
    [
      'required_tags duplicate',
      [qw(event_types chat.message required_tags)],
      [qw(overnet_v overnet_v overnet_et overnet_ot overnet_oid v t o d)]
    ],
    ['body_schema array',               [qw(event_types chat.message body_schema)],               []],
    ['body_schema type string',         [qw(event_types chat.message body_schema type)],          'string'],
    ['references string',               [qw(event_types chat.message references)],                'none'],
    ['state_effect invalid',            [qw(event_types chat.message state_effect)],              'changes'],
    ['authorization array',             [qw(event_types chat.message authorization)],             []],
    ['authorization extra',             [qw(event_types chat.message authorization x)],           1],
    ['authorization model invalid',     [qw(event_types chat.message authorization model)],       'owner'],
    ['authorization description empty', [qw(event_types chat.message authorization description)], ''],
    ['privacy invalid',                 [qw(event_types chat.message privacy)],                   'private'],
    ['event extensions array',          [qw(event_types chat.message extensions)],                []],
    ['fixtures array',                  [qw(fixtures)],                                           []],
    ['fixtures extra',                  [qw(fixtures x)],                                         []],
    ['fixture valid string',            [qw(fixtures valid)],                                     'a.json'],
    ['fixture valid absolute',          [qw(fixtures valid)],                                     ['/tmp/a.json']],
    ['fixture valid parent',            [qw(fixtures valid)],                                     ['../a.json']],
    ['fixture valid duplicate',         [qw(fixtures valid)],                                     [qw(a.json a.json)]],
    ['extensions array',                [qw(extensions)],                                         []],
  );

  return map {
    my ($name, $path, $value) = @{$_};
    [$name, sub { _set_path($_[0], $path, $value) }];
  } @cases;
}

sub _reference_contract_cases {
  my $valid_reference = {
    name               => 'related',
    required           => JSON::false,
    tag                => 'e',
    target_object_type => 'chat.channel',
    target_event_type  => undef,
  };

  my @cases = (
    ['reference item string',       'chat.channel'],
    ['reference extra',             {%{$valid_reference}, x => 1}],
    ['reference missing name',      _without($valid_reference, 'name')],
    ['reference name empty',        {%{$valid_reference}, name               => ''}],
    ['reference required number',   {%{$valid_reference}, required           => 1}],
    ['reference tag bad',           {%{$valid_reference}, tag                => 'bad tag'}],
    ['reference target object bad', {%{$valid_reference}, target_object_type => 'channel'}],
    [
      'reference target event bad',
      {
        %{$valid_reference},
        target_object_type => undef,
        target_event_type  => 'message'
      }
    ],
    ['reference both targets', {%{$valid_reference}, target_event_type => 'chat.message'}],
    [
      'reference no targets',
      {
        %{$valid_reference},
        target_object_type => undef,
        target_event_type  => undef
      }
    ],
    ['reference required null tag', {%{$valid_reference}, required => JSON::true, tag => undef}],
  );

  return map {
    my ($name, $reference) = @{$_};
    [
      $name,
      sub {
        $_[0]->{event_types}{'chat.message'}{references} = [$reference];
      }
    ];
  } @cases;
}

sub _schema_valid {
  my ($instance, $schema) = @_;
  my $result = $json_schema->evaluate($instance, $schema);
  return $result->valid ? 1 : 0;
}

sub _event_with_body {
  my ($body)  = @_;
  my $event   = _clone($base_event);
  my $content = JSON::decode_json($event->{content});
  $content->{body}  = $body;
  $event->{content} = JSON::encode_json($content);
  return $event;
}

sub _without {
  my ($hash, $key) = @_;
  my %copy = %{$hash};
  delete $copy{$key};
  return \%copy;
}

sub _set_path {
  my ($root, $path, $value) = @_;
  my $current = $root;
  for my $part (@{$path}[0 .. @{$path} - 2]) {
    $current = $current->{$part};
  }
  $current->{$path->[-1]} = $value;
  return;
}

sub _delete_path {
  my ($root, @path) = @_;
  my $current = $root;
  for my $part (@path[0 .. @path - 2]) {
    $current = $current->{$part};
  }
  delete $current->{$path[-1]};
  return;
}

sub _clone {
  my ($value) = @_;
  return JSON::decode_json(JSON::encode_json($value));
}

sub _load_json {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;
  return JSON::decode_json($json);
}

sub _spec_root {
  for my $dir (
    File::Spec->catdir($FindBin::Bin, '..', '..', 'spec'),
    File::Spec->catdir($FindBin::Bin, '..', '..', '..', 'spec'),
  ) {
    my $abs = File::Spec->rel2abs($dir);
    return $abs if -d $abs;
  }

  return File::Spec->rel2abs(File::Spec->catdir($FindBin::Bin, '..', '..', 'spec'));
}
