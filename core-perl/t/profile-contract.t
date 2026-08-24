use strictures 2;
use Test2::V0;
use Test2::Tools::ClassicCompare qw(is);
use JSON           ();
use File::Basename qw(dirname);
use File::Spec;
use FindBin;

use Overnet::Core::ProfileContract;

my $spec_dir     = _spec_root();
my $fixtures_dir = File::Spec->catdir($spec_dir, 'fixtures', 'profile-contracts');

plan skip_all => "profile contract fixtures not found at $fixtures_dir"
  unless -d $fixtures_dir;

opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
my @fixture_files = sort grep {/\.json$/mx} readdir $dh;
closedir $dh;

for my $file (@fixture_files) {
  my $fixture  = _load_fixture(File::Spec->catfile($fixtures_dir, $file));
  my $input    = $fixture->{input};
  my $expected = $fixture->{expected};

  subtest "$file - $fixture->{description}" => sub {
    my @contracts = _contracts_from_input($input);

    if ( exists $expected->{profile_contract_valid}
      && exists $input->{contract}) {
      my $result = Overnet::Core::ProfileContract::validate_contract($input->{contract});
      _check_result($result, $expected->{profile_contract_valid}, $expected->{reason});
    }

    if (exists $expected->{profile_contract_set_valid}) {
      my $result = Overnet::Core::ProfileContract::validate_contract_set(\@contracts);
      _check_result($result, $expected->{profile_contract_set_valid}, $expected->{reason});
    }

    if (exists $expected->{profile_event_valid}) {
      my $result = Overnet::Core::ProfileContract::validate_profile_event(
        event     => $input->{event},
        contracts => \@contracts,
      );
      _check_result($result, $expected->{profile_event_valid}, $expected->{reason});
    }

    if (($expected->{profile_event_validation} // '') eq 'not_applicable') {
      my $result = Overnet::Core::ProfileContract::validate_profile_event(
        event    => $input->{event},
        contract => $input->{contract},
      );
      ok $result->{valid}, 'event remains valid without selected profile contract';
      is $result->{applicable}, 0, 'profile event validation is not applicable';
    }
  };
}

subtest 'contract set resolves dotted dependency profile targets through depends_on' => sub {
  my $identity = _contract(
    'com.example.identity',
    object_types => {
      'com.example.identity.profile' => _object_type(),
    },
    event_types => {
      'com.example.identity.profile.updated' => _event_type(
        object_type => 'com.example.identity.profile',
        kind        => 37800,
      ),
    },
  );

  my $chat = _contract(
    'com.example.chat',
    depends_on => [
      {
        profile => 'com.example.identity',
        version => '>=1.0.0 <2.0.0',
      },
    ],
    object_types => {
      'com.example.chat.channel' => _object_type(),
    },
    event_types => {
      'com.example.chat.message' => _event_type(
        object_type => 'com.example.chat.channel',
        references  => [
          {
            name               => 'sender_avatar',
            required           => JSON::false,
            tag                => 'p',
            target_object_type => 'com.example.identity.profile.avatar',
            target_event_type  => undef,
          },
        ],
      ),
    },
  );

  my $result = Overnet::Core::ProfileContract::validate_contract_set([$identity, $chat]);
  _check_result($result, 0, 'profile_contract_set.reference_target_missing');
};

subtest 'contract document enforces schema-level structure' => sub {
  my @cases = (
    [
      'contract_version must be numeric version 1',
      sub { $_[0]->{contract_version} = '1' },
      'profile_contract.invalid_contract_version',
    ],
    ['description must be non-empty', sub { $_[0]->{description} = '' }, 'profile_contract.invalid_description',],
    [
      'capabilities must be an array',
      sub { $_[0]->{capabilities} = 'schema.test.events' },
      'profile_contract.invalid_capabilities',
    ],
    [
      'capabilities must be unique',
      sub { push @{$_[0]->{capabilities}}, 'schema.test.events' },
      'profile_contract.duplicate_capability',
    ],
    [
      'capabilities must be profile-scoped names',
      sub { $_[0]->{capabilities}[0] = 'Events' },
      'profile_contract.invalid_capability',
    ],
    [
      'dependency entries must be objects',
      sub { $_[0]->{depends_on} = ['schema.test.dep'] },
      'profile_contract.invalid_dependency',
    ],
    [
      'dependency entries reject extra fields',
      sub {
        $_[0]->{depends_on} = [{profile => 'schema.dep', version => '1.0.0', extra => 1}];
      },
      'profile_contract.invalid_dependency',
    ],
    [
      'object_types must contain at least one definition',
      sub { $_[0]->{object_types} = {} },
      'profile_contract.invalid_object_types',
    ],
    [
      'object type definitions must be objects',
      sub { $_[0]->{object_types}{'schema.test.object'} = 'object' },
      'profile_contract.invalid_object_type',
    ],
    [
      'object type descriptions must be non-empty',
      sub {
        $_[0]->{object_types}{'schema.test.object'}{description} = '';
      },
      'profile_contract.invalid_object_type_description',
    ],
    [
      'object id rejects extra fields',
      sub { $_[0]->{object_types}{'schema.test.object'}{id}{extra} = 1 },
      'profile_contract.invalid_object_id',
    ],
    [
      'object id scheme must be known',
      sub {
        $_[0]->{object_types}{'schema.test.object'}{id}{scheme} = 'slug';
      },
      'profile_contract.invalid_object_id_scheme',
    ],
    [
      'object id pattern must be null or non-empty',
      sub {
        $_[0]->{object_types}{'schema.test.object'}{id}{pattern} = '';
      },
      'profile_contract.invalid_object_id_pattern',
    ],
    [
      'object id examples must be an array',
      sub {
        $_[0]->{object_types}{'schema.test.object'}{id}{examples} =
          'example';
      },
      'profile_contract.invalid_object_id_examples',
    ],
    [
      'object state derivation must be known',
      sub {
        $_[0]->{object_types}{'schema.test.object'}{state}{derivation} = 'latest';
      },
      'profile_contract.invalid_state_derivation',
    ],
    [
      'object state_event_type must be null or non-empty',
      sub {
        $_[0]->{object_types}{'schema.test.object'}{state}{state_event_type} = '';
      },
      'profile_contract.invalid_state_event_type',
    ],
    [
      'event_types must contain at least one definition',
      sub { $_[0]->{event_types} = {} },
      'profile_contract.invalid_event_types',
    ],
    [
      'event type definitions must be objects',
      sub { $_[0]->{event_types}{'schema.test.event'} = 'event' },
      'profile_contract.invalid_event_type',
    ],
    [
      'event type descriptions must be non-empty',
      sub { $_[0]->{event_types}{'schema.test.event'}{description} = '' },
      'profile_contract.invalid_event_type_description',
    ],
    [
      'event kind must be a JSON integer',
      sub { $_[0]->{event_types}{'schema.test.event'}{kind} = '7800' },
      'profile_contract.invalid_event_kind',
    ],
    [
      'event object_type must be a profile-scoped name',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{object_type} =
          'object';
      },
      'profile_contract.invalid_event_object_type',
    ],
    [
      'required_tags must use valid tag names',
      sub {
        push
          @{$_[0]->{event_types}{'schema.test.event'}{required_tags}},
          'bad tag';
      },
      'profile_contract.invalid_required_tag',
    ],
    [
      'references must be an array',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{references} = 'none';
      },
      'profile_contract.invalid_references',
    ],
    [
      'reference entries must be objects',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{references} =
          ['schema.test.object'];
      },
      'profile_contract.invalid_reference',
    ],
    [
      'reference entries reject extra fields',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{references} =
          [_reference(extra => 1)];
      },
      'profile_contract.invalid_reference',
    ],
    [
      'reference names must be non-empty',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{references} =
          [_reference(name => '')];
      },
      'profile_contract.invalid_reference_name',
    ],
    [
      'reference required must be a JSON boolean',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{references} =
          [_reference(required => 1)];
      },
      'profile_contract.invalid_reference_required',
    ],
    [
      'reference tags must use valid tag names',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{references} =
          [_reference(tag => 'bad tag')];
      },
      'profile_contract.invalid_reference_tag',
    ],
    [
      'reference target object type must be profile-scoped',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{references} =
          [_reference(target_object_type => 'object')];
      },
      'profile_contract.invalid_reference_target_object_type',
    ],
    [
      'state_effect must be known',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{state_effect} =
          'changes';
      },
      'profile_contract.invalid_state_effect',
    ],
    [
      'authorization must be an object',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{authorization} =
          'open';
      },
      'profile_contract.invalid_authorization',
    ],
    [
      'authorization model must be known',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{authorization}{model} = 'owner';
      },
      'profile_contract.invalid_authorization_model',
    ],
    [
      'authorization description must be non-empty',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{authorization}{description} = '';
      },
      'profile_contract.invalid_authorization_description',
    ],
    [
      'privacy must be known',
      sub {
        $_[0]->{event_types}{'schema.test.event'}{privacy} = 'private';
      },
      'profile_contract.invalid_privacy',
    ],
    [
      'fixtures must be an object',
      sub { $_[0]->{fixtures} = [] },
      'profile_contract.invalid_fixtures',
    ],
    [
      'fixture paths must be relative',
      sub { $_[0]->{fixtures}{valid} = ['/tmp/event.json'] },
      'profile_contract.invalid_fixture_path',
    ],
    [
      'fixture paths must be unique',
      sub {
        $_[0]->{fixtures}{valid} =
          ['fixtures/a.json', 'fixtures/a.json'];
      },
      'profile_contract.duplicate_fixture_path',
    ],
    [
      'extensions must be an object',
      sub { $_[0]->{extensions} = [] },
      'profile_contract.invalid_extensions',
    ],
  );

  for my $case (@cases) {
    my ($name, $mutate, $reason) = @{$case};
    subtest $name => sub {
      my $contract = _schema_contract();
      $mutate->($contract);
      my $result = Overnet::Core::ProfileContract::validate_contract($contract);
      _check_result($result, 0, $reason);
    };
  }
};

subtest 'profile event body schema uses JSON Schema draft semantics' => sub {
  my @cases = (
    [
      'maxLength rejects long strings',
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
      'pattern rejects non-matching strings',
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
      'minimum rejects small integers',
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
      'items rejects invalid array members',
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
      'anyOf rejects when no branch matches',
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
      'oneOf rejects when more than one branch matches',
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
      'not rejects forbidden matches',
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
  );

  for my $case (@cases) {
    my ($name, $body_schema, $body) = @{$case};
    subtest $name => sub {
      my $contract = _schema_contract();
      $contract->{event_types}{'schema.test.event'}{body_schema} =
        $body_schema;

      my $result = Overnet::Core::ProfileContract::validate_profile_event(
        event    => _event_for_body($body),
        contract => $contract,
      );

      _check_result($result, 0, 'profile_event.body_schema_mismatch');
    };
  }
};

subtest 'document and set structural guards' => sub {
  my $not_object = Overnet::Core::ProfileContract::validate_contract('junk');
  ok !$not_object->{valid}, 'non-object contracts are invalid';
  is $not_object->{errors}[0], 'profile_contract.document_not_object',
    'the non-object rejection is reported';

  my $not_array = Overnet::Core::ProfileContract::validate_contract_set('junk');
  ok !$not_array->{valid}, 'non-array contract sets are invalid';
  is $not_array->{errors}[0], 'profile_contract_set.contracts_not_array',
    'the non-array rejection is reported';

  my $broken_set = Overnet::Core::ProfileContract::validate_contract_set([{}]);
  ok !$broken_set->{valid}, 'sets containing invalid contracts are invalid';

  my $event_context = Overnet::Core::ProfileContract::validate_profile_event(
    event     => {kind => 7800, tags => [], content => '{}'},
    contracts => [{}],
  );
  ok !$event_context->{valid}, 'events cannot validate against an invalid contract set';
};

subtest 'event selection and wire decoding edge paths' => sub {
  my $chat = _contract(
    'com.example.chat',
    object_types => {
      'com.example.chat.channel' => _object_type(),
    },
    event_types => {
      'com.example.chat.message' => _event_type(object_type => 'com.example.chat.channel'),
    },
  );
  my $duplicate = _contract(
    'com.example.chatdup',
    object_types => {
      'com.example.chatdup.channel' => _object_type(),
    },
    event_types => {
      'com.example.chat.message' => _event_type(object_type => 'com.example.chatdup.channel'),
    },
  );

  my $event_for = sub {
    my (%args) = @_;
    return {
      kind    => 7800,
      tags    => [
        ['overnet_v', '0.1.0'],
        ['overnet_et', 'com.example.chat.message'],
        ['overnet_ot', $args{object_type} // 'com.example.chat.channel'],
        ['overnet_oid', 'chan-1'],
        ['v', '0.1.0'], ['t', 'com.example.chat.message'],
        ['o',  $args{object_type} // 'com.example.chat.channel'],
        ['d', 'chan-1'],
        ['short'],
      ],
      content => $args{content} // JSON::encode_json({body => {}}),
    };
  };

  my $ambiguous = Overnet::Core::ProfileContract::validate_profile_event(
    event     => $event_for->(),
    contracts => [$chat, $duplicate],
  );
  ok !$ambiguous->{valid}, 'an event type defined by two contracts is ambiguous';

  my $bad_json = Overnet::Core::ProfileContract::validate_profile_event(
    event     => $event_for->(content => 'not json'),
    contracts => [$chat],
  );
  ok !$bad_json->{valid}, 'events with undecodable content are invalid';

  {

    package t::profile_contract::EventObject;

    sub new { my ($class, %args) = @_; return bless {%args}, $class }
    sub kind    { my ($self) = @_; return $self->{kind} }
    sub tags    { my ($self) = @_; return $self->{tags} }
    sub content { my ($self) = @_; return $self->{content} }
  }
  my $wrapped = Overnet::Core::ProfileContract::validate_profile_event(
    event     => t::profile_contract::EventObject->new(%{$event_for->()}),
    contracts => [$chat],
  );
  ok $wrapped->{valid}, 'blessed events with accessors validate';

  ok Overnet::Core::ProfileContract::_is_json_number(5),      'integers are JSON numbers';
  ok Overnet::Core::ProfileContract::_is_json_number(5.5),    'floats are JSON numbers';
  ok !Overnet::Core::ProfileContract::_is_json_number('5'),   'strings are not JSON numbers';
  ok !Overnet::Core::ProfileContract::_is_json_number(undef), 'undef is not a JSON number';
  ok !Overnet::Core::ProfileContract::_is_json_number([]),    'references are not JSON numbers';
};

done_testing;


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

sub _check_result {
  my ($result, $valid, $reason) = @_;
  is $result->{valid}, $valid, "valid = $valid";
  if (!$valid && defined $reason) {
    my $found = grep { $_ eq $reason } @{$result->{errors}};
    ok $found, "errors contain $reason";
  }
  return;
}

sub _contracts_from_input {
  my ($input) = @_;
  my @contracts;

  push @contracts, $input->{contract}
    if exists $input->{contract} && defined $input->{contract};

  push @contracts, @{$input->{contracts}}
    if ref($input->{contracts}) eq 'ARRAY';

  push @contracts, _contract_from_fixture($input->{contract_fixture})
    if defined $input->{contract_fixture};

  if (ref($input->{contract_fixtures}) eq 'ARRAY') {
    push @contracts, map { _contract_from_fixture($_) } @{$input->{contract_fixtures}};
  }

  return @contracts;
}

sub _contract_from_fixture {
  my ($path) = @_;
  my $fixture = _load_fixture(File::Spec->catfile($spec_dir, $path));
  return $fixture->{input}{contract};
}

sub _load_fixture {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;
  return JSON::decode_json($json);
}

sub _contract {
  my ($profile, %extra) = @_;
  return {
    contract_version => 1,
    profile          => $profile,
    profile_version  => '1.0.0',
    status           => 'draft',
    description      => "$profile contract",
    capabilities     => ["$profile.events"],
    object_types     => $extra{object_types},
    event_types      => $extra{event_types},
    fixtures         => {
      valid   => [],
      invalid => [],
    },
    extensions => {},
    (
      exists $extra{depends_on}
      ? (depends_on => $extra{depends_on})
      : ()
    ),
  };
}

sub _schema_contract {
  return _contract(
    'schema.test',
    object_types => {
      'schema.test.object' => _object_type(),
    },
    event_types => {
      'schema.test.event' => _event_type(
        object_type => 'schema.test.object',
      ),
    },
  );
}

sub _object_type {
  return {
    description => 'Object.',
    id          => {
      scheme   => 'profile-defined',
      pattern  => undef,
      examples => [],
    },
    state => {
      derivation       => 'event-log',
      state_event_type => undef,
    },
    extensions => {},
  };
}

sub _reference {
  my (%extra) = @_;
  return {
    name               => exists $extra{name}               ? $extra{name} : 'related',
    required           => exists $extra{required}           ? $extra{required} : JSON::false,
    tag                => exists $extra{tag}                ? $extra{tag} : 'e',
    target_object_type => exists $extra{target_object_type} ? $extra{target_object_type}
    : 'schema.test.object',
    target_event_type => exists $extra{target_event_type} ? $extra{target_event_type}
    : undef,
    (exists $extra{extra} ? (extra => $extra{extra}) : ()),
  };
}

sub _event_for_body {
  my ($body) = @_;
  return {
    kind => 7800,
    tags => [
      [overnet_v   => '1'],
      [overnet_et  => 'schema.test.event'],
      [overnet_ot  => 'schema.test.object'],
      [overnet_oid => 'object-1'],
      [v           => '1'],
      [t           => 'schema.test.event'],
      [o           => 'schema.test.object'],
      [d           => 'object-1'],
    ],
    content => JSON::encode_json(
      {
        provenance => {
          type => 'native',
        },
        body => $body,
      }
    ),
  };
}

sub _event_type {
  my (%extra) = @_;
  return {
    description   => 'Event.',
    kind          => $extra{kind} || 7800,
    object_type   => $extra{object_type},
    required_tags => [qw(overnet_v overnet_et overnet_ot overnet_oid v t o d),],
    body_schema   => {
      type => 'object',
    },
    references    => $extra{references} || [],
    state_effect  => 'creates',
    authorization => {
      model       => 'open',
      description => 'Open.',
    },
    privacy    => 'public',
    extensions => {},
  };
}
