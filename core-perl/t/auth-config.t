use strictures 2;

use FindBin;
use File::Spec;
use File::Temp qw(tempdir);
use JSON       ();
use Test::More;

use Overnet::Auth::Config;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

subtest 'load_file returns endpoint and agent config from JSON' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');
  my $state_file  = File::Spec->catfile($dir, 'auth-state.json');

  _write_json(
    $config_file,
    {
      daemon => {
        endpoint   => $socket_path,
        state_file => $state_file,
      },
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
    },
  );

  my $config = Overnet::Auth::Config->load_file(path => $config_file);

  is $config->endpoint,   $socket_path, 'config exposes the daemon endpoint';
  is $config->state_file, $state_file,  'config exposes the daemon state file';
  is_deeply $config->agent_args,
    {
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
    service_pins                 => {},
    sessions                     => [],
    allow_unattended_autoapprove => 0,
    },
    'config exposes the agent constructor args and defaults to fail-closed approval';
};

subtest 'daemon accessors return the configured daemon values' => sub {
  my $config = Overnet::Auth::Config->new(
    config => {
      daemon => {
        endpoint    => '/run/overnet-auth.sock',
        socket_mode => '0600',
        state_file  => '/var/lib/overnet/auth-state.json',
      },
    },
  );

  is $config->endpoint,    '/run/overnet-auth.sock',            'endpoint reflects the daemon section';
  is $config->socket_mode, '0600',                              'socket_mode reflects the daemon section';
  is $config->state_file,  '/var/lib/overnet/auth-state.json',  'state_file reflects the daemon section';
};

subtest 'agent_args carries an explicit unattended-autoapprove opt-in from config' => sub {
  my $config = Overnet::Auth::Config->new(
    config => {
      allow_unattended_autoapprove => JSON::true,
      identities                   => [
        {
          identity_id     => 'default',
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => $fixture_pubkey,
          },
        },
      ],
    },
  );

  is $config->agent_args->{allow_unattended_autoapprove}, 1,
    'a truthy config opt-in becomes a normalized boolean in agent_args';

  my $default = Overnet::Auth::Config->new(config => {});
  is $default->agent_args->{allow_unattended_autoapprove}, 0,
    'an absent opt-in normalizes to fail-closed';

  my $off = Overnet::Auth::Config->new(config => {allow_unattended_autoapprove => JSON::false},);
  is $off->agent_args->{allow_unattended_autoapprove}, 0,
    'an explicit false opt-in stays fail-closed';
};

subtest 'config rejects a non-boolean unattended-autoapprove setting' => sub {
  for my $bad ('false', 1, {}) {
    my $error = eval {
      Overnet::Auth::Config->new(config => {allow_unattended_autoapprove => $bad},);
      1;
    } ? undef : $@;

    like $error, qr/allow_unattended_autoapprove\ must\ be\ a\ boolean/mx,
      'a non-boolean opt-in value is rejected so a malformed setting cannot silently enable auto-approval';
  }
};

subtest 'agent_args can combine static identities with separately loaded mutable state' => sub {
  my $config = Overnet::Auth::Config->new(
    config => {
      daemon => {
        endpoint   => '/tmp/overnet-auth.sock',
        state_file => '/tmp/overnet-auth-state.json',
      },
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
    },
  );

  my $agent_args = $config->agent_args(
    state => {
      policies => [
        {
          policy_id   => 'policy-1',
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => ['irc://irc.example.test/overnet'],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
      service_pins => {
        'wss://relay.example.test/auth' => {
          scheme => 'nostr.pubkey',
          value  => ('1' x 64),
        },
      },
      sessions => [
        {
          session_handle => {id => 'sess-1'},
          identity_id    => 'default',
          program_id     => 'irc.bridge',
          service        => {
            locators => ['wss://relay.example.test/auth'],
          },
          scope     => 'irc://irc.example.test/overnet',
          action    => 'session.authenticate',
          renewable => 1,
          artifacts => [],
        },
      ],
    },
  );

  is $agent_args->{identities}[0]{identity_id}, 'default',  'static identities remain in config';
  is $agent_args->{policies}[0]{policy_id},     'policy-1', 'mutable policies can come from separate state';
  is $agent_args->{service_pins}{'wss://relay.example.test/auth'}{value},
    ('1' x 64),
    'mutable service pins can come from separate state';
  is $agent_args->{sessions}[0]{session_handle}{id}, 'sess-1', 'mutable sessions can come from separate state';
};

subtest 'load_file rejects non-object JSON configs' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  _write_raw($config_file, qq{["not","an","object"]\n});

  my $error = eval {
    Overnet::Auth::Config->load_file(path => $config_file);
    1;
  } ? undef : $@;

  like $error, qr/auth\ config\ must\ decode\ to\ an\ object/mx, 'non-object auth config files are rejected';
};

subtest 'empty auth config remains valid without a daemon section' => sub {
  my $config = Overnet::Auth::Config->new(config => {});

  ok !defined($config->endpoint),   'empty config has no endpoint';
  ok !defined($config->state_file), 'empty config has no state file';
  is_deeply $config->mutable_state,
    {
    policies     => [],
    service_pins => {},
    sessions     => [],
    },
    'empty config still exposes empty mutable state';
};

subtest 'constructor and section validation reject malformed configs' => sub {
  my $build_error = sub {
    my (@args) = @_;
    return eval { Overnet::Auth::Config->new(@args); 1 } ? undef : $@;
  };

  ok !defined $build_error->({config => {}}), 'a single hashref constructor argument is accepted';
  like $build_error->('odd'), qr/constructor\ arguments\ must\ be\ a\ hash/mx,
    'odd argument lists are rejected';
  like $build_error->(config => 'nope'), qr/auth\ config\ must\ be\ an\ object/mx,
    'non-object configs are rejected';
  like $build_error->(config => {daemon => []}),
    qr/daemon\ section\ must\ be\ an\ object/mx, 'non-object daemon sections are rejected';
  like $build_error->(config => {daemon => {state_file => q{}}}),
    qr/daemon\.state_file\ must\ be\ a\ string/mx, 'empty state_file values are rejected';
  like $build_error->(config => {identities => {}}),
    qr/identities\ must\ be\ an\ array/mx, 'non-array identities are rejected';
  like $build_error->(config => {policies => {}}),
    qr/policies\ must\ be\ an\ array/mx, 'non-array policies are rejected';
  like $build_error->(config => {service_pins => []}),
    qr/service_pins\ must\ be\ an\ object/mx, 'non-object service pins are rejected';
  like $build_error->(config => {sessions => {}}),
    qr/sessions\ must\ be\ an\ array/mx, 'non-array sessions are rejected';
  like $build_error->(config => {allow_unattended_autoapprove => 'yes'}),
    qr/allow_unattended_autoapprove\ must\ be\ a\ boolean/mx, 'non-boolean autoapprove is rejected';
};

subtest 'load_file rejects unusable paths and content' => sub {
  my $load_error = sub {
    my (%args) = @_;
    return eval { Overnet::Auth::Config->load_file(%args); 1 } ? undef : $@;
  };

  like $load_error->(), qr/path\ is\ required/mx, 'a path is required';
  like $load_error->(path => q{}), qr/path\ is\ required/mx,
    'an empty-string path is rejected, not opened as an empty filename';
  like $load_error->(path => ['not', 'a', 'path']), qr/path\ is\ required/mx,
    'a reference path is rejected instead of being treated as a filename';
  like $load_error->(path => File::Spec->catfile(tempdir(CLEANUP => 1), 'missing.json')),
    qr/open\ .*missing\.json\ failed/mx, 'missing files fail to open';

  my $dir      = tempdir(CLEANUP => 1);
  my $bad_json = File::Spec->catfile($dir, 'bad.json');
  _write_raw($bad_json, 'not json');
  like $load_error->(path => $bad_json), qr/is\ not\ valid\ JSON/mx, 'invalid JSON is rejected';

  my $not_object = File::Spec->catfile($dir, 'array.json');
  _write_raw($not_object, '[1,2]');
  like $load_error->(path => $not_object),
    qr/auth\ config\ must\ decode\ to\ an\ object/mx, 'non-object JSON is rejected';
};

subtest 'agent_args validates injected mutable state and clones values' => sub {
  my $config = Overnet::Auth::Config->new(
    config => {
      identities                   => [{identity_id => 'default', extras => [undef, 'kept']}],
      allow_unattended_autoapprove => JSON::true,
    },
  );

  my $state_error = sub {
    my ($state) = @_;
    return eval { $config->agent_args(state => $state); 1 } ? undef : $@;
  };
  like $state_error->('junk'), qr/mutable\ state\ must\ be\ an\ object/mx,
    'non-object states are rejected';
  like $state_error->({policies => {}}), qr/state\ policies\ must\ be\ an\ array/mx,
    'non-array state policies are rejected';
  like $state_error->({service_pins => []}), qr/state\ service_pins\ must\ be\ an\ object/mx,
    'non-object state service pins are rejected';
  like $state_error->({sessions => {}}), qr/state\ sessions\ must\ be\ an\ array/mx,
    'non-array state sessions are rejected';

  my $args = $config->agent_args(state => {policies => [{policy_id => 'p1'}]});
  is $args->{allow_unattended_autoapprove}, 1, 'boolean autoapprove flags become plain flags';
  is_deeply $args->{policies}, [{policy_id => 'p1'}], 'injected state policies are cloned into agent args';
  is_deeply $args->{identities}[0]{extras}, [undef, 'kept'],
    'undef entries are preserved in cloned arrays';

  my $default_args = $config->agent_args;
  is_deeply $default_args->{policies}, [], 'agent args default to the config mutable state';
};

subtest 'JSON null values anywhere in the config survive cloning' => sub {
  my $config = eval {
    Overnet::Auth::Config->new(
      config => {
        description => undef,
        daemon      => {endpoint => '/tmp/auth.sock', socket_mode => undef},
        identities  => [{identity_id => 'default', display_name => undef}],
        sessions    => [{session_handle => {id => 'sess-1'}, service => undef}],
      },
    );
  };
  is $@, '', 'a config containing nulls constructs without dying';
  is_deeply $config->identities, [{identity_id => 'default', display_name => undef}],
    'null identity fields are preserved without shifting hash keys';
  is_deeply $config->mutable_state->{sessions},
    [{session_handle => {id => 'sess-1'}, service => undef}],
    'null session fields are preserved without shifting hash keys';
  is $config->endpoint, '/tmp/auth.sock', 'sibling keys of a null value keep their values';

  my $dir       = tempdir(CLEANUP => 1);
  my $null_file = File::Spec->catfile($dir, 'null.json');
  _write_raw($null_file, '{"daemon":{"endpoint":"/tmp/auth.sock"},"note":null}');
  my $loaded = eval { Overnet::Auth::Config->load_file(path => $null_file) };
  is $@, '', 'a config file containing a JSON null loads without dying';
  is $loaded->endpoint, '/tmp/auth.sock', 'the loaded config still exposes its endpoint';
};

done_testing;

sub _write_json {
  my ($path, $value) = @_;
  _write_raw($path, JSON::encode_json($value));
  return;
}

sub _write_raw {
  my ($path, $content) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} $content
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
  return;
}
