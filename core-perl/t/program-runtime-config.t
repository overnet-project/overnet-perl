use strictures 2;
use Test::More;

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

subtest 'services expose effective config and description' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    config => {
      mode   => 'test',
      nested => {enabled => 1},
    },
    config_description => {
      schema => {
        type       => 'object',
        properties => {
          mode => {type => 'string'},
        },
      },
      schema_ref => 'overnet://schema/program-config',
      version    => '2026-04-13',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $get = $services->dispatch_request('config.get', {}, permissions => ['config.read'],);
  is_deeply(
    $get,
    {
      config => {
        mode   => 'test',
        nested => {enabled => 1},
      },
    },
    'config.get returns effective config',
  );

  my $describe = $services->dispatch_request('config.describe', {}, permissions => ['config.read'],);
  is_deeply(
    $describe,
    {
      schema => {
        type       => 'object',
        properties => {
          mode => {type => 'string'},
        },
      },
      schema_ref => 'overnet://schema/program-config',
      version    => '2026-04-13',
    },
    'config.describe returns runtime-known config metadata',
  );
};

subtest 'config service results are isolated from caller mutation' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    config => {
      mode   => 'stable',
      nested => {enabled => 1},
    },
    config_description => {
      schema => {
        type => 'object',
      },
      version => '1.0',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $config = $services->dispatch_request('config.get', {}, permissions => ['config.read'],);
  $config->{config}{mode} = 'mutated';
  $config->{config}{nested}{enabled} = 0;

  my $config_again = $services->dispatch_request('config.get', {}, permissions => ['config.read'],);
  is $config_again->{config}{mode},            'stable', 'config.get returns a cloned config object';
  is $config_again->{config}{nested}{enabled}, 1,        'nested config data is isolated from mutation';

  my $describe = $services->dispatch_request('config.describe', {}, permissions => ['config.read'],);
  $describe->{schema}{type} = 'array';
  $describe->{version} = 'mutated';

  my $describe_again = $services->dispatch_request('config.describe', {}, permissions => ['config.read'],);
  is $describe_again->{schema}{type}, 'object', 'config.describe returns cloned schema metadata';
  is $describe_again->{version},      '1.0',    'config.describe result is isolated from mutation';
};

subtest 'services enforce config.read permission' => sub {
  my $runtime  = Overnet::Program::Runtime->new(config => {mode => 'test'},);
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request('config.get', {}, permissions => [],);
    1;
  } or $error = $@;
  is ref($error),                            'HASH',                      'config.get permission error is structured';
  is $error->{code},                         'runtime.permission_denied', 'config.get requires config.read';
  is $error->{details}{required_permission}, 'config.read',               'config.get reports required permission';

  $error = undef;
  eval {
    $services->dispatch_request('config.describe', {}, permissions => [],);
    1;
  } or $error = $@;
  is ref($error),    'HASH',                                'config.describe permission error is structured';
  is $error->{code}, 'runtime.permission_denied',           'config.describe requires config.read';
  is $error->{details}{required_permission}, 'config.read', 'config.describe reports required permission';
};

subtest 'runtime validates config description constructor params' => sub {
  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          config_description => {
            schema_ref => {},
          },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/config_description\.schema_ref\ must\ be\ a\ non-empty\ string/mx,
    'runtime rejects invalid config description metadata',
  );
};

subtest 'instance defaults runtime.init config from runtime and serves config.get through protocol' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    config => {
      mode        => 'production',
      adapter_ref => 'irc.default',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['config.read'],
    service_handler             => $services,
  );

  my $hello = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'config.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  is_deeply(
    $hello->{send}{params}{config},
    {
      mode        => 'production',
      adapter_ref => 'irc.default',
    },
    'runtime.init uses runtime config by default',
  );

  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $hello->{send}{id}
    )
  );
  $instance->process_program_message(Overnet::Program::Protocol::build_program_ready());

  my $response = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'cfg-1',
      method => 'config.get',
      params => {},
    )
  );

  ok $response->{send}{ok}, 'config.get succeeds through protocol';
  is_deeply(
    $response->{send}{result},
    {
      config => {
        mode        => 'production',
        adapter_ref => 'irc.default',
      },
    },
    'config.get returns the same runtime config through protocol',
  );
};

done_testing;
