use strictures 2;
use Test2::V0;

use Overnet::Program::Permissions;
use Overnet::Program::Protocol;

sub error_from (&) {
  my ($code) = @_;
  my $error;
  eval { $code->(); 1 } or $error = $@;
  return $error;
}

subtest 'maps baseline service methods to permissions' => sub {
  is(Overnet::Program::Permissions->required_permission_for_method('storage.put'),
    'storage.write', 'storage.put requires storage.write');
  is(Overnet::Program::Permissions->required_permission_for_method('secrets.get'),
    'secrets.read', 'secrets.get requires secrets.read');
  is(Overnet::Program::Permissions->required_permission_for_method('overnet.emit_event'),
    'overnet.emit_event', 'overnet.emit_event requires overnet.emit_event');
};

subtest 'has_permission matches granted permissions exactly' => sub {
  ok(
    Overnet::Program::Permissions->has_permission(
      permissions => ['storage.write', 'config.read'],
      permission  => 'storage.write',
    ),
    'granted permission matches'
  );
  ok(
    !Overnet::Program::Permissions->has_permission(
      permissions => ['storage.read'],
      permission  => 'storage.write',
    ),
    'missing permission does not match'
  );
};

subtest 'assert_method_allowed permits a mapped method with its grant' => sub {
  ok(
    Overnet::Program::Permissions->assert_method_allowed(
      method      => 'storage.get',
      permissions => ['storage.read'],
    ),
    'mapped method with grant is allowed'
  );
};

subtest 'assert_method_allowed denies a mapped method without its grant' => sub {
  my $error = error_from {
    Overnet::Program::Permissions->assert_method_allowed(
      method      => 'storage.put',
      permissions => ['storage.read'],
    );
  };

  ref_ok $error, 'HASH', 'denial is a structured error';
  is $error->{code},                         'runtime.permission_denied', 'denial uses runtime.permission_denied';
  is $error->{details}{required_permission}, 'storage.write',             'denial names the required permission';
};

subtest 'assert_method_allowed fails closed for unmapped methods' => sub {
  my $error = error_from {
    Overnet::Program::Permissions->assert_method_allowed(
      method      => 'future.unmapped_service',
      permissions => [
        'config.read',        'secrets.read',
        'storage.read',       'storage.write',
        'events.append',      'events.read',
        'subscriptions.read', 'nostr.read',
        'nostr.write',        'timers.write',
        'adapters.use',       'overnet.emit_event',
        'overnet.emit_state', 'overnet.emit_private_message',
        'overnet.emit_capabilities',
      ],
    );
  };

  ref_ok $error, 'HASH', 'unmapped method is rejected, not dispatched';
  is $error->{code}, 'runtime.permission_denied', 'fail-closed rejection uses runtime.permission_denied';
  like $error->{message}, qr/no\ permission\ mapping/imx, 'rejection explains the missing mapping';
};

subtest 'every baseline service method has a permission mapping' => sub {
  my @methods = Overnet::Program::Protocol->service_request_methods;
  ok scalar(@methods) > 0, 'protocol enumerates baseline service methods';

  for my $method (@methods) {
    ok(defined Overnet::Program::Permissions->required_permission_for_method($method),
      "service method $method has a permission mapping");
  }
};

subtest 'permission helpers reject malformed inputs' => sub {
  like(
    error_from { Overnet::Program::Permissions->required_permission_for_method(q{}) },
    qr/method is required/,
    'empty method names croak',
  );
  like(
    error_from { Overnet::Program::Permissions->has_permission(permissions => 'junk', permission => 'x') },
    qr/permissions must be an array/,
    'non-array permission lists croak',
  );
  like(
    error_from { Overnet::Program::Permissions->has_permission(permissions => [], permission => q{}) },
    qr/permission is required/,
    'empty permission names croak',
  );
  ok(
    Overnet::Program::Permissions->has_permission(
      permissions => [undef, ['ref'], 'storage.write'],
      permission  => 'storage.write',
    ),
    'malformed granted entries are skipped while matching',
  );
  ok(
    !Overnet::Program::Permissions->has_permission(permission => 'storage.write'),
    'a missing permission list grants nothing',
  );
};

done_testing;
