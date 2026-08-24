package Overnet::Program::Permissions;

use strictures 2;
use Carp qw(croak);

our $VERSION = '0.001';

my %METHOD_PERMISSIONS = (
  'config.get'                       => 'config.read',
  'config.describe'                  => 'config.read',
  'secrets.get'                      => 'secrets.read',
  'storage.put'                      => 'storage.write',
  'storage.get'                      => 'storage.read',
  'storage.delete'                   => 'storage.write',
  'storage.list'                     => 'storage.read',
  'events.append'                    => 'events.append',
  'events.read'                      => 'events.read',
  'subscriptions.open'               => 'subscriptions.read',
  'subscriptions.close'              => 'subscriptions.read',
  'nostr.publish_event'              => 'nostr.write',
  'nostr.query_events'               => 'nostr.read',
  'nostr.open_subscription'          => 'nostr.read',
  'nostr.read_subscription_snapshot' => 'nostr.read',
  'nostr.close_subscription'         => 'nostr.read',
  'timers.schedule'                  => 'timers.write',
  'timers.cancel'                    => 'timers.write',
  'adapters.open_session'            => 'adapters.use',
  'adapters.map_input'               => 'adapters.use',
  'adapters.derive'                  => 'adapters.use',
  'adapters.close_session'           => 'adapters.use',
  'overnet.emit_event'               => 'overnet.emit_event',
  'overnet.emit_state'               => 'overnet.emit_state',
  'overnet.emit_private_message'     => 'overnet.emit_private_message',
  'overnet.emit_capabilities'        => 'overnet.emit_capabilities',
);

sub required_permission_for_method {
  my ($class, $method) = @_;

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }

  return $METHOD_PERMISSIONS{$method};
}

sub has_permission {
  my ($class, %args) = @_;

  my $permissions = $args{permissions};
  my $permission  = $args{permission};

  if (defined $permissions && ref($permissions) ne 'ARRAY') {
    croak "permissions must be an array\n";
  }
  if (!(defined $permission && !ref($permission) && length($permission))) {
    croak "permission is required\n";
  }

  $permissions ||= [];
  for my $granted (@{$permissions}) {
    if (!(defined $granted && !ref($granted))) {
      next;
    }
    if ($granted eq $permission) {
      return 1;
    }
  }

  return 0;
}

sub assert_method_allowed {
  my ($class, %args) = @_;

  my $method      = $args{method};
  my $permissions = $args{permissions};

  my $required_permission = $class->required_permission_for_method($method);
  if (!(defined $required_permission)) {
    CORE::die {
      code    => 'runtime.permission_denied',
      message => "No permission mapping for method $method; failing closed",
      details => {
        method => $method,
      },
    };
  }

  if (
    !$class->has_permission(
      permissions => $permissions,
      permission  => $required_permission,
    )
  ) {
    CORE::die {
      code    => 'runtime.permission_denied',
      message => "Permission denied for method $method",
      details => {
        method              => $method,
        required_permission => $required_permission,
      },
    };
  }

  return 1;
}

1;

=head1 NAME

Overnet::Program::Permissions - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Permissions;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 required_permission_for_method

Public API entry point.

=head2 has_permission

Public API entry point.

=head2 assert_method_allowed

Public API entry point. Permission enforcement fails closed: a method with
no permission mapping is rejected with C<runtime.permission_denied> rather
than dispatched without enforcement.

=head1 DIAGNOSTICS

This module reports errors through normal Perl exceptions or structured return values.

=head1 CONFIGURATION AND ENVIRONMENT

No module-specific environment configuration is required.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

No known bugs are documented.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
