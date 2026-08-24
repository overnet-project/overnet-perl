package Overnet::Program::SecretProvider;

use strictures 2;
use Moo;
use Carp        qw(croak);
use English     qw(-no_match_vars);
use JSON        ();
use List::Util  qw(any);
use Time::HiRes qw(time);

our $VERSION = '0.001';

has now_cb               => (is => 'ro', reader   => '_now_cb');
has random_bytes_cb      => (is => 'ro', reader   => '_random_bytes_cb');
has secrets              => (is => 'rw', accessor => '_secrets');
has secret_policies      => (is => 'rw', accessor => '_secret_policies');
has secret_handle_ttl_ms => (is => 'ro', reader   => '_secret_handle_ttl_ms');
has secret_handles       => (is => 'rw', accessor => '_secret_handles');
has audit_events         => (is => 'rw', accessor => '_audit_events');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $now_cb          = $args{now_cb} || sub { int(time() * 1000) };
  my $random_bytes_cb = $args{random_bytes_cb};
  my $secrets         = exists $args{secrets} ? $args{secrets} : {};
  my $secret_policies =
    exists $args{secret_policies} ? $args{secret_policies} : {};
  my $secret_handle_ttl_ms =
    exists $args{secret_handle_ttl_ms}
    ? $args{secret_handle_ttl_ms}
    : 300_000;

  if (!(ref($now_cb) eq 'CODE')) {
    croak "now_cb must be a code reference\n";
  }
  if (defined $random_bytes_cb && ref($random_bytes_cb) ne 'CODE') {
    croak "random_bytes_cb must be a code reference\n";
  }
  if (!(ref($secrets) eq 'HASH')) {
    croak "secrets must be an object\n";
  }
  if (!(ref($secret_policies) eq 'HASH')) {
    croak "secret_policies must be an object\n";
  }
  if (!(defined $secret_handle_ttl_ms && !ref($secret_handle_ttl_ms) && $secret_handle_ttl_ms =~ /\A[1-9]\d*\z/mxs)) {
    croak "secret_handle_ttl_ms must be a positive integer\n";
  }

  _validate_secrets($secrets);
  _validate_secret_policies($secret_policies);

  return {
    now_cb               => $now_cb,
    random_bytes_cb      => $random_bytes_cb,
    secrets              => _clone_json($secrets),
    secret_policies      => _clone_json($secret_policies),
    secret_handle_ttl_ms => 0 + $secret_handle_ttl_ms,
    secret_handles       => {},
    audit_events         => [],
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub has_secret {
  my ($self, %args) = @_;
  my $name = _require_string_arg(name => $args{name});
  return exists $self->{secrets}{$name} ? 1 : 0;
}

sub audit_events {
  my ($self) = @_;
  return _clone_json($self->{audit_events});
}

sub issue_secret_handle {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $name       = _require_string_arg(name       => $args{name});
  my $program_id = _optional_string_arg(program_id => $args{program_id});
  my $purpose    = _optional_string_arg(purpose    => $args{purpose});

  $self->_expire_secret_handles;

  if (
    !(
      $self->_may_issue_secret(
        name       => $name,
        session_id => $session_id,
        program_id => $program_id,
        purpose    => $purpose,
      )
    )
  ) {
    $self->_audit(
      action     => 'secret_handle.issue',
      outcome    => 'denied',
      name       => $name,
      session_id => $session_id,
      (defined $program_id ? (program_id => $program_id) : ()),
      (defined $purpose    ? (purpose    => $purpose)    : ()),
      reason => 'secret_unavailable',
    );
    _invalid_secret_access(param => 'name');
  }

  my $handle_id     = $self->_generate_secret_handle_id;
  my $expires_at_ms = $self->_now_ms + $self->{secret_handle_ttl_ms};
  $self->{secret_handles}{$handle_id} = {
    session_id    => $session_id,
    name          => $name,
    expires_at_ms => $expires_at_ms,
    (defined $program_id ? (program_id => $program_id) : ()),
    (defined $purpose    ? (purpose    => $purpose)    : ()),
  };

  my $result = {
    name          => $name,
    secret_handle => {
      id         => $handle_id,
      expires_at => _ms_to_unix_seconds($expires_at_ms),
    },
  };

  $self->_audit(
    action     => 'secret_handle.issue',
    outcome    => 'issued',
    name       => $name,
    session_id => $session_id,
    (defined $program_id ? (program_id => $program_id) : ()),
    (defined $purpose    ? (purpose    => $purpose)    : ()),
    expires_at => $result->{secret_handle}{expires_at},
  );

  return $result;
}

sub resolve_secret_handle {
  my ($self, %args) = @_;
  my $session_id  = _require_string_arg(session_id => $args{session_id});
  my $handle_id   = _require_string_arg(handle_id  => $args{handle_id});
  my $program_id  = _optional_string_arg(program_id  => $args{program_id});
  my $purpose     = _optional_string_arg(purpose     => $args{purpose});
  my $method      = _optional_string_arg(method      => $args{method});
  my $adapter_id  = _optional_string_arg(adapter_id  => $args{adapter_id});
  my $secret_slot = _optional_string_arg(secret_slot => $args{secret_slot});
  my $error_param = _optional_string_arg(error_param => $args{error_param});

  $self->_expire_secret_handles;

  my $handle = $self->{secret_handles}{$handle_id};
  if (!(defined $handle)) {
    $self->_audit(
      action     => 'secret_handle.resolve',
      outcome    => 'denied',
      session_id => $session_id,
      (defined $program_id  ? (program_id  => $program_id)  : ()),
      (defined $purpose     ? (purpose     => $purpose)     : ()),
      (defined $method      ? (method      => $method)      : ()),
      (defined $adapter_id  ? (adapter_id  => $adapter_id)  : ()),
      (defined $secret_slot ? (secret_slot => $secret_slot) : ()),
      reason => 'secret_handle_unavailable',
    );
    _invalid_secret_access(param => $error_param);
  }

  my $name = $handle->{name};

  if (
    !(
      $self->_may_resolve_secret_handle(
        handle      => $handle,
        session_id  => $session_id,
        program_id  => $program_id,
        purpose     => $purpose,
        method      => $method,
        adapter_id  => $adapter_id,
        secret_slot => $secret_slot,
      )
    )
  ) {
    $self->_audit(
      action     => 'secret_handle.resolve',
      outcome    => 'denied',
      name       => $name,
      session_id => $session_id,
      (defined $program_id  ? (program_id  => $program_id)  : ()),
      (defined $purpose     ? (purpose     => $purpose)     : ()),
      (defined $method      ? (method      => $method)      : ()),
      (defined $adapter_id  ? (adapter_id  => $adapter_id)  : ()),
      (defined $secret_slot ? (secret_slot => $secret_slot) : ()),
      reason => 'secret_handle_unavailable',
    );
    _invalid_secret_access(param => $error_param);
  }

  my $resolved = {
    name  => $name,
    value => $self->{secrets}{$name},
  };

  $self->_audit(
    action     => 'secret_handle.resolve',
    outcome    => 'resolved',
    name       => $name,
    session_id => $session_id,
    (defined $program_id  ? (program_id  => $program_id)  : ()),
    (defined $purpose     ? (purpose     => $purpose)     : ()),
    (defined $method      ? (method      => $method)      : ()),
    (defined $adapter_id  ? (adapter_id  => $adapter_id)  : ()),
    (defined $secret_slot ? (secret_slot => $secret_slot) : ()),
  );

  return $resolved;
}

sub revoke_secret_handle {
  my ($self, %args) = @_;
  my $handle_id = _require_string_arg(handle_id => $args{handle_id});

  my $handle = delete $self->{secret_handles}{$handle_id};
  if (!(defined $handle)) {
    return 0;
  }

  $self->_audit(
    action     => 'secret_handle.revoke',
    outcome    => 'revoked',
    name       => $handle->{name},
    session_id => $handle->{session_id},
    (
      defined $handle->{program_id}
      ? (program_id => $handle->{program_id})
      : ()
    ),
    reason => 'explicit_revoke',
  );

  return 1;
}

sub revoke_secret_handles_for_session {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $count      = 0;

  for my $handle_id (keys %{$self->{secret_handles}}) {
    my $handle = $self->{secret_handles}{$handle_id};
    if (!(defined $handle)) {
      next;
    }
    if (!(($handle->{session_id} || q{}) eq $session_id)) {
      next;
    }

    delete $self->{secret_handles}{$handle_id};
    $count++;
  }

  $self->_audit(
    action     => 'secret_handle.revoke_session',
    outcome    => 'revoked',
    session_id => $session_id,
    count      => $count,
  );

  return $count;
}

sub rotate_secret {
  my ($self, %args) = @_;
  my $name    = _require_string_arg(name  => $args{name});
  my $value   = _require_string_arg(value => $args{value});
  my $revoked = 0;

  for my $handle_id (keys %{$self->{secret_handles}}) {
    my $handle = $self->{secret_handles}{$handle_id};
    if (!(defined $handle)) {
      next;
    }
    if (!(($handle->{name} || q{}) eq $name)) {
      next;
    }

    delete $self->{secret_handles}{$handle_id};
    $revoked++;
  }

  $self->{secrets}{$name} = $value;
  $self->_audit(
    action  => 'secret.rotate',
    outcome => 'rotated',
    name    => $name,
    revoked => $revoked,
  );

  return {
    name    => $name,
    revoked => $revoked,
  };
}

sub _may_issue_secret {
  my ($self, %args) = @_;
  my $name = $args{name};
  if (!(exists $self->{secrets}{$name})) {
    return 0;
  }

  my $policy = $self->{secret_policies}{$name} || {};
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_session_ids},
        value   => $args{session_id},
      )
    )
  ) {
    return 0;
  }
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_program_ids},
        value   => $args{program_id},
      )
    )
  ) {
    return 0;
  }
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_purposes},
        value   => $args{purpose},
      )
    )
  ) {
    return 0;
  }

  return 1;
}

sub _may_resolve_secret_handle {
  my ($self, %args) = @_;
  my $handle = $args{handle};
  my $name   = $handle->{name};
  if (!(exists $self->{secrets}{$name})) {
    return 0;
  }
  if (!(($handle->{session_id} || q{}) eq ($args{session_id} || q{}))) {
    return 0;
  }
  if (
    defined $handle->{program_id}
    && (!defined $args{program_id}
      || $handle->{program_id} ne $args{program_id})
  ) {
    return 0;
  }
  if (defined $handle->{purpose}
    && (!defined $args{purpose} || $handle->{purpose} ne $args{purpose})) {
    return 0;
  }

  my $policy = $self->{secret_policies}{$name} || {};
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_session_ids},
        value   => $args{session_id},
      )
    )
  ) {
    return 0;
  }
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_program_ids},
        value   => $args{program_id},
      )
    )
  ) {
    return 0;
  }
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_purposes},
        value   => $args{purpose},
      )
    )
  ) {
    return 0;
  }
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_methods},
        value   => $args{method},
      )
    )
  ) {
    return 0;
  }
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_adapter_ids},
        value   => $args{adapter_id},
      )
    )
  ) {
    return 0;
  }
  if (
    !(
      $self->_matches_allowed_list(
        allowed => $policy->{allowed_secret_slots},
        value   => $args{secret_slot},
      )
    )
  ) {
    return 0;
  }

  return 1;
}

sub _matches_allowed_list {
  my ($self, %args) = @_;
  my $allowed = $args{allowed};
  if (!(defined $allowed)) {
    return 1;
  }

  if (!(ref($allowed) eq 'ARRAY' && @{$allowed})) {
    return 0;
  }
  if (!(defined $args{value})) {
    return 0;
  }

  for my $candidate (@{$allowed}) {
    if ($candidate eq $args{value}) {
      return 1;
    }
  }

  return 0;
}

sub _audit {
  my ($self, %event) = @_;
  if (!(exists $event{at})) {
    $event{at} = _ms_to_unix_seconds($self->_now_ms);
  }
  push @{$self->{audit_events}}, _clone_json(\%event);
  return 1;
}

sub _now_ms {
  my ($self) = @_;
  my $now = $self->{now_cb}->();

  if (!(defined $now && !ref($now) && $now =~ /\A-?\d+\z/mxs)) {
    croak "now_cb must return an integer millisecond timestamp\n";
  }

  return 0 + $now;
}

sub _expire_secret_handles {
  my ($self) = @_;
  my $now_ms = $self->_now_ms;

  for my $handle_id (keys %{$self->{secret_handles}}) {
    my $handle = $self->{secret_handles}{$handle_id};
    if (!(defined $handle)) {
      next;
    }
    if (($handle->{expires_at_ms} || 0) <= $now_ms) {
      delete $self->{secret_handles}{$handle_id};
    }
  }

  return 1;
}

sub _generate_secret_handle_id {
  my ($self) = @_;

  for (1 .. 10) {
    my $bytes = eval { $self->_secure_random_bytes(32) };
    if (!$EVAL_ERROR && defined $bytes) {
      my $id = 'sh_' . unpack('H*', $bytes);
      if (exists $self->{secret_handles}{$id}) {
        next;
      }
      return $id;
    }
  }

  CORE::die {
    code    => 'runtime.service_unavailable',
    message => 'Secure secret handle issuance unavailable',
    details => {
      method => 'secrets.get',
    },
  };

  return;
}

sub _secure_random_bytes {
  my ($self, $length) = @_;

  if (!(defined $length && !ref($length) && $length =~ /\A[1-9]\d*\z/mxs)) {
    croak "length must be a positive integer\n";
  }

  if (my $cb = $self->{random_bytes_cb}) {
    my $bytes = $cb->($length);
    if (defined $bytes && !ref($bytes) && length($bytes) == $length) {
      return $bytes;
    }
    croak "random_bytes_cb must return exactly $length bytes\n";
  }

  my $bytes = eval {
    require Crypt::URandom;
    Crypt::URandom::urandom($length)
      ;    # uncoverable statement reason: Crypt::URandom is not installed in the test environment
  };

  # uncoverable branch true reason: Crypt::URandom is not installed in the test environment
  if (defined $bytes && !ref($bytes) && length($bytes) == $length) {
    return $bytes;    # uncoverable statement reason: Crypt::URandom is not installed in the test environment
  }

  $bytes = eval {
    require Bytes::Random::Secure;
    my $rng = Bytes::Random::Secure->new(NonBlocking => 1);
    $rng->bytes($length);
  };
  if (defined $bytes && !ref($bytes) && length($bytes) == $length) {
    return $bytes;
  }

  # uncoverable branch true reason: Bytes::Random::Secure always satisfies the request before this fallback
  # uncoverable branch false reason: Bytes::Random::Secure always satisfies the request before this fallback
  if (open my $fh, '<:raw', '/dev/urandom') {
    my $buffer = q{};    # uncoverable statement reason: unreachable while an earlier random source is available
    my $read   = read($fh, $buffer, $length)
      ;                  # uncoverable statement reason: unreachable while an earlier random source is available
                         # uncoverable branch true reason: unreachable while an earlier random source is available
                         # uncoverable branch false reason: unreachable while an earlier random source is available
    if (!close $fh) {    # uncoverable statement reason: unreachable while an earlier random source is available
      return;            # uncoverable statement reason: unreachable while an earlier random source is available
    }

    # uncoverable branch true reason: unreachable while an earlier random source is available
    # uncoverable branch false reason: unreachable while an earlier random source is available
    if (defined $read && $read == $length)
    {    # uncoverable statement reason: unreachable while an earlier random source is available
      return $buffer;    # uncoverable statement reason: unreachable while an earlier random source is available
    }
  }

  croak "No secure random source available\n"
    ;    # uncoverable statement reason: unreachable while an earlier random source is available
}

sub _validate_secrets {
  my ($secrets) = @_;

  for my $name (sort keys %{$secrets}) {
    if (!(defined $name && length($name))) {
      croak "secret names must be non-empty strings\n";
    }
    if (!defined $secrets->{$name} || ref($secrets->{$name})) {
      croak "secret $name must be a string\n";
    }
  }

  return 1;
}

sub _validate_secret_policies {
  my ($policies) = @_;

  for my $name (sort keys %{$policies}) {
    if (!(defined $name && length($name))) {
      croak "secret policy names must be non-empty strings\n";
    }
    my $policy = $policies->{$name};
    if (!(ref($policy) eq 'HASH')) {
      croak "secret policy $name must be an object\n";
    }

    for my $field (
      qw(
      allowed_session_ids
      allowed_program_ids
      allowed_purposes
      allowed_methods
      allowed_adapter_ids
      allowed_secret_slots
      )
    ) {
      if (!(exists $policy->{$field})) {
        next;
      }
      if (!(ref($policy->{$field}) eq 'ARRAY' && !any { !defined || ref || !length } @{$policy->{$field}})) {
        croak "secret policy $name.$field must be an array of non-empty strings\n";
      }
    }
  }

  return 1;
}

sub _invalid_secret_access {
  my (%args) = @_;
  my $param = $args{param};

  CORE::die {
    code    => 'protocol.invalid_params',
    message => 'Secret access denied or unavailable',
    (defined $param ? (details => {param => $param}) : ()),
  };

  return;
}

sub _require_string_arg {
  my ($name, $value) = @_;

  if (!(defined $value && !ref($value) && length($value))) {
    croak "$name is required\n";
  }

  return $value;
}

sub _optional_string_arg {
  my ($name, $value) = @_;
  if (!(defined $value)) {
    return;
  }

  if (ref($value) || !length($value)) {
    croak "$name must be a non-empty string\n";
  }

  return $value;
}

sub _clone_json {
  my ($value) = @_;
  if (!(defined $value)) {
    return;
  }
  return JSON::decode_json(JSON::encode_json($value));
}

sub _ms_to_unix_seconds {
  my ($ms) = @_;
  return int(($ms + 999) / 1000);
}

1;

=head1 NAME

Overnet::Program::SecretProvider - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::SecretProvider;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 has_secret

Public API entry point.

=head2 audit_events

Public API entry point.

=head2 issue_secret_handle

Public API entry point.

=head2 resolve_secret_handle

Public API entry point.

=head2 revoke_secret_handle

Public API entry point.

=head2 revoke_secret_handles_for_session

Public API entry point.

=head2 rotate_secret

Public API entry point.

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
