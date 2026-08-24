package Overnet::Auth::Agent;

use strictures 2;
use Moo;
use English qw(-no_match_vars);

use JSON         ();
use Time::HiRes  qw(time);
use Scalar::Util qw(blessed weaken);
use Overnet::Authority::Delegation;
use Overnet::CommandBus;

our $VERSION = '0.001';

has identities                   => (is => 'rw',   accessor => '_identities');
has identity_order               => (is => 'rw',   accessor => '_identity_order');
has policies                     => (is => 'rw',   accessor => '_policies');
has service_pins                 => (is => 'rw',   accessor => '_service_pins');
has sessions                     => (is => 'rw',   accessor => '_sessions');
has state_writer                 => (is => 'ro',   reader   => '_state_writer');
has next_policy_id               => (is => 'rw',   accessor => '_next_policy_id_value');
has next_session_id              => (is => 'rw',   accessor => '_next_session_id_value');
has allow_unattended_autoapprove => (is => 'ro',   reader   => '_allow_unattended_autoapprove');
has bus                          => (is => 'lazy', init_arg => undef);

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $state = {
    identities                   => {},
    identity_order               => [],
    policies                     => [],
    service_pins                 => {},
    sessions                     => {},
    state_writer                 => $args{state_writer},
    next_policy_id               => 1,
    next_session_id              => 1,
    allow_unattended_autoapprove => $args{allow_unattended_autoapprove} ? 1 : 0,
  };

  for my $identity (@{$args{identities} || []}) {
    if (!(ref($identity) eq 'HASH')) {
      next;
    }
    my $identity_id = $identity->{identity_id};
    if (!(defined $identity_id && !ref($identity_id) && length($identity_id))) {
      next;
    }

    my %stored = %{$identity};
    $state->{identities}{$identity_id} = \%stored;
    push @{$state->{identity_order}}, $identity_id;
  }

  for my $policy (@{$args{policies} || []}) {
    if (!(ref($policy) eq 'HASH')) {
      next;
    }
    my $stored = _normalize_policy_input($policy);
    if (!($stored)) {
      next;
    }

    my $policy_id = _policy_id_value($policy->{policy_id});
    if (!(defined $policy_id)) {
      $policy_id = _next_policy_id($state);
    }
    $stored->{policy_id} = $policy_id;
    push @{$state->{policies}}, $stored;
    _note_policy_id($state, $policy_id);
  }

  $state->{service_pins} = {
    map  { $_ => {%{$args{service_pins}{$_}}} }
    grep { ref($args{service_pins}{$_}) eq 'HASH' }
      keys %{$args{service_pins} || {}}
  };

  for my $session (@{$args{sessions} || []}) {
    if (!(ref($session) eq 'HASH')) {
      next;
    }
    my $handle = _session_handle_id($session->{session_handle});
    if (!(defined $handle)) {
      next;
    }
    $state->{sessions}{$handle} = {%{$session}, session_handle => {%{$session->{session_handle} || {}}},};
    while (exists $state->{sessions}{'sess-' . $state->{next_session_id}}) {
      $state->{next_session_id}++;
    }
  }

  return $state;
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub dispatch {
  my ($self, $request) = @_;
  my $id =
    (ref($request) eq 'HASH' && defined($request->{id}) && !ref($request->{id}))
    ? $request->{id}
    : undef;

  if (!(ref($request) eq 'HASH')) {
    return $self->_error_response($id, 'protocol.invalid_message', 'request must be an object');
  }
  if (!((($request->{type} || q{}) eq 'request'))) {
    return $self->_error_response($id, 'protocol.invalid_message', 'request type must be request');
  }

  my $method = $request->{method};
  if (!(defined $method && !ref($method) && length($method))) {
    return $self->_error_response($id, 'protocol.invalid_message', 'method is required');
  }

  if (!($self->bus->has_handler($method))) {
    return $self->_error_response($id, 'protocol.unknown_method', "unsupported method: $method");
  }

  my $params = ref($request->{params}) eq 'HASH' ? $request->{params} : {};

  my $result;
  my $error;
  eval {
    $result = $self->bus->dispatch($method, $params, {request => $request});
    1;
  } or $error = $EVAL_ERROR;

  if ($error) {
    my $normalized = Overnet::CommandBus->normalize_error($error, code => 'auth.internal_failure');
    return $self->_error_response($id, $normalized->{code}, $normalized->{message});
  }

  return {
    type   => 'response',
    id     => $id,
    ok     => JSON::true,
    result => $result,
  };
}

sub _build_bus {
  my ($self) = @_;
  weaken(my $agent = $self);

  my %method_impls = (
    'agent.info'          => '_dispatch_agent_info',
    'identities.list'     => '_dispatch_identities_list',
    'policies.list'       => '_dispatch_policies_list',
    'policies.grant'      => '_dispatch_policies_grant',
    'policies.revoke'     => '_dispatch_policies_revoke',
    'service_pins.list'   => '_dispatch_service_pins_list',
    'service_pins.set'    => '_dispatch_service_pins_set',
    'service_pins.forget' => '_dispatch_service_pins_forget',
    'sessions.list'       => '_dispatch_sessions_list',
    'sessions.authorize'  => '_dispatch_authorize',
    'sessions.renew'      => '_dispatch_renew',
    'sessions.revoke'     => '_dispatch_revoke',
  );

  my $bus =
    Overnet::CommandBus->new(middleware => [Overnet::CommandBus->error_normalizer(code => 'auth.internal_failure')],);
  for my $method (sort keys %method_impls) {
    my $impl = $method_impls{$method};
    $bus->register(
      $method,
      sub {
        my (undef, undef, $context) = @_;
        return $agent->$impl($context->{request});
      }
    );
  }

  return $bus;
}

sub _dispatch_agent_info {
  my ($self, $request) = @_;

  return {
    protocol_version => '0.2.0',
    capabilities     => [
      'agent.info',      'identities.list',    'policies.list',    'policies.grant',
      'policies.revoke', 'service_pins.list',  'service_pins.set', 'service_pins.forget',
      'sessions.list',   'sessions.authorize', 'sessions.renew',   'sessions.revoke',
    ],
  };
}

sub _dispatch_identities_list {
  my ($self, $request) = @_;

  my @identities;
  for my $identity_id (@{$self->{identity_order}}) {
    my $identity   = $self->{identities}{$identity_id} || {};
    my %descriptor = (
      identity_id     => $identity_id,
      public_identity => _clone_hash($identity->{public_identity}),
    );
    if ( defined $identity->{backend_type}
      && !ref($identity->{backend_type})
      && length($identity->{backend_type})) {
      $descriptor{backend_type} = $identity->{backend_type};
    }
    push @identities, \%descriptor;
  }

  return {identities => \@identities,};
}

sub _dispatch_policies_list {
  my ($self, $request) = @_;

  return {policies => [map { _policy_descriptor($_) } @{$self->{policies}}],};
}

sub _dispatch_policies_grant {
  my ($self, $request) = @_;
  my $params = $request->{params};

  if (!(ref($params) eq 'HASH')) {
    CORE::die {code => 'protocol.invalid_params', message => 'params must be an object'};
  }

  my $stored = _normalize_policy_input($params->{policy})
    or CORE::die {code => 'protocol.invalid_params', message => 'policy must be a valid policy object'};

  my ($policy, $persist_error) = $self->_persist_mutation(
    sub {
      my $policy_id = $self->_next_policy_id;
      $stored->{policy_id} = $policy_id;
      push @{$self->{policies}}, $stored;
      return _policy_descriptor($stored);
    }
  );
  if (!($policy)) {
    CORE::die {code => $persist_error->[0], message => $persist_error->[1]};
  }

  return {policy => $policy,};
}

sub _dispatch_policies_revoke {
  my ($self, $request) = @_;
  my $params = $request->{params};

  if (!(ref($params) eq 'HASH')) {
    CORE::die {code => 'protocol.invalid_params', message => 'params must be an object'};
  }

  my $policy_id = _policy_id_value($params->{policy_id});
  if (!(defined $policy_id)) {
    CORE::die {code => 'protocol.invalid_params', message => 'policy_id is required'};
  }

  my ($revoked, $persist_error) = $self->_persist_mutation(
    sub {
      $self->{policies} = [grep { (($_->{policy_id} || q{}) ne $policy_id) } @{$self->{policies}}];
      return 1;
    }
  );
  if (!($revoked)) {
    CORE::die {code => $persist_error->[0], message => $persist_error->[1]};
  }

  return {policy_id => $policy_id,};
}

sub _dispatch_service_pins_list {
  my ($self, $request) = @_;

  return {
    service_pins => [
      map { {locator => $_, service_identity => _clone_hash($self->{service_pins}{$_}),} }
      sort keys %{$self->{service_pins}}
    ],
  };
}

sub _dispatch_service_pins_set {
  my ($self, $request) = @_;
  my $params = $request->{params};

  if (!(ref($params) eq 'HASH')) {
    CORE::die {code => 'protocol.invalid_params', message => 'params must be an object'};
  }

  my $locator = $params->{locator};
  if (!(defined $locator && !ref($locator) && length($locator))) {
    CORE::die {code => 'protocol.invalid_params', message => 'locator is required'};
  }

  my $service_identity = _normalize_service_identity($params->{service_identity});
  if (!($service_identity)) {
    CORE::die {code => 'protocol.invalid_params', message => 'service_identity must be a valid descriptor'};
  }

  my ($stored, $persist_error) = $self->_persist_mutation(
    sub {
      $self->{service_pins}{$locator} = $service_identity;
      return _clone_hash($service_identity);
    }
  );
  if (!($stored)) {
    CORE::die {code => $persist_error->[0], message => $persist_error->[1]};
  }

  return {
    locator          => $locator,
    service_identity => $stored,
  };
}

sub _dispatch_service_pins_forget {
  my ($self, $request) = @_;
  my $params = $request->{params};

  if (!(ref($params) eq 'HASH')) {
    CORE::die {code => 'protocol.invalid_params', message => 'params must be an object'};
  }

  my $locator = $params->{locator};
  if (!(defined $locator && !ref($locator) && length($locator))) {
    CORE::die {code => 'protocol.invalid_params', message => 'locator is required'};
  }

  my ($forgotten, $persist_error) = $self->_persist_mutation(
    sub {
      delete $self->{service_pins}{$locator};
      return 1;
    }
  );
  if (!($forgotten)) {
    CORE::die {code => $persist_error->[0], message => $persist_error->[1]};
  }

  return {locator => $locator,};
}

sub _dispatch_sessions_list {
  my ($self, $request) = @_;

  return {
    sessions => [
      map { _session_descriptor($self->{sessions}{$_}) }
      sort keys %{$self->{sessions}}
    ],
  };
}

sub _dispatch_authorize {
  my ($self,    $request)       = @_;
  my ($context, $context_error) = $self->_authorize_context($request->{params});
  if (!($context)) {
    CORE::die {code => $context_error->[0], message => $context_error->[1]};
  }

  my ($service_pin_state, $service_error) = $self->_service_pin_state($context->{service});
  if (!(defined $service_pin_state)) {
    CORE::die {code => $service_error->[0], message => $service_error->[1]};
  }

  if (!($self->_authorize_allowed($context))) {
    CORE::die {
      code    => 'auth.headless_unavailable',
      message => 'approval is required but interactive approval is unavailable'
    };
  }

  my ($returned, $artifact_error) = $self->_authorize_artifacts($context);
  if (!($returned)) {
    CORE::die {code => $artifact_error->[0], message => $artifact_error->[1]};
  }

  my ($session_handle, $persist_error) = $self->_persist_authorized_session($context, $service_pin_state);
  if (!($session_handle)) {
    CORE::die {code => $persist_error->[0], message => $persist_error->[1]};
  }

  return _authorize_response(
    identity_id       => $context->{identity}{identity_id},
    service_pin_state => $service_pin_state,
    artifacts         => $returned,
    session_handle    => $session_handle,
  );
}

sub _authorize_context {
  my ($self, $params) = @_;
  if (!(ref($params) eq 'HASH')) {
    return (undef, ['protocol.invalid_params', 'params must be an object']);
  }
  my $error = _validate_authorize_params($params);
  if ($error) {
    return (undef, $error);
  }
  my ($identity, $identity_error) = $self->_resolve_identity($params->{identity_id});
  if (!($identity)) {
    return (undef, $identity_error);
  }
  return (
    {
      identity   => $identity,
      program_id => $params->{program_id},
      service    => $params->{service},
      scope      => $params->{scope},
      action     => $params->{action},
      artifacts  => $params->{artifacts},
      challenge  => $params->{challenge},
    },
    undef
  );
}

sub _validate_authorize_params {
  my ($params) = @_;
  for my $check ([program_id => 'program_id is required'], [scope => 'scope is required'],) {
    if (!(_non_empty_scalar($params->{$check->[0]}))) {
      return ['protocol.invalid_params', $check->[1]];
    }
  }
  if (!(ref($params->{service}) eq 'HASH')) {
    return ['protocol.invalid_params', 'service must be an object'];
  }
  if (!(ref($params->{service}{locators}) eq 'ARRAY' && @{$params->{service}{locators}})) {
    return ['protocol.invalid_params', 'service.locators must be a non-empty array'];
  }
  if (!(_supported_authorize_action($params->{action}))) {
    return ['auth.unsupported_action', "unsupported action: $params->{action}"];
  }
  if (!(ref($params->{artifacts}) eq 'ARRAY' && @{$params->{artifacts}})) {
    return ['protocol.invalid_params', 'artifacts must be a non-empty array'];
  }
  return;
}

sub _non_empty_scalar {
  my ($value) = @_;
  return defined $value && !ref($value) && length($value) ? 1 : 0;
}

sub _supported_authorize_action {
  my ($action) = @_;
  return
       defined $action
    && !ref($action)
    && ($action eq 'session.authenticate' || $action eq 'session.delegate') ? 1 : 0;
}

sub _authorize_allowed {
  my ($self, $context) = @_;
  if (
    $self->_policy_matches(
      identity_id => $context->{identity}{identity_id},
      program_id  => $context->{program_id},
      service     => $context->{service},
      scope       => $context->{scope},
      action      => $context->{action},
    )
  ) {
    return 1;
  }

  # The agent exposes no approval UI, and a request cannot vouch for its own
  # approval: a client-supplied "interactive" flag is not evidence that a user
  # consented. Absent a matching policy, fail closed unless the operator has
  # explicitly opted this agent into unattended auto-approval.
  return $self->{allow_unattended_autoapprove} ? 1 : 0;
}

sub _authorize_artifacts {
  my ($self, $context) = @_;
  my @returned;
  for my $artifact (@{$context->{artifacts}}) {
    my ($built, $artifact_error) = $self->_build_artifact(
      identity  => $context->{identity},
      action    => $context->{action},
      scope     => $context->{scope},
      challenge => $context->{challenge},
      artifact  => $artifact,
    );
    if (!($built)) {
      return (undef, $artifact_error);
    }
    push @returned, $built;
  }
  return (\@returned, undef);
}

sub _persist_authorized_session {
  my ($self, $context, $service_pin_state) = @_;
  return $self->_persist_mutation(
    sub {
      if ($service_pin_state eq 'first_contact') {
        $self->_pin_service_identity($context->{service});
      }
      return $self->_store_session(
        identity_id => $context->{identity}{identity_id},
        program_id  => $context->{program_id},
        service     => _clone_hash($context->{service}),
        scope       => $context->{scope},
        action      => $context->{action},
        renewable   => 1,
        artifacts   => [map { _clone_hash($_) } @{$context->{artifacts}}],
      );
    }
  );
}

sub _authorize_response {
  my (%args) = @_;
  return {
    identity_id       => $args{identity_id},
    service_pin_state => $args{service_pin_state},
    artifacts         => $args{artifacts},
    session_handle    => $args{session_handle},
  };
}

sub _dispatch_renew {
  my ($self, $request) = @_;
  my $params = $request->{params};

  if (!(ref($params) eq 'HASH')) {
    CORE::die {code => 'protocol.invalid_params', message => 'params must be an object'};
  }

  my $session_handle = _session_handle_id($params->{session_handle});
  if (!(defined $session_handle)) {
    CORE::die {code => 'protocol.invalid_params', message => 'session_handle.id is required'};
  }

  my $session = $self->{sessions}{$session_handle}
    or CORE::die {code => 'protocol.invalid_params', message => 'unknown session_handle'};

  if (!($session->{renewable})) {
    CORE::die {code => 'auth.policy_denied', message => 'session is not renewable'};
  }

  my ($identity, $identity_error) =
    $self->_resolve_identity($session->{identity_id});
  if (!($identity)) {
    CORE::die {code => $identity_error->[0], message => $identity_error->[1]};
  }

  my ($service_pin_state, $service_error) =
    $self->_service_pin_state($session->{service});
  if (!(defined $service_pin_state)) {
    CORE::die {code => $service_error->[0], message => $service_error->[1]};
  }

  my $approved = $self->_policy_matches(
    identity_id => $session->{identity_id},
    program_id  => $session->{program_id},
    service     => $session->{service},
    scope       => $session->{scope},
    action      => $session->{action},
  );

  if (!$approved) {
    CORE::die {code => 'auth.policy_denied', message => 'session no longer matches current policy'};
  }

  my @returned;
  for my $artifact (@{$session->{artifacts} || []}) {
    my ($built, $artifact_error) = $self->_build_artifact(
      identity  => $identity,
      action    => $session->{action},
      scope     => $session->{scope},
      challenge => $params->{challenge},
      artifact  => $artifact,
    );
    if (!($built)) {
      CORE::die {code => $artifact_error->[0], message => $artifact_error->[1]};
    }
    push @returned, $built;
  }

  return {
    identity_id       => $session->{identity_id},
    service_pin_state => $service_pin_state,
    artifacts         => \@returned,
    session_handle    => _clone_hash($session->{session_handle}),
  };
}

sub _dispatch_revoke {
  my ($self, $request) = @_;
  my $params = $request->{params};

  if (!(ref($params) eq 'HASH')) {
    CORE::die {code => 'protocol.invalid_params', message => 'params must be an object'};
  }

  my $session_handle = _session_handle_id($params->{session_handle});
  if (!(defined $session_handle)) {
    CORE::die {code => 'protocol.invalid_params', message => 'session_handle.id is required'};
  }

  my ($revoked, $persist_error) = $self->_persist_mutation(
    sub {
      delete $self->{sessions}{$session_handle};
      return 1;
    }
  );
  if (!($revoked)) {
    CORE::die {code => $persist_error->[0], message => $persist_error->[1]};
  }

  return {};
}

sub _resolve_identity {
  my ($self, $identity_id) = @_;

  if (defined $identity_id && !ref($identity_id) && length($identity_id)) {
    my $identity = $self->{identities}{$identity_id}
      or return (undef, ['auth.unknown_identity', "unknown identity_id: $identity_id"]);
    return ($identity, undef);
  }

  if (!(@{$self->{identity_order}} == 1)) {
    return (undef, ['auth.identity_required', 'identity_id is required']);
  }

  my $default_id = $self->{identity_order}[0];
  return ($self->{identities}{$default_id}, undef);
}

sub _policy_matches {
  my ($self, %args) = @_;

  for my $policy (@{$self->{policies}}) {
    if (!(_policy_base_matches($policy, \%args))) {
      next;
    }
    if (_policy_service_matches($policy, $args{service})) {
      return 1;
    }
  }

  return 0;
}

sub _policy_base_matches {
  my ($policy, $args) = @_;
  for my $field (qw(identity_id program_id scope action)) {
    if (!(($policy->{$field} || q{}) eq ($args->{$field} || q{}))) {
      return 0;
    }
  }
  return 1;
}

sub _policy_service_matches {
  my ($policy, $service) = @_;
  my $policy_identity  = $policy->{service_identity};
  my $request_identity = $service->{service_identity};

  if (ref($request_identity) eq 'HASH') {
    return _service_identity_matches($policy_identity, $request_identity);
  }
  if (ref($policy_identity) eq 'HASH') {
    return 0;
  }
  return _sorted_list($policy->{locators}) eq _sorted_list($service->{locators}) ? 1 : 0;
}

sub _service_identity_matches {
  my ($policy_identity, $request_identity) = @_;
  if (!(ref($policy_identity) eq 'HASH')) {
    return 0;
  }
  for my $field (qw(scheme value)) {
    if (!(($policy_identity->{$field} || q{}) eq ($request_identity->{$field} || q{}))) {
      return 0;
    }
  }
  return 1;
}

sub _next_policy_id {
  my ($self) = @_;
  my $policy_id = 'policy-' . $self->{next_policy_id}++;
  return $policy_id;
}

sub _note_policy_id {
  my ($self, $policy_id) = @_;
  if (!(defined $policy_id)) {
    return;
  }
  my ($policy_number) = $policy_id =~ /\Apolicy-(\d+)\z/mxs;
  if (!(defined $policy_number)) {
    return;
  }

  my $next = $policy_number + 1;
  if ($next > $self->{next_policy_id}) {
    $self->{next_policy_id} = $next;
  }
  return;
}

sub _policy_descriptor {
  my ($policy) = @_;
  my %descriptor = (
    policy_id   => $policy->{policy_id},
    identity_id => $policy->{identity_id},
    program_id  => $policy->{program_id},
    scope       => $policy->{scope},
    action      => $policy->{action},
  );
  if (ref($policy->{locators}) eq 'ARRAY') {
    $descriptor{locators} = _clone_hash($policy->{locators});
  }
  if (ref($policy->{service_identity}) eq 'HASH') {
    $descriptor{service_identity} =
      _clone_hash($policy->{service_identity});
  }
  return \%descriptor;
}

sub _session_descriptor {
  my ($session) = @_;
  my %descriptor = (
    session_handle => _clone_hash($session->{session_handle}),
    identity_id    => $session->{identity_id},
    program_id     => $session->{program_id},
    service        => _clone_hash($session->{service}),
    scope          => $session->{scope},
    action         => $session->{action},
    renewable      => $session->{renewable} ? 1 : 0,
  );
  if (defined $session->{expires_at} && !ref($session->{expires_at})) {
    $descriptor{expires_at} = $session->{expires_at};
  }
  return \%descriptor;
}

sub _normalize_policy_input {
  my ($policy) = @_;
  if (!(ref($policy) eq 'HASH')) {
    return;
  }

  my $fields = _required_policy_fields($policy);
  if (!($fields)) {
    return;
  }

  my $service = _policy_service_input($policy);
  my ($locators, $service_identity) = _normalized_policy_service($service);

  if (!(@{$locators} || $service_identity)) {
    return;
  }

  my %stored = (%{$fields},);
  if (@{$locators}) {
    $stored{locators} = $locators;
  }
  if ($service_identity) {
    $stored{service_identity} = $service_identity;
  }

  return \%stored;
}

sub _required_policy_fields {
  my ($policy) = @_;
  my %fields;
  for my $field (qw(identity_id program_id scope action)) {
    my $value = $policy->{$field};
    if (!(defined $value && !ref($value) && length($value))) {
      return;
    }
    $fields{$field} = $value;
  }
  return \%fields;
}

sub _policy_service_input {
  my ($policy) = @_;
  if (ref($policy->{service}) eq 'HASH') {
    return $policy->{service};
  }
  return {
    _policy_locator_arg($policy),
    (ref($policy->{locators}) eq 'ARRAY'        ? (locators         => $policy->{locators})         : ()),
    (ref($policy->{service_identity}) eq 'HASH' ? (service_identity => $policy->{service_identity}) : ()),
  };
}

sub _policy_locator_arg {
  my ($policy) = @_;
  if (defined($policy->{locator}) && !ref($policy->{locator}) && length($policy->{locator})) {
    return (locators => [$policy->{locator}]);
  }
  return;
}

sub _normalized_policy_service {
  my ($service) = @_;
  my @locators =
    ref($service->{locators}) eq 'ARRAY'
    ? grep { defined && !ref && length } @{$service->{locators}}
    : ();
  my $service_identity = _normalize_service_identity($service->{service_identity});
  return (\@locators, $service_identity);
}

sub _normalize_service_identity {
  my ($service_identity) = @_;
  if (!(ref($service_identity) eq 'HASH')) {
    return;
  }

  my $scheme = $service_identity->{scheme};
  my $value  = $service_identity->{value};
  if (!(defined $scheme && !ref($scheme) && length($scheme))) {
    return;
  }
  if (!(defined $value && !ref($value) && length($value))) {
    return;
  }

  my %normalized = (
    scheme => $scheme,
    value  => $value,
  );
  if ( defined $service_identity->{display}
    && !ref($service_identity->{display})
    && length($service_identity->{display})) {
    $normalized{display} = $service_identity->{display};
  }

  return \%normalized;
}

sub _policy_id_value {
  my ($policy_id) = @_;
  if (!(defined $policy_id && !ref($policy_id) && length($policy_id))) {
    return;
  }
  return $policy_id;
}

sub _persist_mutation {
  my ($self, $mutator) = @_;
  my $snapshot = $self->_mutable_state_snapshot;
  my $result   = $mutator->();
  my $writer   = $self->{state_writer};

  if (ref($writer) eq 'CODE') {
    my $ok = eval { $writer->($self->_persistent_state) };
    if ($EVAL_ERROR || !$ok) {
      my $message = $EVAL_ERROR || 'auth state write failed';
      chomp $message;
      $self->_restore_mutable_state_snapshot($snapshot);
      return (undef, ['auth.internal_failure', $message]);
    }
  }

  return ($result, undef);
}

sub _mutable_state_snapshot {
  my ($self) = @_;
  return {
    policies        => _clone_hash($self->{policies}),
    service_pins    => _clone_hash($self->{service_pins}),
    sessions        => _clone_hash($self->{sessions}),
    next_policy_id  => $self->{next_policy_id},
    next_session_id => $self->{next_session_id},
  };
}

sub _restore_mutable_state_snapshot {
  my ($self, $snapshot) = @_;
  $self->{policies}        = _clone_hash($snapshot->{policies})     || [];
  $self->{service_pins}    = _clone_hash($snapshot->{service_pins}) || {};
  $self->{sessions}        = _clone_hash($snapshot->{sessions})     || {};
  $self->{next_policy_id}  = $snapshot->{next_policy_id};
  $self->{next_session_id} = $snapshot->{next_session_id};
  return 1;
}

sub _persistent_state {
  my ($self) = @_;
  return {
    policies     => [map { _clone_hash($_) } @{$self->{policies}}],
    service_pins => _clone_hash($self->{service_pins}),
    sessions     => [
      map { _clone_hash($self->{sessions}{$_}) }
      sort keys %{$self->{sessions}}
    ],
  };
}

sub _service_pin_state {
  my ($self, $service) = @_;
  my $identity = $service->{service_identity};

  if (!(ref($identity) eq 'HASH')) {
    return ('provisional', undef);
  }

  for my $locator (@{$service->{locators} || []}) {
    my $pinned = $self->{service_pins}{$locator};
    if (!(ref($pinned) eq 'HASH')) {
      next;
    }
    if (
      !(
           (($pinned->{scheme} || q{}) eq ($identity->{scheme} || q{}))
        && (($pinned->{value} || q{}) eq ($identity->{value} || q{}))
      )
    ) {
      return (undef,
        ['auth.service_identity_mismatch', 'presented service identity does not match pinned service identity']);
    }
  }

  for my $locator (@{$service->{locators} || []}) {
    if (ref($self->{service_pins}{$locator}) eq 'HASH') {
      return ('known', undef);
    }
  }

  return ('first_contact', undef);
}

sub _pin_service_identity {
  my ($self, $service) = @_;
  if (!(ref($service->{service_identity}) eq 'HASH')) {
    return;
  }

  for my $locator (@{$service->{locators} || []}) {
    if (!(defined $locator && !ref($locator) && length($locator))) {
      next;
    }
    $self->{service_pins}{$locator} =
      _clone_hash($service->{service_identity});
  }
  return;
}

sub _build_artifact {
  my ($self,   %args)           = @_;
  my ($params, $artifact_error) = _artifact_params($args{artifact});
  if (!($params)) {
    return (undef, $artifact_error);
  }
  my ($key, $backend_error) = _identity_signing_key($args{identity});
  if (!(defined $key)) {
    return (undef, [$backend_error->{code}, $backend_error->{message}]);
  }

  my ($event, $event_error) = _event_for_action(
    key       => $key,
    action    => $args{action},
    scope     => $args{scope},
    challenge => $args{challenge},
    params    => $params,
  );
  if (!($event)) {
    return (undef, $event_error);
  }

  if (ref($event) eq 'HASH' && !$event->{valid} && $event->{reason}) {
    return (undef, ['auth.internal_failure', $event->{reason}]);
  }

  return (
    {
      type   => 'nostr.event',
      format => 'nostr.event',
      value  => $event,
    },
    undef
  );
}

sub _artifact_params {
  my ($artifact) = @_;
  if (!(ref($artifact) eq 'HASH')) {
    return (undef, ['protocol.invalid_params', 'artifact must be an object']);
  }
  my $type = $artifact->{type} || q{};
  if (!($type eq 'nostr.event')) {
    return (undef, ['auth.unsupported_artifact', "unsupported artifact type: $type"]);
  }
  if (!(ref($artifact->{params}) eq 'HASH')) {
    return (undef, ['protocol.invalid_params', 'artifact params must be an object']);
  }
  return ($artifact->{params}, undef);
}

sub _event_for_action {
  my (%args) = @_;
  if (($args{action} || q{}) eq 'session.authenticate') {
    return _auth_event_for_artifact(%args);
  }
  if (($args{action} || q{}) eq 'session.delegate') {
    return _delegation_event_for_artifact(%args);
  }
  return (undef, ['auth.unsupported_action', "unsupported action: $args{action}"]);
}

sub _auth_event_for_artifact {
  my (%args) = @_;
  my $error = _validate_auth_artifact(%args);
  if ($error) {
    return (undef, $error);
  }
  return (
    Overnet::Authority::Delegation->create_auth_event(
      key        => $args{key},
      challenge  => $args{challenge}{value},
      scope      => $args{scope},
      created_at => _created_at(),
    ),
    undef
  );
}

sub _validate_auth_artifact {
  my (%args) = @_;
  if (!(_has_challenge_value($args{challenge}))) {
    return ['protocol.invalid_params', 'challenge.value is required for session.authenticate'];
  }
  if (!(defined($args{params}{kind}) && $args{params}{kind} == 22_242)) {
    return ['protocol.invalid_params', 'session.authenticate requires kind 22242 nostr.event artifact'];
  }
  my %tags = _first_tag_values($args{params}{tags});
  return _validate_auth_tags(\%tags, $args{scope}, $args{challenge}{value});
}

sub _has_challenge_value {
  my ($challenge) = @_;
  return
       ref($challenge) eq 'HASH'
    && defined($challenge->{value})
    && !ref($challenge->{value})
    && length($challenge->{value}) ? 1 : 0;
}

sub _validate_auth_tags {
  my ($tags, $scope, $challenge) = @_;
  if (!(defined($tags->{relay}) && $tags->{relay} eq $scope)) {
    return ['protocol.invalid_params', 'auth event relay tag must match the requested scope'];
  }
  if (!(defined($tags->{challenge}) && $tags->{challenge} eq $challenge)) {
    return ['protocol.invalid_params', 'auth event challenge tag must match the requested challenge'];
  }
  return;
}

sub _delegation_event_for_artifact {
  my (%args) = @_;
  my ($tags, $error) = _validated_delegation_tags(%args);
  if (!($tags)) {
    return (undef, $error);
  }
  return (
    Overnet::Authority::Delegation->create_delegation_grant_event(
      key             => $args{key},
      relay_url       => $tags->{relay},
      scope           => $args{scope},
      delegate_pubkey => $tags->{delegate},
      session_id      => $tags->{session},
      expires_at      => $tags->{expires_at},
      created_at      => _created_at(),
      (defined($tags->{nick}) ? (nick => $tags->{nick}) : ()),
    ),
    undef
  );
}

sub _validated_delegation_tags {
  my (%args) = @_;
  if (!(defined($args{params}{kind}) && $args{params}{kind} == 14_142)) {
    return (undef, ['protocol.invalid_params', 'session.delegate requires kind 14142 nostr.event artifact']);
  }
  my %tags  = _first_tag_values($args{params}{tags});
  my $error = _validate_delegation_tags(\%tags, $args{scope});
  return $error ? (undef, $error) : (\%tags, undef);
}

sub _validate_delegation_tags {
  my ($tags, $scope) = @_;
  for my $check (
    [relay => sub { defined $tags->{relay} && length $tags->{relay} } => 'delegation event relay tag is required'],
    [
      server => sub { defined($tags->{server}) && $tags->{server} eq $scope } =>
        'delegation event server tag must match the requested scope'
    ],
    [
      delegate => sub { defined($tags->{delegate}) && $tags->{delegate} =~ /\A[0-9a-f]{64}\z/mxs } =>
        'delegation event delegate tag is required'
    ],
    [
      session => sub { defined($tags->{session}) && length($tags->{session}) } =>
        'delegation event session tag is required'
    ],
    [
      expires_at => sub { defined($tags->{expires_at}) && $tags->{expires_at} =~ /\A\d+\z/mxs } =>
        'delegation event expires_at tag is required'
    ],
  ) {
    if (!($check->[1]->())) {
      return ['protocol.invalid_params', $check->[2]];
    }
  }
  return;
}

sub _store_session {
  my ($self, %args) = @_;
  my $id     = 'sess-' . $self->{next_session_id}++;
  my $handle = {id => $id};

  $self->{sessions}{$id} = {%args, session_handle => _clone_hash($handle),};

  return $handle;
}

sub _identity_signing_key {
  my ($identity) = @_;
  my ($backend, $backend_error) = _identity_backend($identity);
  if (!($backend)) {
    return (undef, $backend_error);
  }
  return $backend->load_signing_key(
    identity       => $identity,
    backend_config => $identity->{backend_config},
  );
}

sub _session_handle_id {
  my ($handle) = @_;
  if (!(ref($handle) eq 'HASH')) {
    return;
  }
  if (!(defined($handle->{id}) && !ref($handle->{id}) && length($handle->{id}))) {
    return;
  }
  return $handle->{id};
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    if (exists $values{$tag->[0]}) {
      next;
    }
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _created_at {
  return int(time());
}

sub _clone_hash {
  my ($value) = @_;
  if (!(defined $value)) {
    return $value;
  }
  if (!(ref($value))) {
    return $value;
  }

  if (ref($value) eq 'HASH') {
    return {
      map { $_ => _clone_hash($value->{$_}) }
        keys %{$value}
    };
  }

  if (ref($value) eq 'ARRAY') {
    return [map { _clone_hash($_) } @{$value}];
  }

  return "$value";
}

sub _sorted_list {
  my ($values) = @_;
  if (!(ref($values) eq 'ARRAY')) {
    return q{};
  }
  return join "\0", sort @{$values};
}

sub _identity_backend {
  my ($identity) = @_;

  if (blessed($identity->{backend})
    && $identity->{backend}->can('load_signing_key')) {
    return ($identity->{backend}, undef);
  }

  my $backend_type = $identity->{backend_type};
  if (!(defined $backend_type && !ref($backend_type) && length($backend_type))) {
    $backend_type = 'direct_secret';
  }

  my %backend_classes = (
    direct_secret => 'Overnet::Auth::Backend::DirectSecret',
    pass          => 'Overnet::Auth::Backend::Pass',
  );

  my $class = $backend_classes{$backend_type};
  if (!(defined $class)) {
    return (
      undef,
      {
        code    => 'auth.backend_unavailable',
        message => "unsupported backend_type: $backend_type",
      }
    );
  }

  eval {
    (my $path = "$class.pm") =~ s{::}{/}gmxs;
    require $path;
    1;
  }
    or return (
    undef,
    {
      code    => 'auth.backend_unavailable',
      message => "$EVAL_ERROR",
    }
    );

  return ($class->new, undef);
}

sub _error_response {
  my ($self, $id, $code, $message) = @_;
  return {
    type  => 'response',
    id    => $id,
    ok    => JSON::false,
    error => {
      code    => $code,
      message => $message,
    },
  };
}

1;

=head1 NAME

Overnet::Auth::Agent - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Agent;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 bus

Public API entry point.

=head2 dispatch

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
