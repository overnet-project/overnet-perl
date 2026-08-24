package Overnet::Program::Services;

use strictures 2;
use Moo;
use Carp         qw(croak);
use English      qw(-no_match_vars);
use JSON         ();
use Scalar::Util qw(weaken);
use Overnet::CommandBus;
use Overnet::Core::Nostr;
use Overnet::Program::Permissions;
use Overnet::Program::Runtime;

our $VERSION = '0.001';
my %SERVICE_METHODS = map { $_ => 1 } qw(
  config.get
  config.describe
  secrets.get
  storage.put
  storage.get
  storage.delete
  storage.list
  events.append
  events.read
  subscriptions.open
  subscriptions.close
  nostr.publish_event
  nostr.query_events
  nostr.open_subscription
  nostr.read_subscription_snapshot
  nostr.close_subscription
  timers.schedule
  timers.cancel
  adapters.open_session
  adapters.map_input
  adapters.derive
  adapters.close_session
  overnet.emit_event
  overnet.emit_state
  overnet.emit_private_message
  overnet.emit_capabilities
);

has runtime => (is => 'ro');
has bus     => (is => 'lazy', init_arg => undef);

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my $runtime = $args{runtime};
  if (!(defined $runtime && ref($runtime) && $runtime->isa('Overnet::Program::Runtime'))) {
    croak "runtime is required\n";
  }

  return {runtime => $runtime,};
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub is_service_method {
  my ($class, $method) = @_;
  return defined $method && !ref($method) && $SERVICE_METHODS{$method} ? 1 : 0;
}

sub service_methods {
  return [sort keys %SERVICE_METHODS];
}

sub get_config {
  my ($self, %args) = @_;
  return {config => $self->{runtime}->config,};
}

sub describe_config {
  my ($self, %args) = @_;
  return $self->{runtime}->describe_config;
}

sub get_secret {
  my ($self, %args) = @_;
  my $session_id = _require_dispatch_session_id(
    method     => 'secrets.get',
    session_id => $args{session_id},
  );
  my $name       = _require_string_param('name', $args{name});
  my %issue_args = (
    session_id => $session_id,
    name       => $name,
  );
  if (exists $args{purpose}) {
    $issue_args{purpose} =
      _require_string_param('purpose', $args{purpose});
  }
  if (defined $args{program_id}) {
    $issue_args{program_id} =
      _require_string_param('program_id', $args{program_id});
  }
  return $self->{runtime}->issue_secret_handle(%issue_args,);
}

sub open_adapter_session {
  my ($self, %args) = @_;
  my $adapter_id = _require_string_param('adapter_id', $args{adapter_id});
  my $config     = exists $args{config} ? $args{config} : {};
  my $secret_handles =
    exists $args{secret_handles}
    ? _require_secret_handle_map_param('secret_handles', $args{secret_handles})
    : {};

  _require_object_param('config', $config);
  if (!($self->{runtime}->adapter_registry->has($adapter_id))) {
    _service_unavailable(
      "Unknown adapter_id: $adapter_id",
      {
        method     => 'adapters.open_session',
        adapter_id => $adapter_id,
      }
    );
  }

  my %open_args = (
    adapter_id     => $adapter_id,
    config         => $config,
    secret_handles => $secret_handles,
  );
  if (defined $args{session_id}) {
    $open_args{session_id} = $args{session_id};
  }
  if (keys %{$secret_handles}) {
    $open_args{session_id} = _require_dispatch_session_id(
      method     => 'adapters.open_session',
      session_id => $args{session_id},
    );
    if (defined $args{program_id}) {
      $open_args{program_id} =
        _require_string_param('program_id', $args{program_id});
    }
  } elsif (defined $args{program_id}) {
    $open_args{program_id} =
      _require_string_param('program_id', $args{program_id});
  }

  my $session = $self->{runtime}->open_adapter_session(%open_args);
  return {adapter_session_id => $session->session_id,};
}

sub map_input {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('adapter_session_id', $args{adapter_session_id});
  _require_present_param('input', \%args);
  my $input = $args{input};

  _require_object_param('input', $input);
  my $session = _require_adapter_session($self->{runtime}, $session_id);
  return _normalize_adapter_result(
    %{
      _call_adapter(
        session => $session,
        method  => 'adapters.map_input',
        code    => sub { $session->map_input($input) },
      )
    }
  );
}

sub derive {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('adapter_session_id', $args{adapter_session_id});
  my $operation  = _require_string_param('operation',          $args{operation});
  _require_present_param('input', \%args);
  my $input = $args{input};

  _require_object_param('input', $input);
  my $session = _require_adapter_session($self->{runtime}, $session_id);
  return _normalize_adapter_result(
    %{
      _call_adapter(
        session => $session,
        method  => 'adapters.derive',
        code    => sub {
          $session->derive(
            operation => $operation,
            input     => $input,
          );
        },
      )
    }
  );
}

sub close_adapter_session {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('adapter_session_id', $args{adapter_session_id});

  _require_adapter_session($self->{runtime}, $session_id);
  $self->{runtime}->close_adapter_session($session_id);
  return {};
}

sub put_storage_value {
  my ($self, %args) = @_;
  my $key = _require_string_param('key', $args{key});
  _require_present_param('value', \%args);
  my $value = _require_object_param('value', $args{value});

  return $self->{runtime}->put_document(
    key   => $key,
    value => $value,
  );
}

sub get_storage_value {
  my ($self, %args) = @_;
  my $key = _require_string_param('key', $args{key});

  _require_storage_key($self->{runtime}, $key);
  return $self->{runtime}->get_document(key => $key,);
}

sub delete_storage_value {
  my ($self, %args) = @_;
  my $key = _require_string_param('key', $args{key});

  _require_storage_key($self->{runtime}, $key);
  return $self->{runtime}->delete_document(key => $key,);
}

sub list_storage_keys {
  my ($self, %args) = @_;
  my %list_args;

  if (exists $args{prefix}) {
    $list_args{prefix} =
      _require_optional_string_param('prefix', $args{prefix});
  }

  return $self->{runtime}->list_documents(%list_args);
}

sub append_event_entry {
  my ($self, %args) = @_;
  my $stream = _require_string_param('stream', $args{stream});
  _require_present_param('event', \%args);
  my $event = _require_object_param('event', $args{event});

  return $self->{runtime}->append_event(
    stream => $stream,
    event  => $event,
  );
}

sub read_event_entries {
  my ($self, %args) = @_;
  my $stream    = _require_string_param('stream', $args{stream});
  my %read_args = (stream => $stream,);

  if (exists $args{after_offset}) {
    $read_args{after_offset} =
      _require_integer_param('after_offset', $args{after_offset});
  }
  if (exists $args{limit}) {
    $read_args{limit} =
      _require_non_negative_integer_param('limit', $args{limit});
  }

  return $self->{runtime}->read_events(%read_args);
}

sub open_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_param('session_id',      $args{session_id});
  my $subscription_id = _require_string_param('subscription_id', $args{subscription_id});
  _require_present_param('query', \%args);
  my $query = _require_object_param('query', $args{query});

  _validate_subscription_query($query);
  if (
    $self->{runtime}->has_subscription(
      session_id      => $session_id,
      subscription_id => $subscription_id,
    )
  ) {
    _invalid_params(
      "Duplicate subscription_id: $subscription_id",
      {
        param           => 'subscription_id',
        subscription_id => $subscription_id,
      },
    );
  }

  $self->{runtime}->open_subscription(
    session_id      => $session_id,
    subscription_id => $subscription_id,
    query           => $query,
  );

  return {subscription_id => $subscription_id,};
}

sub close_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_param('session_id',      $args{session_id});
  my $subscription_id = _require_string_param('subscription_id', $args{subscription_id});

  if (
    !(
      $self->{runtime}->has_subscription(
        session_id      => $session_id,
        subscription_id => $subscription_id,
      )
    )
  ) {
    _invalid_params(
      "Unknown subscription_id: $subscription_id",
      {
        param           => 'subscription_id',
        subscription_id => $subscription_id,
      },
    );
  }

  $self->{runtime}->close_subscription(
    session_id      => $session_id,
    subscription_id => $subscription_id,
  );

  return {};
}

sub publish_nostr_event {
  my ($self, %args) = @_;
  my $relay_url = _require_string_param('relay_url', $args{relay_url});
  _require_present_param('event', \%args);
  my $event = _require_object_param('event', $args{event});

  my %publish_args = (
    relay_url => $relay_url,
    event     => $event,
  );
  if (exists $args{timeout_ms}) {
    $publish_args{timeout_ms} =
      _require_positive_integer_param('timeout_ms', $args{timeout_ms});
  }

  return $self->{runtime}->publish_nostr_event(%publish_args);
}

sub open_nostr_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_param('session_id',      $args{session_id});
  my $subscription_id = _require_string_param('subscription_id', $args{subscription_id});
  my $relay_url       = _require_string_param('relay_url',       $args{relay_url});
  _require_present_param('filters', \%args);
  my $filters = _require_array_param('filters', $args{filters});

  _validate_nostr_filters($filters);
  if (
    $self->{runtime}->has_nostr_subscription(
      session_id      => $session_id,
      subscription_id => $subscription_id,
    )
  ) {
    _invalid_params(
      "Duplicate subscription_id: $subscription_id",
      {
        param           => 'subscription_id',
        subscription_id => $subscription_id,
      },
    );
  }

  my %open_args = (
    session_id      => $session_id,
    subscription_id => $subscription_id,
    relay_url       => $relay_url,
    filters         => $filters,
  );
  if (exists $args{timeout_ms}) {
    $open_args{timeout_ms} =
      _require_positive_integer_param('timeout_ms', $args{timeout_ms});
  }

  return $self->{runtime}->open_nostr_subscription(%open_args);
}

sub query_nostr_events {
  my ($self, %args) = @_;
  my $relay_url = _require_string_param('relay_url', $args{relay_url});
  my $filters   = _require_array_param('filters', $args{filters});
  if (!(@{$filters})) {
    _invalid_params('filters must be a non-empty array', {param => 'filters'},);
  }

  my %query_args = (
    relay_url => $relay_url,
    filters   => $filters,
  );
  if (exists $args{timeout_ms}) {
    $query_args{timeout_ms} =
      _require_positive_integer_param('timeout_ms', $args{timeout_ms});
  }

  return {events => $self->{runtime}->query_nostr_events(%query_args),};
}

sub read_nostr_subscription_snapshot {
  my ($self, %args) = @_;
  my $session_id      = _require_string_param('session_id',      $args{session_id});
  my $subscription_id = _require_string_param('subscription_id', $args{subscription_id});

  if (
    !(
      $self->{runtime}->has_nostr_subscription(
        session_id      => $session_id,
        subscription_id => $subscription_id,
      )
    )
  ) {
    _invalid_params(
      "Unknown subscription_id: $subscription_id",
      {
        param           => 'subscription_id',
        subscription_id => $subscription_id,
      },
    );
  }

  my %read_args = (
    session_id      => $session_id,
    subscription_id => $subscription_id,
  );
  if (exists $args{refresh}) {
    $read_args{refresh} =
      _require_boolean_param('refresh', $args{refresh});
  }

  return $self->{runtime}->read_nostr_subscription_snapshot(%read_args);
}

sub close_nostr_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_param('session_id',      $args{session_id});
  my $subscription_id = _require_string_param('subscription_id', $args{subscription_id});

  if (
    !(
      $self->{runtime}->has_nostr_subscription(
        session_id      => $session_id,
        subscription_id => $subscription_id,
      )
    )
  ) {
    _invalid_params(
      "Unknown subscription_id: $subscription_id",
      {
        param           => 'subscription_id',
        subscription_id => $subscription_id,
      },
    );
  }

  return $self->{runtime}->close_nostr_subscription(
    session_id      => $session_id,
    subscription_id => $subscription_id,
  );
}

sub schedule_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('session_id', $args{session_id});
  my $timer_id   = _require_string_param('timer_id',   $args{timer_id});

  my $has_at       = exists $args{at};
  my $has_delay_ms = exists $args{delay_ms};
  if (($has_at && $has_delay_ms) || (!$has_at && !$has_delay_ms)) {
    _invalid_params('Exactly one of at or delay_ms must be supplied', {param => 'at'},);
  }

  my %schedule_args = (
    session_id => $session_id,
    timer_id   => $timer_id,
  );
  if ($has_at) {
    $schedule_args{at} = _require_integer_param('at', $args{at});
  } else {
    $schedule_args{delay_ms} =
      _require_non_negative_integer_param('delay_ms', $args{delay_ms});
  }
  if (exists $args{repeat_ms}) {
    $schedule_args{repeat_ms} =
      _require_positive_integer_param('repeat_ms', $args{repeat_ms});
  }
  if (exists $args{payload}) {
    $schedule_args{payload} =
      _require_object_param('payload', $args{payload});
  }

  if (
    $self->{runtime}->has_timer(
      session_id => $session_id,
      timer_id   => $timer_id,
    )
  ) {
    _invalid_params(
      "Duplicate timer_id: $timer_id",
      {
        param    => 'timer_id',
        timer_id => $timer_id,
      },
    );
  }

  $self->{runtime}->schedule_timer(%schedule_args);
  return {timer_id => $timer_id,};
}

sub cancel_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('session_id', $args{session_id});
  my $timer_id   = _require_string_param('timer_id',   $args{timer_id});

  if (
    !(
      $self->{runtime}->has_timer(
        session_id => $session_id,
        timer_id   => $timer_id,
      )
    )
  ) {
    _invalid_params(
      "Unknown timer_id: $timer_id",
      {
        param    => 'timer_id',
        timer_id => $timer_id,
      },
    );
  }

  $self->{runtime}->cancel_timer(
    session_id => $session_id,
    timer_id   => $timer_id,
  );
  return {};
}

sub emit_event {
  my ($self, %args) = @_;
  _require_present_param('event', \%args);
  my $event = _require_object_param('event', $args{event});

  return $self->{runtime}->accept_emitted_item(
    method    => 'overnet.emit_event',
    item_type => 'event',
    candidate => $event,
  );
}

sub emit_state {
  my ($self, %args) = @_;
  _require_present_param('state', \%args);
  my $state = _require_object_param('state', $args{state});

  return $self->{runtime}->accept_emitted_item(
    method    => 'overnet.emit_state',
    item_type => 'state',
    candidate => $state,
  );
}

sub emit_private_message {
  my ($self, %args) = @_;
  _require_present_param('message', \%args);
  my $message = _require_object_param('message', $args{message});

  return $self->{runtime}->accept_emitted_private_message(
    method    => 'overnet.emit_private_message',
    candidate => $message,
  );
}

sub emit_capabilities {
  my ($self, %args) = @_;
  _require_present_param('capabilities', \%args);
  my $capabilities = _require_array_param('capabilities', $args{capabilities});

  return $self->{runtime}->accept_emitted_capabilities(
    method       => 'overnet.emit_capabilities',
    capabilities => $capabilities,
  );
}

sub dispatch_request {
  my ($self, $method, $params, %args) = @_;

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  $params ||= {};
  if (ref($params) ne 'HASH') {
    croak "params must be an object\n";
  }

  if (!(__PACKAGE__->is_service_method($method))) {
    _protocol_unknown_method("Unknown service method: $method", {method => $method});
  }

  if (!($self->bus->has_handler($method))) {
    _service_unavailable("Runtime service method $method is not available", {method => $method},);
  }

  return $self->bus->dispatch(
    $method, $params,
    {
      session_id  => $args{session_id},
      program_id  => $args{program_id},
      permissions => $args{permissions},
    },
  );
}

sub _build_bus {
  my ($self) = @_;
  weaken(my $services = $self);

  my %service_impls = (
    'config.get'                       => {impl => 'get_config'},
    'config.describe'                  => {impl => 'describe_config'},
    'secrets.get'                      => {impl => 'get_secret', context => [qw(session_id program_id)]},
    'storage.put'                      => {impl => 'put_storage_value'},
    'storage.get'                      => {impl => 'get_storage_value'},
    'storage.delete'                   => {impl => 'delete_storage_value'},
    'storage.list'                     => {impl => 'list_storage_keys'},
    'events.append'                    => {impl => 'append_event_entry'},
    'events.read'                      => {impl => 'read_event_entries'},
    'subscriptions.open'               => {impl => 'open_subscription',  context => ['session_id']},
    'subscriptions.close'              => {impl => 'close_subscription', context => ['session_id']},
    'nostr.publish_event'              => {impl => 'publish_nostr_event'},
    'nostr.query_events'               => {impl => 'query_nostr_events'},
    'nostr.open_subscription'          => {impl => 'open_nostr_subscription',          context => ['session_id']},
    'nostr.read_subscription_snapshot' => {impl => 'read_nostr_subscription_snapshot', context => ['session_id']},
    'nostr.close_subscription'         => {impl => 'close_nostr_subscription',         context => ['session_id']},
    'timers.schedule'                  => {impl => 'schedule_timer',                   context => ['session_id']},
    'timers.cancel'                    => {impl => 'cancel_timer',                     context => ['session_id']},
    'adapters.open_session'            => {impl => 'open_adapter_session', context => [qw(session_id program_id)]},
    'adapters.map_input'               => {impl => 'map_input'},
    'adapters.derive'                  => {impl => 'derive'},
    'adapters.close_session'           => {impl => 'close_adapter_session'},
    'overnet.emit_event'               => {impl => 'emit_event'},
    'overnet.emit_state'               => {impl => 'emit_state'},
    'overnet.emit_private_message'     => {impl => 'emit_private_message'},
    'overnet.emit_capabilities'        => {impl => 'emit_capabilities'},
  );

  my $bus = Overnet::CommandBus->new(
    middleware => [
      Overnet::CommandBus->error_normalizer(code => 'program.operation_failed'),
      sub {
        my ($method, $params, $context, $next) = @_;
        Overnet::Program::Permissions->assert_method_allowed(
          method      => $method,
          permissions => $context->{permissions},
        );
        return $next->();
      },
    ],
  );

  for my $method (sort keys %service_impls) {
    my $impl         = $service_impls{$method}{impl};
    my @context_keys = @{$service_impls{$method}{context} || []};
    $bus->register(
      $method,
      sub {
        my (undef, $params, $context) = @_;
        return $services->$impl(%{$params}, map { $_ => $context->{$_} } @context_keys);
      }
    );
  }

  return $bus;
}

sub _call_adapter {
  my (%args)  = @_;
  my $session = $args{session};
  my $method  = $args{method};
  my $code    = $args{code};

  my $result;
  my $error;
  eval {
    $result = $code->();
    1;
  } or $error = $EVAL_ERROR;

  if ($error) {
    if (ref($error) eq 'HASH') {
      CORE::die $error;
    }

    chomp $error;
    _service_unavailable(
      $error,
      {
        method     => $method,
        adapter_id => $session->adapter_id,
      },
    );
  }

  return {
    adapter_id => $session->adapter_id,
    method     => $method,
    result     => $result,
  };
}

sub _normalize_adapter_result {
  my (%args)     = @_;
  my $result     = $args{result};
  my $adapter_id = $args{adapter_id};
  my $method     = $args{method};

  if (ref($result) ne 'HASH') {
    _service_unavailable(
      'Adapter result must be an object',
      {
        method     => $method,
        adapter_id => $adapter_id,
      },
    );
  }

  if (exists $result->{valid} && !$result->{valid}) {
    my $message =
         defined $result->{reason}
      && !ref($result->{reason})
      && length($result->{reason})
      ? $result->{reason}
      : 'Adapter rejected request';
    _invalid_params(
      $message,
      {
        method     => $method,
        adapter_id => $adapter_id,
      },
    );
  }

  my %normalized;
  if (exists $result->{events}) {
    $normalized{events} = _normalized_result_array(
      name       => 'events',
      value      => $result->{events},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }
  if (exists $result->{state}) {
    $normalized{state} = _normalized_result_array(
      name       => 'state',
      value      => $result->{state},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }
  if (exists $result->{view}) {
    $normalized{view} = _normalized_result_array(
      name       => 'view',
      value      => $result->{view},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }
  if (exists $result->{admission}) {
    $normalized{admission} = _normalized_result_array(
      name       => 'admission',
      value      => $result->{admission},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }
  if (exists $result->{permission}) {
    $normalized{permission} = _normalized_result_array(
      name       => 'permission',
      value      => $result->{permission},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }
  if (exists $result->{capabilities}) {
    $normalized{capabilities} = _normalized_result_array(
      name       => 'capabilities',
      value      => $result->{capabilities},
      adapter_id => $adapter_id,
      method     => $method,
    );
    _validate_adapter_capability_items(
      capabilities => $normalized{capabilities},
      adapter_id   => $adapter_id,
      method       => $method,
    );
  }

  if (exists $result->{event}) {
    if (ref($result->{event}) ne 'HASH') {
      _service_unavailable(
        'Adapter event result must be an object',
        {
          method     => $method,
          adapter_id => $adapter_id,
        },
      );
    }

    if (($result->{event}{kind} || 0) == 37_800) {
      $normalized{state} ||= [];
      push @{$normalized{state}}, $result->{event};
    } else {
      $normalized{events} ||= [];
      push @{$normalized{events}}, $result->{event};
    }
  }

  return \%normalized;
}

sub _normalized_result_array {
  my (%args) = @_;
  my $name   = $args{name};
  my $value  = $args{value};

  if (!(ref($value) eq 'ARRAY')) {
    _service_unavailable(
      "Adapter $name result must be an array",
      {
        method     => $args{method},
        adapter_id => $args{adapter_id},
      },
    );
  }

  for my $item (@{$value}) {
    if (!(ref($item) eq 'HASH')) {
      _service_unavailable(
        "Adapter $name items must be objects",
        {
          method     => $args{method},
          adapter_id => $args{adapter_id},
        },
      );
    }
  }

  return [@{$value}];
}

sub _validate_adapter_capability_items {
  my (%args)       = @_;
  my $capabilities = $args{capabilities};
  my $adapter_id   = $args{adapter_id};
  my $method       = $args{method};

  for my $index (0 .. $#{$capabilities || []}) {
    my $capability = $capabilities->[$index];
    my $path       = "capabilities[$index]";

    if (!(defined $capability->{name} && !ref($capability->{name}) && length($capability->{name}))) {
      _service_unavailable(
        "Adapter $path.name must be a non-empty string",
        {
          method     => $method,
          adapter_id => $adapter_id,
        },
      );
    }

    if (!(defined $capability->{version} && !ref($capability->{version}) && length($capability->{version}))) {
      _service_unavailable(
        "Adapter $path.version must be a non-empty string",
        {
          method     => $method,
          adapter_id => $adapter_id,
        },
      );
    }

    if (exists $capability->{details}
      && ref($capability->{details}) ne 'HASH') {
      _service_unavailable(
        "Adapter $path.details must be an object",
        {
          method     => $method,
          adapter_id => $adapter_id,
        },
      );
    }
  }

  return 1;
}

sub _require_adapter_session {
  my ($runtime, $session_id) = @_;
  my $session = $runtime->get_adapter_session($session_id);

  if (!(defined $session)) {
    _invalid_params(
      "Unknown adapter_session_id: $session_id",
      {
        param              => 'adapter_session_id',
        adapter_session_id => $session_id,
      },
    );
  }

  return $session;
}

sub _require_storage_key {
  my ($runtime, $key) = @_;

  if (!($runtime->has_document(key => $key))) {
    _invalid_params(
      "Unknown key: $key",
      {
        param => 'key',
        key   => $key,
      },
    );
  }

  return 1;
}

sub _validate_nostr_filters {
  my ($filters) = @_;

  if (!(ref($filters) eq 'ARRAY' && @{$filters})) {
    _invalid_params('filters must be a non-empty array', {param => 'filters'},);
  }

  for my $index (0 .. $#{$filters}) {
    if (ref($filters->[$index]) ne 'HASH') {
      _invalid_params("filters[$index] must be an object", {param => "filters.$index"},);
    }
  }

  return 1;
}

sub _require_dispatch_session_id {
  my (%args)     = @_;
  my $method     = $args{method};
  my $session_id = $args{session_id};

  if (!(defined $session_id && !ref($session_id) && length($session_id))) {
    _service_unavailable("Runtime service method $method requires session context", {method => $method},);
  }

  return $session_id;
}

sub _require_present_param {
  my ($name, $params) = @_;
  if (!(exists $params->{$name})) {
    _invalid_params("$name is required", {param => $name});
  }
  return 1;
}

sub _require_string_param {
  my ($name, $value) = @_;
  if (!(defined $value && !ref($value) && length($value))) {
    _invalid_params("$name is required", {param => $name});
  }
  return $value;
}

sub _require_optional_string_param {
  my ($name, $value) = @_;
  if (!defined $value || ref($value)) {
    _invalid_params("$name must be a string", {param => $name});
  }
  return $value;
}

sub _require_object_param {
  my ($name, $value) = @_;
  if (ref($value) ne 'HASH') {
    _invalid_params("$name must be an object", {param => $name});
  }
  return $value;
}

sub _require_array_param {
  my ($name, $value) = @_;
  if (ref($value) ne 'ARRAY') {
    _invalid_params("$name must be an array", {param => $name});
  }
  return $value;
}

sub _require_secret_handle_map_param {
  my ($name, $value) = @_;

  if (ref($value) ne 'HASH') {
    _invalid_params("$name must be an object", {param => $name});
  }

  my %validated;
  for my $slot (sort keys %{$value}) {
    if (!defined($slot) || !length($slot)) {
      _invalid_params("$name slot names must be non-empty strings", {param => $name});
    }

    my $handle = $value->{$slot};
    if (ref($handle) ne 'HASH') {
      _invalid_params("$name.$slot must be an object", {param => "$name.$slot"});
    }
    if (!(defined $handle->{id} && !ref($handle->{id}) && length($handle->{id}))) {
      _invalid_params("$name.$slot.id must be a non-empty string", {param => "$name.$slot.id"});
    }
    if (
      exists $handle->{expires_at}
      && (!defined($handle->{expires_at})
        || ref($handle->{expires_at})
        || $handle->{expires_at} !~ /\A-?\d+\z/mxs)
    ) {
      _invalid_params("$name.$slot.expires_at must be an integer", {param => "$name.$slot.expires_at"});
    }

    $validated{$slot} = {
      id => $handle->{id},
      (
        exists $handle->{expires_at}
        ? (expires_at => 0 + $handle->{expires_at})
        : ()
      ),
    };
  }

  return \%validated;
}

sub _require_integer_param {
  my ($name, $value) = @_;
  if (!(defined $value && !ref($value) && $value =~ /\A-?\d+\z/mxs)) {
    _invalid_params("$name must be an integer", {param => $name});
  }
  return 0 + $value;
}

sub _require_non_negative_integer_param {
  my ($name, $value) = @_;
  if (!(defined $value && !ref($value) && $value =~ /\A\d+\z/mxs)) {
    _invalid_params("$name must be a non-negative integer", {param => $name});
  }
  return 0 + $value;
}

sub _require_positive_integer_param {
  my ($name, $value) = @_;
  if (!(defined $value && !ref($value) && $value =~ /\A[1-9]\d*\z/mxs)) {
    _invalid_params("$name must be a positive integer", {param => $name});
  }
  return 0 + $value;
}

sub _require_boolean_param {
  my ($name, $value) = @_;
  if (JSON::is_bool($value)) {
    return $value ? 1 : 0;
  }
  if (defined $value && !ref($value) && ($value eq '0' || $value eq '1')) {
    return 0 + $value;
  }
  _invalid_params("$name must be 0 or 1", {param => $name});
  return;
}

sub _validate_subscription_query {
  my ($query) = @_;
  my %allowed = map { $_ => 1 } qw(kind overnet_et overnet_ot overnet_oid);

  for my $field (sort keys %{$query}) {
    if (!($allowed{$field})) {
      _invalid_params("query contains unsupported field: $field", {param => "query.$field"},);
    }
  }

  if (exists $query->{kind}) {
    if (!(defined $query->{kind} && !ref($query->{kind}) && $query->{kind} =~ /\A-?\d+\z/mxs)) {
      _invalid_params('query.kind must be an integer', {param => 'query.kind'},);
    }
  }

  for my $field (qw(overnet_et overnet_ot overnet_oid)) {
    if (!(exists $query->{$field})) {
      next;
    }
    if (!(defined $query->{$field} && !ref($query->{$field}) && length($query->{$field}))) {
      _invalid_params("query.$field must be a non-empty string", {param => "query.$field"},);
    }
  }

  return 1;
}

sub _invalid_params {
  my ($message, $details) = @_;
  CORE::die {
    code    => 'protocol.invalid_params',
    message => $message,
    (defined $details ? (details => $details) : ()),
  };

  return;
}

sub _protocol_unknown_method {
  my ($message, $details) = @_;
  CORE::die {
    code    => 'protocol.unknown_method',
    message => $message,
    (defined $details ? (details => $details) : ()),
  };

  return;
}

sub _service_unavailable {
  my ($message, $details) = @_;
  CORE::die {
    code    => 'runtime.service_unavailable',
    message => $message,
    (defined $details ? (details => $details) : ()),
  };

  return;
}

1;

=head1 NAME

Overnet::Program::Services - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Services;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 runtime

Public API entry point.

=head2 bus

Public API entry point.

=head2 is_service_method

Public API entry point.

=head2 service_methods

Public API entry point.

=head2 get_config

Public API entry point.

=head2 describe_config

Public API entry point.

=head2 get_secret

Public API entry point.

=head2 open_adapter_session

Public API entry point.

=head2 map_input

Public API entry point.

=head2 derive

Public API entry point.

=head2 close_adapter_session

Public API entry point.

=head2 put_storage_value

Public API entry point.

=head2 get_storage_value

Public API entry point.

=head2 delete_storage_value

Public API entry point.

=head2 list_storage_keys

Public API entry point.

=head2 append_event_entry

Public API entry point.

=head2 read_event_entries

Public API entry point.

=head2 open_subscription

Public API entry point.

=head2 close_subscription

Public API entry point.

=head2 publish_nostr_event

Public API entry point.

=head2 open_nostr_subscription

Public API entry point.

=head2 query_nostr_events

Public API entry point.

=head2 read_nostr_subscription_snapshot

Public API entry point.

=head2 close_nostr_subscription

Public API entry point.

=head2 schedule_timer

Public API entry point.

=head2 cancel_timer

Public API entry point.

=head2 emit_event

Public API entry point.

=head2 emit_state

Public API entry point.

=head2 emit_private_message

Public API entry point.

=head2 emit_capabilities

Public API entry point.

=head2 dispatch_request

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
