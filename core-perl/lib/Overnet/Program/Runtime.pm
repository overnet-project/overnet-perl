package Overnet::Program::Runtime;

use strictures 2;
use Moo;
use Carp       qw(croak);
use English    qw(-no_match_vars);
use JSON       ();
use List::Util qw(any);
use Net::Nostr::Event;
use Time::HiRes qw(time);
use Overnet::Core::Nostr;
use Overnet::Core::PrivateMessaging ();
use Overnet::Core::Validator        ();
use Overnet::Program::AdapterRegistry;
use Overnet::Program::AdapterSession;
use Overnet::Program::SecretProvider;
use Overnet::Program::Store;
use Overnet::Program::Subscription;
use Overnet::Program::Timer;

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;

has adapter_registry      => (is => 'ro', reader   => '_adapter_registry');
has store                 => (is => 'ro', reader   => '_store');
has secret_provider       => (is => 'ro', reader   => '_secret_provider');
has now_cb                => (is => 'ro', reader   => '_now_cb');
has config                => (is => 'ro', reader   => '_raw_config');
has config_description    => (is => 'ro', reader   => '_raw_config_description');
has next_session_id       => (is => 'rw', accessor => '_next_session_id_value');
has adapter_sessions      => (is => 'rw', accessor => '_adapter_sessions');
has timers                => (is => 'rw', accessor => '_timers');
has emitted_items         => (is => 'rw', accessor => '_emitted_items');
has subscriptions         => (is => 'rw', accessor => '_subscriptions');
has nostr_subscriptions   => (is => 'rw', accessor => '_nostr_subscriptions');
has runtime_notifications => (is => 'rw', accessor => '_runtime_notifications');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args             = _constructor_args_hash(@args);
  my $adapter_registry = $args{adapter_registry} || Overnet::Program::AdapterRegistry->new;
  my $store            = $args{store}            || Overnet::Program::Store->new;
  my $now_cb           = $args{now_cb}           || sub { int(time() * 1000) };
  my $secret_provider  = $args{secret_provider};
  my $config           = exists $args{config} ? $args{config} : {};
  my $config_description =
    exists $args{config_description} ? $args{config_description} : {};

  _validate_runtime_new_args(
    adapter_registry   => $adapter_registry,
    store              => $store,
    now_cb             => $now_cb,
    config             => $config,
    config_description => $config_description,
    args               => \%args,
  );
  $secret_provider = _build_secret_provider($secret_provider, $now_cb, \%args);

  _validate_config_description($config_description);

  return {
    adapter_registry      => $adapter_registry,
    store                 => $store,
    secret_provider       => $secret_provider,
    now_cb                => $now_cb,
    config                => _clone_json($config),
    config_description    => _clone_json($config_description),
    next_session_id       => 1,
    adapter_sessions      => {},
    timers                => {},
    emitted_items         => [],
    subscriptions         => {},
    nostr_subscriptions   => {},
    runtime_notifications => {},
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub adapter_registry {
  my ($self) = @_;
  return $self->{adapter_registry};
}

sub store {
  my ($self) = @_;
  return $self->{store};
}

sub secret_provider {
  my ($self) = @_;
  return $self->{secret_provider};
}

sub config {
  my ($self) = @_;
  return _clone_json($self->{config});
}

sub describe_config {
  my ($self) = @_;
  return _clone_json($self->{config_description});
}

sub has_secret {
  my ($self, %args) = @_;
  return $self->{secret_provider}->has_secret(%args);
}

sub issue_secret_handle {
  my ($self, %args) = @_;
  return $self->{secret_provider}->issue_secret_handle(%args);
}

sub resolve_secret_handle {
  my ($self, %args) = @_;
  return $self->{secret_provider}->resolve_secret_handle(%args);
}

sub revoke_secret_handle {
  my ($self, %args) = @_;
  return $self->{secret_provider}->revoke_secret_handle(%args);
}

sub revoke_secret_handles_for_session {
  my ($self, %args) = @_;
  return $self->{secret_provider}->revoke_secret_handles_for_session(%args);
}

sub rotate_secret {
  my ($self, %args) = @_;
  return $self->{secret_provider}->rotate_secret(%args);
}

sub secret_audit_events {
  my ($self) = @_;
  return $self->{secret_provider}->audit_events;
}

sub emitted_items {
  my ($self) = @_;
  return [@{$self->{emitted_items} || []}];
}

sub emitted_stream_name {
  my ($self, $item_type) = @_;

  if (
    !(
      defined $item_type && !ref($item_type) && ($item_type eq 'event'
        || $item_type eq 'state'
        || $item_type eq 'private_message'
        || $item_type eq 'capability')
    )
  ) {
    croak "item_type must be event, state, private_message, or capability\n";
  }

  return "runtime.accepted.$item_type";
}

sub register_adapter {
  my ($self, %args) = @_;
  return $self->{adapter_registry}->register(%args);
}

sub register_adapter_definition {
  my ($self, %args) = @_;
  return $self->{adapter_registry}->register_definition(%args);
}

sub open_adapter_session {
  my ($self, %args) = @_;

  my $adapter_id = $args{adapter_id};
  my $config     = $args{config} || {};
  my $secret_handles =
    exists $args{secret_handles} ? $args{secret_handles} : {};
  my $program_session_id = $args{session_id};
  my $program_id         = $args{program_id};

  _validate_open_adapter_session_args(
    adapter_id         => $adapter_id,
    config             => $config,
    secret_handles     => $secret_handles,
    program_session_id => $program_session_id,
    program_id         => $program_id,
  );

  my $adapter = $self->_build_adapter_for_session($adapter_id, $secret_handles);

  my $session_id = 'adapter-' . $self->{next_session_id}++;
  my $session    = Overnet::Program::AdapterSession->new(
    session_id         => $session_id,
    adapter_id         => $adapter_id,
    adapter            => $adapter,
    config             => $config,
    program_session_id => $program_session_id,
    program_id         => $program_id,
  );

  my %resolved_secret_values;
  eval {
    %resolved_secret_values = $self->_resolve_session_secret_values(
      adapter_id         => $adapter_id,
      secret_handles     => $secret_handles,
      program_session_id => $program_session_id,
      program_id         => $program_id,
    );
    $session->open_session(secret_values => \%resolved_secret_values);
    1;
  } or do {
    my $error = $EVAL_ERROR;
    _clear_secret_values(\%resolved_secret_values);
    if (ref($error) eq 'HASH') {
      CORE::die $error;
    }

    if (!ref($error)) {
      chomp $error;
    }
    CORE::die {
      code    => 'runtime.service_unavailable',
      message => $error,
      details => {
        method     => 'adapters.open_session',
        adapter_id => $adapter_id,
      },
    };
  };
  _clear_secret_values(\%resolved_secret_values);

  $self->{adapter_sessions}{$session_id} = $session;
  return $session;
}

sub _validate_runtime_new_args {
  my (%args) = @_;
  if (!(ref($args{adapter_registry}) && $args{adapter_registry}->isa('Overnet::Program::AdapterRegistry'))) {
    croak "adapter_registry must be an Overnet::Program::AdapterRegistry instance\n";
  }
  if (!(ref($args{store}) && $args{store}->isa('Overnet::Program::Store'))) {
    croak "store must be an Overnet::Program::Store instance\n";
  }
  if (!(ref($args{now_cb}) eq 'CODE')) {
    croak "now_cb must be a code reference\n";
  }
  _validate_runtime_config_args(%args);
  _validate_runtime_secret_provider_args($args{args});
  return;
}

sub _validate_runtime_config_args {
  my (%args) = @_;
  if (!(ref($args{config}) eq 'HASH')) {
    croak "config must be an object\n";
  }
  if (!(ref($args{config_description}) eq 'HASH')) {
    croak "config_description must be an object\n";
  }
  return;
}

sub _validate_runtime_secret_provider_args {
  my ($args) = @_;
  if (exists $args->{host}) {
    croak "host is reserved for process supervision; use secret_provider instead\n";
  }
  return;
}

sub _build_secret_provider {
  my ($secret_provider, $now_cb, $args) = @_;
  if (defined $secret_provider) {
    _validate_supplied_secret_provider($secret_provider, $args);
    return $secret_provider;
  }
  return Overnet::Program::SecretProvider->new(
    now_cb => $now_cb,
    _secret_provider_constructor_args($args),
  );
}

sub _validate_supplied_secret_provider {
  my ($secret_provider, $args) = @_;
  if (!(ref($secret_provider) && $secret_provider->isa('Overnet::Program::SecretProvider'))) {
    croak "secret_provider must be an Overnet::Program::SecretProvider instance\n";
  }
  for my $field (qw(secrets secret_policies secret_handle_ttl_ms random_bytes_cb)) {
    if (exists $args->{$field}) {
      croak "$field cannot be supplied when secret_provider is provided\n";
    }
  }
  return;
}

sub _secret_provider_constructor_args {
  my ($args) = @_;
  my @constructor_args;
  for my $field (qw(secrets secret_policies secret_handle_ttl_ms random_bytes_cb)) {
    if (exists $args->{$field}) {
      push @constructor_args, $field => $args->{$field};
    }
  }
  return @constructor_args;
}

sub _validate_open_adapter_session_args {
  my (%args) = @_;
  if (!(defined $args{adapter_id} && !ref($args{adapter_id}) && length($args{adapter_id}))) {
    croak "adapter_id is required\n";
  }
  if (ref($args{config}) ne 'HASH') {
    croak "config must be an object\n";
  }
  if (ref($args{secret_handles}) ne 'HASH') {
    croak "secret_handles must be an object\n";
  }
  _validate_open_adapter_program_args(%args);
  return;
}

sub _validate_open_adapter_program_args {
  my (%args) = @_;
  if (keys(%{$args{secret_handles}}) && !(_is_non_empty_string($args{program_session_id}))) {
    croak "session_id is required when secret_handles are supplied\n";
  }
  if (defined $args{program_id} && !_is_non_empty_string($args{program_id})) {
    croak "program_id must be a non-empty string\n";
  }
  return;
}

sub _is_non_empty_string {
  my ($value) = @_;
  return defined $value && !ref($value) && length($value) ? 1 : 0;
}

sub _build_adapter_for_session {
  my ($self, $adapter_id, $secret_handles) = @_;
  my $adapter = $self->{adapter_registry}->build($adapter_id);
  if (!(defined $adapter)) {
    croak "Unknown adapter_id: $adapter_id\n";
  }
  if (keys %{$secret_handles}) {
    _require_adapter_secret_slot_support(
      adapter    => $adapter,
      adapter_id => $adapter_id,
      slots      => [sort keys %{$secret_handles}],
    );
  }
  return $adapter;
}

sub _resolve_session_secret_values {
  my ($self, %args) = @_;
  my %resolved_secret_values;
  for my $slot (sort keys %{$args{secret_handles}}) {
    my $handle = $args{secret_handles}{$slot};
    _validate_secret_handle($slot, $handle);
    my $resolved = $self->resolve_secret_handle(
      session_id => $args{program_session_id},
      handle_id  => $handle->{id},
      (defined $args{program_id} ? (program_id => $args{program_id}) : ()),
      method      => 'adapters.open_session',
      adapter_id  => $args{adapter_id},
      secret_slot => $slot,
      purpose     => "adapters.open_session:$args{adapter_id}:$slot",
      error_param => "secret_handles.$slot",
    );
    $resolved_secret_values{$slot} = $resolved->{value};
  }
  return %resolved_secret_values;
}

sub _validate_secret_handle {
  my ($slot, $handle) = @_;
  if (!(ref($handle) eq 'HASH')) {
    CORE::die {
      code    => 'protocol.invalid_params',
      message => "secret_handles.$slot must be a secret_handle object",
      details => {
        param => "secret_handles.$slot",
      },
    };
  }
  if (!(defined $handle->{id} && !ref($handle->{id}) && length($handle->{id}))) {
    CORE::die {
      code    => 'protocol.invalid_params',
      message => "secret_handles.$slot.id must be a non-empty string",
      details => {
        param => "secret_handles.$slot.id",
      },
    };
  }
  return;
}

sub get_adapter_session {
  my ($self, $session_id) = @_;
  if (!(defined $session_id)) {
    return;
  }
  return $self->{adapter_sessions}{$session_id};
}

sub close_adapter_session {
  my ($self, $session_id) = @_;
  if (!(defined $session_id && !ref($session_id) && length($session_id))) {
    croak "adapter_session_id is required\n";
  }

  my $session = $self->{adapter_sessions}{$session_id};
  if (!(defined $session)) {
    croak "Unknown adapter_session_id: $session_id\n";
  }

  $session->close_session;
  delete $self->{adapter_sessions}{$session_id};

  return 1;
}

sub adapter_session_ids {
  my ($self) = @_;
  return [sort keys %{$self->{adapter_sessions}}];
}

sub release_session_resources {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});

  my %released = (
    adapter_sessions_closed    => 0,
    subscriptions_closed       => 0,
    nostr_subscriptions_closed => 0,
    timers_canceled            => 0,
    notifications_cleared      => 0,
    secret_handles_revoked     => 0,
  );

  for my $adapter_session_id (sort keys %{$self->{adapter_sessions}}) {
    my $session = $self->{adapter_sessions}{$adapter_session_id};
    if (!(defined $session)) {
      next;
    }
    if (!(defined $session->program_session_id)) {
      next;
    }
    if (!($session->program_session_id eq $session_id)) {
      next;
    }

    my $closed_ok   = eval { $session->close_session; 1; };
    my $close_error = $EVAL_ERROR;
    if (!$closed_ok && $close_error) {
      undef $close_error;
    }
    delete $self->{adapter_sessions}{$adapter_session_id};
    $released{adapter_sessions_closed}++;
  }

  if (exists $self->{subscriptions}{$session_id}) {
    $released{subscriptions_closed} =
      scalar keys %{$self->{subscriptions}{$session_id} || {}};
    delete $self->{subscriptions}{$session_id};
  }

  if (exists $self->{nostr_subscriptions}{$session_id}) {
    $released{nostr_subscriptions_closed} =
      scalar keys %{$self->{nostr_subscriptions}{$session_id} || {}};
    delete $self->{nostr_subscriptions}{$session_id};
  }

  if (exists $self->{timers}{$session_id}) {
    $released{timers_canceled} =
      scalar keys %{$self->{timers}{$session_id} || {}};
    delete $self->{timers}{$session_id};
  }

  if (exists $self->{runtime_notifications}{$session_id}) {
    $released{notifications_cleared} =
      scalar @{$self->{runtime_notifications}{$session_id} || []};
    delete $self->{runtime_notifications}{$session_id};
  }

  # A session released here may have terminated abnormally (crash, kill, EOF)
  # without an orderly runtime.shutdown, so revoke its outstanding secret
  # handles rather than leaving them live until TTL expiry (services spec 5.10).
  $released{secret_handles_revoked} = $self->revoke_secret_handles_for_session(session_id => $session_id);

  return \%released;
}

sub append_event {
  my ($self, %args) = @_;
  return $self->{store}->append_event(%args);
}

sub read_events {
  my ($self, %args) = @_;
  return $self->{store}->read_events(%args);
}

sub has_document {
  my ($self, %args) = @_;
  return $self->{store}->has_document(%args);
}

sub put_document {
  my ($self, %args) = @_;
  return $self->{store}->put_document(%args);
}

sub get_document {
  my ($self, %args) = @_;
  return $self->{store}->get_document(%args);
}

sub delete_document {
  my ($self, %args) = @_;
  return $self->{store}->delete_document(%args);
}

sub list_documents {
  my ($self, %args) = @_;
  return $self->{store}->list_documents(%args);
}

sub has_subscription {
  my ($self, %args) = @_;
  my $session_id      = $args{session_id};
  my $subscription_id = $args{subscription_id};

  if (!(defined $session_id && defined $subscription_id)) {
    return 0;
  }
  return exists $self->{subscriptions}{$session_id} && exists $self->{subscriptions}{$session_id}{$subscription_id}
    ? 1
    : 0;
}

sub has_nostr_subscription {
  my ($self, %args) = @_;
  my $session_id      = $args{session_id};
  my $subscription_id = $args{subscription_id};

  if (!(defined $session_id && defined $subscription_id)) {
    return 0;
  }
  return exists $self->{nostr_subscriptions}{$session_id}
    && exists $self->{nostr_subscriptions}{$session_id}{$subscription_id}
    ? 1
    : 0;
}

sub has_timer {
  my ($self, %args) = @_;
  my $session_id = $args{session_id};
  my $timer_id   = $args{timer_id};

  if (!(defined $session_id && defined $timer_id)) {
    return 0;
  }
  return exists $self->{timers}{$session_id} && exists $self->{timers}{$session_id}{$timer_id}
    ? 1
    : 0;
}

sub schedule_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $timer_id   = _require_string_arg(timer_id   => $args{timer_id});
  my $repeat_ms  = $args{repeat_ms};
  my $payload    = $args{payload};

  if (
    $self->has_timer(
      session_id => $session_id,
      timer_id   => $timer_id,
    )
  ) {
    croak "Duplicate timer_id: $timer_id\n";
  }
  if (defined $repeat_ms
    && (ref($repeat_ms) || $repeat_ms !~ /\A[1-9]\d*\z/mxs)) {
    croak "repeat_ms must be a positive integer\n";
  }
  if (defined $payload && ref($payload) ne 'HASH') {
    croak "payload must be an object\n";
  }

  my $due_at_ms;
  if (exists $args{at}) {
    my $at = $args{at};
    if (!(defined $at && !ref($at) && $at =~ /\A-?\d+\z/mxs)) {
      croak "at must be an integer\n";
    }
    $due_at_ms = (0 + $at) * 1000;
  } else {
    my $delay_ms = $args{delay_ms};
    if (!(defined $delay_ms && !ref($delay_ms) && $delay_ms =~ /\A\d+\z/mxs)) {
      croak "delay_ms must be a non-negative integer\n";
    }
    $due_at_ms = $self->_now_ms + (0 + $delay_ms);
  }

  my $timer = Overnet::Program::Timer->new(
    session_id => $session_id,
    timer_id   => $timer_id,
    due_at_ms  => $due_at_ms,
    (defined $repeat_ms ? (repeat_ms => $repeat_ms) : ()),
    (defined $payload   ? (payload   => $payload)   : ()),
  );
  $self->{timers}{$session_id}{$timer_id} = $timer;

  return $timer;
}

sub cancel_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $timer_id   = _require_string_arg(timer_id   => $args{timer_id});

  my $timer = delete $self->{timers}{$session_id}{$timer_id};
  if (!(defined $timer)) {
    croak "Unknown timer_id: $timer_id\n";
  }
  if (!(keys %{$self->{timers}{$session_id} || {}})) {
    delete $self->{timers}{$session_id};
  }

  my $queue = $self->{runtime_notifications}{$session_id} || [];
  @{$queue} = grep {
    !(   ($_->{method} || q{}) eq 'runtime.timer_fired'
      && ref($_->{params}) eq 'HASH'
      && ($_->{params}{timer_id} || q{}) eq $timer_id)
  } @{$queue};

  return 1;
}

sub open_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_arg(session_id      => $args{session_id});
  my $subscription_id = _require_string_arg(subscription_id => $args{subscription_id});
  my $query           = $args{query};

  if (!(ref($query) eq 'HASH')) {
    croak "query must be an object\n";
  }
  if (
    $self->has_subscription(
      session_id      => $session_id,
      subscription_id => $subscription_id,
    )
  ) {
    croak "Duplicate subscription_id: $subscription_id\n";
  }

  my $subscription = Overnet::Program::Subscription->new(
    session_id      => $session_id,
    subscription_id => $subscription_id,
    query           => $query,
  );
  $self->{subscriptions}{$session_id}{$subscription_id} = $subscription;

  for my $item (@{$self->{emitted_items}}) {
    my %notification_args = (
      session_id   => $session_id,
      subscription => $subscription,
      item_type    => $item->{item_type},
      data         => $item->{data},
    );
    if ($item->{item_type} eq 'event' || $item->{item_type} eq 'state') {
      $notification_args{event} = _event_from_wire($item->{data});
    }
    $self->_queue_subscription_notification_if_match(%notification_args,);
  }

  return $subscription;
}

sub close_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_arg(session_id      => $args{session_id});
  my $subscription_id = _require_string_arg(subscription_id => $args{subscription_id});

  my $subscription =
    delete $self->{subscriptions}{$session_id}{$subscription_id};
  if (!(defined $subscription)) {
    croak "Unknown subscription_id: $subscription_id\n";
  }
  if (!(keys %{$self->{subscriptions}{$session_id} || {}})) {
    delete $self->{subscriptions}{$session_id};
  }

  my $queue = $self->{runtime_notifications}{$session_id} || [];
  @{$queue} = grep {
    !(   ($_->{method} || q{}) eq 'runtime.subscription_event'
      && ref($_->{params}) eq 'HASH'
      && ($_->{params}{subscription_id} || q{}) eq $subscription_id)
  } @{$queue};

  return 1;
}

sub publish_nostr_event {
  my ($self, %args) = @_;
  my $relay_url = _require_string_arg(relay_url => $args{relay_url});
  my $event     = $args{event};

  if (!(ref($event) eq 'HASH')) {
    croak "event must be an object\n";
  }

  my %publish_args = (
    relay_url => $relay_url,
    event     => _clone_json($event),
  );
  if (exists $args{timeout_ms}) {
    my $timeout_ms = $args{timeout_ms};
    if (!(defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/mxs)) {
      croak "timeout_ms must be a positive integer\n";
    }
    $publish_args{timeout_ms} = 0 + $timeout_ms;
  }

  return Overnet::Core::Nostr->publish_event(%publish_args);
}

sub query_nostr_events {
  my ($self, %args) = @_;
  my $relay_url = _require_string_arg(relay_url => $args{relay_url});
  my $filters   = $args{filters};

  if (!(ref($filters) eq 'ARRAY' && @{$filters})) {
    croak "filters must be a non-empty array\n";
  }

  my %query_args = (
    relay_url => $relay_url,
    filters   => _clone_json($filters),
  );
  if (exists $args{timeout_ms}) {
    my $timeout_ms = $args{timeout_ms};
    if (!(defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/mxs)) {
      croak "timeout_ms must be a positive integer\n";
    }
    $query_args{timeout_ms} = 0 + $timeout_ms;
  }

  return Overnet::Core::Nostr->query_events(%query_args);
}

sub open_nostr_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_arg(session_id      => $args{session_id});
  my $subscription_id = _require_string_arg(subscription_id => $args{subscription_id});
  my $relay_url       = _require_string_arg(relay_url       => $args{relay_url});
  my $filters         = $args{filters};

  if (!(ref($filters) eq 'ARRAY' && @{$filters})) {
    croak "filters must be a non-empty array\n";
  }
  if (
    $self->has_nostr_subscription(
      session_id      => $session_id,
      subscription_id => $subscription_id,
    )
  ) {
    croak "Duplicate subscription_id: $subscription_id\n";
  }

  my $timeout_ms =
    exists $args{timeout_ms}
    ? $args{timeout_ms}
    : 250;
  if (!(defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/mxs)) {
    croak "timeout_ms must be a positive integer\n";
  }

  my $events = Overnet::Core::Nostr->query_events(
    relay_url  => $relay_url,
    filters    => _clone_json($filters),
    timeout_ms => 0 + $timeout_ms,
  );
  my %seen_ids = map { ($_->{id} || q{}) => 1 }
    grep { ref eq 'HASH' && defined $_->{id} } @{$events || []};

  $self->{nostr_subscriptions}{$session_id}{$subscription_id} = {
    session_id      => $session_id,
    subscription_id => $subscription_id,
    relay_url       => $relay_url,
    filters         => _clone_json($filters),
    timeout_ms      => 0 + $timeout_ms,
    poll_timeout_ms => (0 + $timeout_ms) > 250 ? 250 : 0 + $timeout_ms,
    snapshot        => _clone_json($events || []),
    seen_event_ids  => \%seen_ids,
  };

  return {
    subscription_id => $subscription_id,
    events          => _clone_json($events || []),
  };
}

sub read_nostr_subscription_snapshot {
  my ($self, %args) = @_;
  my $session_id      = _require_string_arg(session_id      => $args{session_id});
  my $subscription_id = _require_string_arg(subscription_id => $args{subscription_id});
  my $refresh         = $args{refresh} ? 1 : 0;

  my $subscription =
    $self->{nostr_subscriptions}{$session_id}{$subscription_id};
  if (!(ref($subscription) eq 'HASH')) {
    croak "Unknown subscription_id: $subscription_id\n";
  }

  if ($refresh) {
    $self->_refresh_nostr_subscription(
      session_id          => $session_id,
      subscription_id     => $subscription_id,
      subscription        => $subscription,
      queue_notifications => 0,
      timeout_ms          => (
        ($subscription->{timeout_ms} || 250) < 1_000
        ? 1_000
        : $subscription->{timeout_ms}
      ),
    );
  }

  return {events => _clone_json($subscription->{snapshot} || []),};
}

sub close_nostr_subscription {
  my ($self, %args) = @_;
  my $session_id      = _require_string_arg(session_id      => $args{session_id});
  my $subscription_id = _require_string_arg(subscription_id => $args{subscription_id});

  my $subscription =
    delete $self->{nostr_subscriptions}{$session_id}{$subscription_id};
  if (!(defined $subscription)) {
    croak "Unknown subscription_id: $subscription_id\n";
  }
  if (!(keys %{$self->{nostr_subscriptions}{$session_id} || {}})) {
    delete $self->{nostr_subscriptions}{$session_id};
  }

  my $queue = $self->{runtime_notifications}{$session_id} || [];
  @{$queue} = grep {
    !(   ($_->{method} || q{}) eq 'runtime.subscription_event'
      && ref($_->{params}) eq 'HASH'
      && ($_->{params}{subscription_id} || q{}) eq $subscription_id)
  } @{$queue};

  return {closed => JSON::true,};
}

sub drain_runtime_notifications {
  my ($self, $session_id) = @_;
  _require_string_arg(session_id => $session_id);
  $self->_refresh_nostr_subscriptions;
  $self->_queue_due_timer_notifications;

  my $notifications =
    delete $self->{runtime_notifications}{$session_id} || [];
  return _clone_json($notifications);
}

sub accept_emitted_private_message {
  my ($self, %args) = @_;

  my $method    = $args{method};
  my $candidate = $args{candidate};

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  if (!(ref($candidate) eq 'HASH')) {
    croak "candidate must be an object\n";
  }

  my $validation = Overnet::Core::PrivateMessaging::validate_transport($candidate);
  my @errors     = @{$validation->{errors} || []};

  if (@errors || !$validation->{valid}) {
    CORE::die {
      code    => 'runtime.validation_failed',
      message => 'Candidate private message failed validation',
      details => {
        method    => $method,
        item_type => 'private_message',
        errors    => \@errors,
      },
    };
  }

  my $visible_transport = _clone_json($candidate->{transport});
  if (ref($visible_transport) eq 'HASH') {
    delete $visible_transport->{decrypted_rumor};
  }
  my $stored = {
    transport    => $visible_transport,
    private_type => $validation->{private_type},
    object_type  => $validation->{object_type},
    object_id    => $validation->{object_id},
  };
  if (ref($validation->{decrypted_rumor}) eq 'HASH') {
    $stored->{decrypted_rumor} =
      _clone_json($validation->{decrypted_rumor});
  }
  if (defined $validation->{sender_identity}) {
    $stored->{sender_identity} = $validation->{sender_identity};
  }

  $self->_record_emitted_item(
    item_type => 'private_message',
    data      => $stored,
  );

  my $result = {accepted => JSON::true,};
  if (defined $stored->{transport}{id}) {
    $result->{event_id} = $stored->{transport}{id};
  }
  if (ref($stored->{decrypted_rumor}) eq 'HASH'
    && defined $stored->{decrypted_rumor}{id}) {
    $result->{rumor_id} = $stored->{decrypted_rumor}{id};
  }

  return $result;
}

sub accept_emitted_item {
  my ($self, %args) = @_;

  my $method    = $args{method};
  my $item_type = $args{item_type};
  my $candidate = $args{candidate};

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  if (!(defined $item_type && ($item_type eq 'event' || $item_type eq 'state'))) {
    croak "item_type must be event or state\n";
  }
  if (!(ref($candidate) eq 'HASH')) {
    croak "candidate must be an object\n";
  }

  my $validation = Overnet::Core::Validator::validate($candidate, {});
  my $event      = $validation->{event};
  my $kind =
    defined $event
    ? $event->kind
    : $candidate->{kind};
  my @errors;
  if ( $item_type eq 'state'
    && defined $kind
    && !ref($kind)
    && $kind != 37_800) {
    push @errors, 'overnet.emit_state requires kind 37800';
  }
  if ( $item_type eq 'event'
    && defined $kind
    && !ref($kind)
    && $kind == 37_800) {
    push @errors, 'overnet.emit_event does not accept kind 37800 state events';
  }
  if (!($validation->{valid})) {
    push @errors, @{$validation->{errors} || []};
  }

  if (@errors) {
    CORE::die {
      code    => 'runtime.validation_failed',
      message => "Candidate Overnet $item_type failed validation",
      details => {
        method    => $method,
        item_type => $item_type,
        errors    => \@errors,
      },
    };
  }

  my $stored = $event->to_hash;
  $self->_record_emitted_item(
    item_type => $item_type,
    data      => $stored,
    event     => $event,
  );

  my $result = {accepted => JSON::true,};
  $result->{event_id} = $event->id;

  return $result;
}

sub accept_emitted_capabilities {
  my ($self, %args) = @_;

  my $method       = $args{method};
  my $capabilities = $args{capabilities};

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  if (!(ref($capabilities) eq 'ARRAY')) {
    croak "capabilities must be an array\n";
  }

  my @errors;
  my @stored;
  for my $index (0 .. $#{$capabilities}) {
    my $capability = $capabilities->[$index];
    my $path       = "capabilities[$index]";

    if (ref($capability) ne 'HASH') {
      push @errors, "$path must be an object";
      next;
    }
    if (!defined $capability->{name}
      || ref($capability->{name})
      || !length($capability->{name})) {
      push @errors, "$path.name must be a non-empty string";
    }
    if (!defined $capability->{version}
      || ref($capability->{version})
      || !length($capability->{version})) {
      push @errors, "$path.version must be a non-empty string";
    }
    if (exists $capability->{details}
      && ref($capability->{details}) ne 'HASH') {
      push @errors, "$path.details must be an object";
    }

    push @stored, _clone_json($capability);
  }

  if (@errors) {
    CORE::die {
      code    => 'runtime.validation_failed',
      message => 'Candidate capability advertisements failed validation',
      details => {
        method    => $method,
        item_type => 'capability',
        errors    => \@errors,
      },
    };
  }

  for my $capability (@stored) {
    $self->_record_emitted_item(
      item_type => 'capability',
      data      => $capability,
    );
  }

  return {accepted => JSON::true,};
}

sub _queue_subscription_notifications_for_item {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $event     = $args{event};
  my $data      = $args{data};

  for my $session_id (sort keys %{$self->{subscriptions}}) {
    for my $subscription_id (sort keys %{$self->{subscriptions}{$session_id}}) {
      my $subscription =
        $self->{subscriptions}{$session_id}{$subscription_id};
      $self->_queue_subscription_notification_if_match(
        session_id   => $session_id,
        subscription => $subscription,
        item_type    => $item_type,
        event        => $event,
        data         => $data,
      );
    }
  }

  return 1;
}

sub _queue_subscription_notification_if_match {
  my ($self, %args) = @_;
  my $session_id   = $args{session_id};
  my $subscription = $args{subscription};
  my $item_type    = $args{item_type};
  my $event        = $args{event};
  my $data         = $args{data};

  if (!(ref($data) eq 'HASH')) {
    return 0;
  }
  if (
    !(
      $subscription->matches(
        item_type => $item_type,
        event     => $event,
        data      => $data,
      )
    )
  ) {
    return 0;
  }

  push @{$self->{runtime_notifications}{$session_id} ||= []},
    {
    method => 'runtime.subscription_event',
    params => {
      subscription_id => $subscription->subscription_id,
      item_type       => $item_type,
      data            => _clone_json($data),
    },
    };

  return 1;
}

sub _record_emitted_item {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $data      = $args{data};

  push @{$self->{emitted_items}},
    {
    item_type => $item_type,
    data      => _clone_json($data),
    };
  $self->append_event(
    stream => $self->emitted_stream_name($item_type),
    event  => $data,
  );
  $self->_queue_subscription_notifications_for_item(
    item_type => $item_type,
    data      => $data,
    (exists $args{event} ? (event => $args{event}) : ()),
  );

  return 1;
}

sub _event_from_wire {
  my ($input) = @_;
  if (!(ref($input) eq 'HASH')) {
    return;
  }

  my $event;
  eval {
    $event = Net::Nostr::Event->from_wire($input);
    1;
  } or return;

  return $event;
}

sub _now_ms {
  my ($self) = @_;
  my $now = $self->{now_cb}->();

  if (!(defined $now && !ref($now) && $now =~ /\A-?\d+\z/mxs)) {
    croak "now_cb must return an integer millisecond timestamp\n";
  }

  return 0 + $now;
}

sub _clear_secret_values {
  my ($values) = @_;
  if (!(ref($values) eq 'HASH')) {
    return 1;
  }

  for my $slot (keys %{$values}) {
    if (!(defined $values->{$slot})) {
      next;
    }
    $values->{$slot} = q{};
    delete $values->{$slot};
  }

  return 1;
}

sub _require_adapter_secret_slot_support {
  my (%args)     = @_;
  my $adapter    = $args{adapter};
  my $adapter_id = $args{adapter_id};
  my $slots      = $args{slots} || [];

  if (!($adapter->can('supported_secret_slots'))) {
    CORE::die {
      code    => 'runtime.service_unavailable',
      message => "Adapter $adapter_id does not declare secure secret input slots",
      details => {
        method     => 'adapters.open_session',
        adapter_id => $adapter_id,
      },
    };
  }

  if (!($adapter->can('open_session'))) {
    CORE::die {
      code    => 'runtime.service_unavailable',
      message => "Adapter $adapter_id does not support secure session opening",
      details => {
        method     => 'adapters.open_session',
        adapter_id => $adapter_id,
      },
    };
  }

  my $supported = $adapter->supported_secret_slots;
  if (!(ref($supported) eq 'ARRAY')) {
    CORE::die {
      code    => 'runtime.service_unavailable',
      message => "Adapter $adapter_id supported_secret_slots must return an array",
      details => {
        method     => 'adapters.open_session',
        adapter_id => $adapter_id,
      },
    };
  }
  if (any { !defined || ref || !length } @{$supported}) {
    CORE::die {
      code    => 'runtime.service_unavailable',
      message => "Adapter $adapter_id supported_secret_slots must contain non-empty strings",
      details => {
        method     => 'adapters.open_session',
        adapter_id => $adapter_id,
      },
    };
  }

  my %supported = map { $_ => 1 } @{$supported};
  for my $slot (@{$slots}) {
    if (!($supported{$slot})) {
      CORE::die {
        code    => 'protocol.invalid_params',
        message => "Unsupported secret handle slot: $slot",
        details => {
          param => "secret_handles.$slot",
        },
      };
    }
  }

  return 1;
}

sub _queue_due_timer_notifications {
  my ($self)   = @_;
  my $now_ms   = $self->_now_ms;
  my $fired_at = int($now_ms / 1000);

  for my $session_id (sort keys %{$self->{timers}}) {
    my $timers = $self->{timers}{$session_id} || {};

    for my $timer_id (sort keys %{$timers}) {
      my $timer = $timers->{$timer_id};
      if (!(defined $timer)) {
        next;
      }

      if (!($timer->is_due($now_ms))) {
        next;
      }

      push @{$self->{runtime_notifications}{$session_id} ||= []},
        {
        method => 'runtime.timer_fired',
        params => $timer->build_notification_params(
          fired_at => $fired_at,
        ),
        };

      if ($timer->is_repeating) {
        $timer->advance_after_fire_until_after($now_ms);
        next;
      }

      delete $timers->{$timer_id};
    }

    if (!(keys %{$timers})) {
      delete $self->{timers}{$session_id};
    }
  }

  return 1;
}

sub _refresh_nostr_subscriptions {
  my ($self) = @_;

  for my $session_id (sort keys %{$self->{nostr_subscriptions}}) {
    for my $subscription_id (sort keys %{$self->{nostr_subscriptions}{$session_id} || {}}) {
      my $subscription =
        $self->{nostr_subscriptions}{$session_id}{$subscription_id};
      if (!(ref($subscription) eq 'HASH')) {
        next;
      }
      $self->_refresh_nostr_subscription(
        session_id          => $session_id,
        subscription_id     => $subscription_id,
        subscription        => $subscription,
        queue_notifications => 1,
      );
    }
  }

  return 1;
}

sub _merge_nostr_snapshot_events {
  my ($old_events, $new_events) = @_;
  my @merged;
  my %seen_ids;

  for my $list ($old_events, $new_events) {
    if (!(ref($list) eq 'ARRAY')) {
      next;
    }
    for my $event (@{$list}) {
      if (!(ref($event) eq 'HASH')) {
        next;
      }
      my $event_id =
           defined($event->{id})
        && !ref($event->{id})
        && length($event->{id})
        ? $event->{id}
        : undef;
      if (defined($event_id) && $seen_ids{$event_id}++) {
        next;
      }
      push @merged, _clone_json($event);
    }
  }

  return \@merged;
}

sub _refresh_nostr_subscription {
  my ($self, %args) = @_;
  my $session_id          = $args{session_id};
  my $subscription_id     = $args{subscription_id};
  my $subscription        = $args{subscription};
  my $queue_notifications = $args{queue_notifications} ? 1 : 0;
  my $timeout_ms =
      defined $args{timeout_ms} ? $args{timeout_ms}
    : $queue_notifications      ? ($subscription->{poll_timeout_ms} || 250)
    :                             $subscription->{timeout_ms};
  if (!(ref($subscription) eq 'HASH')) {
    return [];
  }

  my $events = eval {
    Overnet::Core::Nostr->query_events(
      relay_url  => $subscription->{relay_url},
      filters    => _clone_json($subscription->{filters}),
      timeout_ms => $timeout_ms,
    );
  };
  if (!(ref($events) eq 'ARRAY')) {
    return [];
  }

  my @new_events;
  for my $event (@{$events}) {
    if (!(ref($event) eq 'HASH')) {
      next;
    }
    if (!(defined $event->{id} && !ref($event->{id}) && length($event->{id}))) {
      next;
    }
    if ($subscription->{seen_event_ids}{$event->{id}}++) {
      next;
    }
    push @new_events, _clone_json($event);
  }

  $subscription->{snapshot} =
    _merge_nostr_snapshot_events($subscription->{snapshot}, $events,);

  if ($queue_notifications) {
    for my $event (@new_events) {
      push @{$self->{runtime_notifications}{$session_id} ||= []},
        {
        method => 'runtime.subscription_event',
        params => {
          subscription_id => $subscription_id,
          item_type       => 'nostr.event',
          data            => _clone_json($event),
        },
        };
    }
  }

  return [@new_events];
}

sub _require_string_arg {
  my ($name, $value) = @_;

  if (!(defined $value && !ref($value) && length($value))) {
    croak "$name is required\n";
  }

  return $value;
}

sub _validate_config_description {
  my ($description) = @_;

  if (exists $description->{schema}
    && ref($description->{schema}) ne 'HASH') {
    croak "config_description.schema must be an object\n";
  }
  if (
    exists $description->{schema_ref}
    && (!defined $description->{schema_ref}
      || ref($description->{schema_ref})
      || !length($description->{schema_ref}))
  ) {
    croak "config_description.schema_ref must be a non-empty string\n";
  }
  if (
    exists $description->{version}
    && (!defined $description->{version}
      || ref($description->{version})
      || !length($description->{version}))
  ) {
    croak "config_description.version must be a non-empty string\n";
  }

  return 1;
}

sub _clone_json {
  my ($value) = @_;
  return $JSON->decode($JSON->encode($value));
}

1;

=head1 NAME

Overnet::Program::Runtime - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Runtime;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 adapter_registry

Public API entry point.

=head2 store

Public API entry point.

=head2 secret_provider

Public API entry point.

=head2 config

Public API entry point.

=head2 describe_config

Public API entry point.

=head2 has_secret

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

=head2 secret_audit_events

Public API entry point.

=head2 emitted_items

Public API entry point.

=head2 emitted_stream_name

Public API entry point.

=head2 register_adapter

Public API entry point.

=head2 register_adapter_definition

Public API entry point.

=head2 open_adapter_session

Public API entry point.

=head2 get_adapter_session

Public API entry point.

=head2 close_adapter_session

Public API entry point.

=head2 adapter_session_ids

Public API entry point.

=head2 release_session_resources

Public API entry point.

=head2 append_event

Public API entry point.

=head2 read_events

Public API entry point.

=head2 has_document

Public API entry point.

=head2 put_document

Public API entry point.

=head2 get_document

Public API entry point.

=head2 delete_document

Public API entry point.

=head2 list_documents

Public API entry point.

=head2 has_subscription

Public API entry point.

=head2 has_nostr_subscription

Public API entry point.

=head2 has_timer

Public API entry point.

=head2 schedule_timer

Public API entry point.

=head2 cancel_timer

Public API entry point.

=head2 open_subscription

Public API entry point.

=head2 close_subscription

Public API entry point.

=head2 publish_nostr_event

Public API entry point.

=head2 query_nostr_events

Public API entry point.

=head2 open_nostr_subscription

Public API entry point.

=head2 read_nostr_subscription_snapshot

Public API entry point.

=head2 close_nostr_subscription

Public API entry point.

=head2 drain_runtime_notifications

Public API entry point.

=head2 accept_emitted_private_message

Public API entry point.

=head2 accept_emitted_item

Public API entry point.

=head2 accept_emitted_capabilities

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
