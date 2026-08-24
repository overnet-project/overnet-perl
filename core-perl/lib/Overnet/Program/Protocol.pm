package Overnet::Program::Protocol;

use strictures 2;
use Moo;
use Carp       qw(croak);
use English    qw(-no_match_vars);
use JSON       ();
use List::Util qw(any);

our $VERSION = '0.001';
my $JSON                         = JSON->new->utf8->canonical;
my $DEFAULT_MAX_FRAME_SIZE       = 1024 * 1024;
my %VALID_MESSAGE_TYPES          = map { $_ => 1 } qw(request response notification);
my %PROGRAM_NOTIFICATION_METHODS = map { $_ => 1 } qw(
  program.hello
  program.ready
  program.log
  program.health
);
my %RUNTIME_NOTIFICATION_METHODS = map { $_ => 1 } qw(
  runtime.fatal
  runtime.subscription_event
  runtime.timer_fired
);
my %RUNTIME_REQUEST_METHODS = map { $_ => 1 } qw(
  runtime.init
  runtime.shutdown
);
my %SERVICE_REQUEST_METHODS = map { $_ => 1 } qw(
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
my %BASELINE_NOTIFICATION_METHODS = (%PROGRAM_NOTIFICATION_METHODS, %RUNTIME_NOTIFICATION_METHODS,);
my %BASELINE_REQUEST_METHODS      = (%RUNTIME_REQUEST_METHODS,      %SERVICE_REQUEST_METHODS,);

has max_frame_size => (is => 'ro');
has _buffer        => (is => 'rw');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);
  my $max_frame_size =
    exists $args{max_frame_size}
    ? $args{max_frame_size}
    : $DEFAULT_MAX_FRAME_SIZE;
  if (!(defined $max_frame_size && !ref($max_frame_size) && $max_frame_size =~ /\A[1-9]\d*\z/mxs)) {
    croak "max_frame_size must be a positive integer\n";
  }

  return {
    max_frame_size => 0 + $max_frame_size,
    _buffer        => q{},
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub buffered_bytes {
  my ($self) = @_;
  return length $self->{_buffer};
}

sub is_program_notification_method {
  my ($class, $method) = @_;
  return
       defined $method
    && !ref($method)
    && $PROGRAM_NOTIFICATION_METHODS{$method} ? 1 : 0;
}

sub is_runtime_notification_method {
  my ($class, $method) = @_;
  return
       defined $method
    && !ref($method)
    && $RUNTIME_NOTIFICATION_METHODS{$method} ? 1 : 0;
}

sub is_runtime_request_method {
  my ($class, $method) = @_;
  return
       defined $method
    && !ref($method)
    && $RUNTIME_REQUEST_METHODS{$method} ? 1 : 0;
}

sub is_service_request_method {
  my ($class, $method) = @_;
  return
       defined $method
    && !ref($method)
    && $SERVICE_REQUEST_METHODS{$method} ? 1 : 0;
}

sub service_request_methods {
  my @methods = sort keys %SERVICE_REQUEST_METHODS;
  return @methods;
}

sub encode_message {
  my ($self, $message) = @_;
  _assert_message_object($message);

  my $json   = $JSON->encode($message);
  my $length = length $json;

  if ($length > $self->{max_frame_size}) {
    croak "Protocol frame exceeds maximum size\n";
  }

  return $length . "\n" . $json;
}

sub validate_message {
  my ($self, $message) = @_;
  _assert_message_object($message);

  my $type = $message->{type};
  if (!(defined $type && !ref($type) && length($type))) {
    return (0, 'protocol.invalid_message', 'Message type is required');
  }
  if (!($VALID_MESSAGE_TYPES{$type})) {
    return (0, 'protocol.unknown_message_type', "Unknown message type: $type");
  }

  if ($type eq 'request') {
    return _validate_request($message);
  } elsif ($type eq 'response') {
    return _validate_response($message);
  } else {
    return _validate_notification($message);
  }
}

sub encode_request {
  my ($self, %args) = @_;
  my $message = build_request(%args);
  return $self->encode_message($message);
}

sub encode_response_ok {
  my ($self, %args) = @_;
  my $message = build_response_ok(%args);
  return $self->encode_message($message);
}

sub encode_response_error {
  my ($self, %args) = @_;
  my $message = build_response_error(%args);
  return $self->encode_message($message);
}

sub encode_notification {
  my ($self, %args) = @_;
  my $message = build_notification(%args);
  return $self->encode_message($message);
}

sub build_request {
  my (%args) = @_;
  _require_string_field(id     => $args{id});
  _require_string_field(method => $args{method});
  _require_object_field_optional(params => $args{params});

  return {
    type   => 'request',
    id     => $args{id},
    method => $args{method},
    params => $args{params} || {},
  };
}

sub build_response_ok {
  my (%args) = @_;
  _require_string_field(id => $args{id});
  _require_object_field_optional(result => $args{result});

  return {
    type   => 'response',
    id     => $args{id},
    ok     => JSON::true,
    result => $args{result} || {},
  };
}

sub build_response_error {
  my (%args) = @_;
  _require_string_field(id      => $args{id});
  _require_string_field(code    => $args{code});
  _require_string_field(message => $args{message});
  _require_object_field_optional(details => $args{details});

  my $error = {
    code    => $args{code},
    message => $args{message},
  };
  if (defined $args{details}) {
    $error->{details} = $args{details};
  }

  return {
    type  => 'response',
    id    => $args{id},
    ok    => JSON::false,
    error => $error,
  };
}

sub build_notification {
  my (%args) = @_;
  _require_string_field(method => $args{method});
  _require_object_field_optional(params => $args{params});

  return {
    type   => 'notification',
    method => $args{method},
    params => $args{params} || {},
  };
}

sub build_program_hello {
  my (%args) = @_;
  _require_string_field(program_id => $args{program_id});
  _require_string_array_field(supported_protocol_versions => $args{supported_protocol_versions});
  _require_string_field_optional(program_version => $args{program_version});
  _require_object_field_optional(metadata => $args{metadata});

  my %params = (
    program_id                  => $args{program_id},
    supported_protocol_versions => $args{supported_protocol_versions},
  );
  if (defined $args{program_version}) {
    $params{program_version} = $args{program_version};
  }
  if (defined $args{metadata}) {
    $params{metadata} = $args{metadata};
  }

  return build_notification(
    method => 'program.hello',
    params => \%params,
  );
}

sub build_runtime_init {
  my (%args) = @_;
  _require_string_field(id               => $args{id});
  _require_string_field(protocol_version => $args{protocol_version});
  _require_string_field(instance_id      => $args{instance_id});
  _require_string_field(program_id       => $args{program_id});
  _require_array_field(permissions => $args{permissions});
  _require_object_field(config   => $args{config});
  _require_object_field(services => $args{services});

  return build_request(
    id     => $args{id},
    method => 'runtime.init',
    params => {
      protocol_version => $args{protocol_version},
      instance_id      => $args{instance_id},
      program_id       => $args{program_id},
      config           => $args{config},
      permissions      => $args{permissions},
      services         => $args{services},
    },
  );
}

sub build_program_ready {
  my (%args) = @_;
  _require_object_field_optional(params => $args{params});
  return build_notification(
    method => 'program.ready',
    params => $args{params} || {},
  );
}

sub build_runtime_fatal {
  my (%args) = @_;
  _require_string_field(code    => $args{code});
  _require_string_field(message => $args{message});
  _require_string_field_optional(phase => $args{phase});
  _require_object_field_optional(details => $args{details});

  my %params = (
    code    => $args{code},
    message => $args{message},
  );
  if (defined $args{phase}) {
    $params{phase} = $args{phase};
  }
  if (defined $args{details}) {
    $params{details} = $args{details};
  }

  return build_notification(
    method => 'runtime.fatal',
    params => \%params,
  );
}

sub build_runtime_shutdown {
  my (%args) = @_;
  _require_string_field(id => $args{id});
  _require_string_field_optional(reason => $args{reason});

  my %params;
  if (defined $args{reason}) {
    $params{reason} = $args{reason};
  }

  return build_request(
    id     => $args{id},
    method => 'runtime.shutdown',
    params => \%params,
  );
}

sub feed {
  my ($self, $chunk) = @_;

  if (defined $chunk && length $chunk) {
    $self->{_buffer} .= $chunk;
  }

  my @messages;

  while (1) {
    my $newline_at = index($self->{_buffer}, "\n");
    if ($newline_at < 0) {

      # No length prefix has terminated yet. A canonical prefix for a frame
      # within max_frame_size cannot be longer than that value has digits, so
      # a longer unterminated run can never begin a valid frame. Reject it
      # rather than buffering an attacker-controlled stream without bound.
      if (length($self->{_buffer}) > length($self->{max_frame_size})) {
        croak "Protocol framing error: length prefix exceeds maximum size\n";
      }
      last;
    }

    my $prefix = substr($self->{_buffer}, 0, $newline_at);
    if (!length $prefix) {
      croak "Protocol framing error: missing length prefix\n";
    }

    if ($prefix !~ /\A\d+\z/mxs) {
      croak "Protocol framing error: non-numeric length prefix\n";
    }

    my $length = 0 + $prefix;
    if ($length > $self->{max_frame_size}) {
      croak "Protocol framing error: frame exceeds maximum size\n";
    }

    my $header_length = $newline_at + 1;
    my $frame_length  = $header_length + $length;
    if (length($self->{_buffer}) < $frame_length) {
      last;
    }

    my $payload = substr($self->{_buffer}, $header_length, $length);
    substr($self->{_buffer}, 0, $frame_length, q{});

    my $message = _decode_payload($payload);
    push @messages, $message;
  }

  return \@messages;
}

sub finish {
  my ($self) = @_;

  if (!(length $self->{_buffer})) {
    return 1;
  }

  my $newline_at = index($self->{_buffer}, "\n");
  if ($newline_at < 0) {
    croak "Protocol framing error: incomplete frame at end of stream\n";
  }

  my $prefix = substr($self->{_buffer}, 0, $newline_at);
  if (!length $prefix) {
    croak "Protocol framing error: missing length prefix\n";
  }

  if ($prefix !~ /\A\d+\z/mxs) {
    croak "Protocol framing error: non-numeric length prefix\n";
  }

  my $length = 0 + $prefix;
  if ($length > $self->{max_frame_size}) {
    croak "Protocol framing error: frame exceeds maximum size\n";
  }

  my $header_length           = $newline_at + 1;
  my $available_payload_bytes = length($self->{_buffer}) - $header_length;
  if ($available_payload_bytes < $length) {
    croak "Protocol framing error: payload shorter than declared length\n";
  }

  croak "Protocol framing error: trailing payload bytes do not begin a valid next frame\n";
}

sub _decode_payload {
  my ($payload) = @_;

  my $decoded;
  eval {
    $decoded = JSON->new->utf8->decode($payload);
    1;
  } or do {
    my $err = $EVAL_ERROR || 'unknown error';
    $err =~ s/\s+at\ \S+\ line\ \d+.*\z//smx;
    croak "Protocol framing error: invalid JSON payload: $err\n";
  };

  if (ref($decoded) ne 'HASH') {
    croak "Protocol framing error: payload must decode to a JSON object\n";
  }

  return $decoded;
}

sub _assert_message_object {
  my ($message) = @_;

  if (!defined $message || ref($message) ne 'HASH') {
    croak "Protocol message must be a hash reference\n";
  }

  return 1;
}

sub _validate_request {
  my ($message) = @_;

  if (!(defined $message->{id} && !ref($message->{id}) && length($message->{id}))) {
    return (0, 'protocol.invalid_message', 'Request id is required');
  }
  if (!(defined $message->{method} && !ref($message->{method}) && length($message->{method}))) {
    return (0, 'protocol.invalid_message', 'Request method is required');
  }
  if (exists $message->{params} && ref($message->{params}) ne 'HASH') {
    return (0, 'protocol.invalid_params', 'Request params must be an object');
  }
  if (!($BASELINE_REQUEST_METHODS{$message->{method}})) {
    return (0, 'protocol.unknown_method', "Unknown request method: $message->{method}");
  }

  if ($message->{method} eq 'runtime.init') {
    return _validate_runtime_init_request($message);
  }

  if ($message->{method} eq 'runtime.shutdown') {
    return _validate_runtime_shutdown_request($message);
  }

  return (1, undef, undef);
}

sub _validate_response {
  my ($message) = @_;

  if (!(defined $message->{id} && !ref($message->{id}) && length($message->{id}))) {
    return (0, 'protocol.invalid_message', 'Response id is required');
  }
  if (!(exists $message->{ok})) {
    return (0, 'protocol.invalid_message', 'Response ok field is required');
  }

  my $ok = $message->{ok};
  if (!(JSON::is_bool($ok))) {
    return (0, 'protocol.invalid_message', 'Response ok field must be a boolean');
  }

  if ($ok) {
    if (exists $message->{result} && ref($message->{result}) ne 'HASH') {
      return (0, 'protocol.invalid_params', 'Successful response result must be an object');
    }
    if (exists $message->{error}) {
      return (0, 'protocol.invalid_message', 'Successful response must not include error');
    }
  } else {
    if (!(ref($message->{error}) eq 'HASH')) {
      return (0, 'protocol.invalid_message', 'Error response must include error object');
    }
    if (!(defined $message->{error}{code} && !ref($message->{error}{code}) && length($message->{error}{code}))) {
      return (0, 'protocol.invalid_message', 'Error response code is required');
    }
    if (!(defined $message->{error}{message} && !ref($message->{error}{message}) && length($message->{error}{message})))
    {
      return (0, 'protocol.invalid_message', 'Error response message is required');
    }
    if (exists $message->{error}{details}
      && ref($message->{error}{details}) ne 'HASH') {
      return (0, 'protocol.invalid_message', 'Error response details must be an object');
    }
  }

  return (1, undef, undef);
}

sub _validate_notification {
  my ($message) = @_;

  if (!(defined $message->{method} && !ref($message->{method}) && length($message->{method}))) {
    return (0, 'protocol.invalid_message', 'Notification method is required');
  }
  if (exists $message->{id}) {
    return (0, 'protocol.invalid_message', 'Notifications must not include id');
  }
  if (exists $message->{params} && ref($message->{params}) ne 'HASH') {
    return (0, 'protocol.invalid_params', 'Notification params must be an object');
  }
  if (!($BASELINE_NOTIFICATION_METHODS{$message->{method}})) {
    return (0, 'protocol.unknown_method', "Unknown notification method: $message->{method}");
  }

  if ($message->{method} eq 'program.hello') {
    return _validate_program_hello_notification($message);
  }

  if ($message->{method} eq 'program.log') {
    return _validate_program_log_notification($message);
  }

  if ($message->{method} eq 'program.health') {
    return _validate_program_health_notification($message);
  }

  if ($message->{method} eq 'runtime.fatal') {
    return _validate_runtime_fatal_notification($message);
  }

  if ($message->{method} eq 'runtime.subscription_event') {
    return _validate_runtime_subscription_event_notification($message);
  }

  if ($message->{method} eq 'runtime.timer_fired') {
    return _validate_runtime_timer_fired_notification($message);
  }

  return (1, undef, undef);
}

sub _validate_program_hello_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (!(_is_non_empty_string($params->{program_id}))) {
    return (0, 'protocol.invalid_params', 'program.hello params.program_id is required');
  }
  if (!(_is_non_empty_string_array($params->{supported_protocol_versions}))) {
    return (0, 'protocol.invalid_params',
      'program.hello params.supported_protocol_versions must be an array of strings');
  }
  if (exists $params->{program_version}
    && !_is_non_empty_string($params->{program_version})) {
    return (0, 'protocol.invalid_params', 'program.hello params.program_version must be a non-empty string');
  }
  if (exists $params->{metadata} && ref($params->{metadata}) ne 'HASH') {
    return (0, 'protocol.invalid_params', 'program.hello params.metadata must be an object');
  }

  return (1, undef, undef);
}

sub _validate_program_log_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (!(_is_non_empty_string($params->{level}))) {
    return (0, 'protocol.invalid_params', 'program.log params.level is required');
  }
  if (!(_is_non_empty_string($params->{message}))) {
    return (0, 'protocol.invalid_params', 'program.log params.message is required');
  }
  if (exists $params->{context} && ref($params->{context}) ne 'HASH') {
    return (0, 'protocol.invalid_params', 'program.log params.context must be an object');
  }

  return (1, undef, undef);
}

sub _validate_program_health_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (!(_is_non_empty_string($params->{status}))) {
    return (0, 'protocol.invalid_params', 'program.health params.status is required');
  }
  if (exists $params->{message}
    && !_is_non_empty_string($params->{message})) {
    return (0, 'protocol.invalid_params', 'program.health params.message must be a non-empty string');
  }
  if (exists $params->{details} && ref($params->{details}) ne 'HASH') {
    return (0, 'protocol.invalid_params', 'program.health params.details must be an object');
  }

  return (1, undef, undef);
}

sub _validate_runtime_fatal_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (!(_is_non_empty_string($params->{code}))) {
    return (0, 'protocol.invalid_params', 'runtime.fatal params.code is required');
  }
  if (!(_is_non_empty_string($params->{message}))) {
    return (0, 'protocol.invalid_params', 'runtime.fatal params.message is required');
  }
  if (exists $params->{phase} && !_is_non_empty_string($params->{phase})) {
    return (0, 'protocol.invalid_params', 'runtime.fatal params.phase must be a non-empty string');
  }
  if (exists $params->{details} && ref($params->{details}) ne 'HASH') {
    return (0, 'protocol.invalid_params', 'runtime.fatal params.details must be an object');
  }

  return (1, undef, undef);
}

sub _validate_runtime_subscription_event_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (!(_is_non_empty_string($params->{subscription_id}))) {
    return (0, 'protocol.invalid_params', 'runtime.subscription_event params.subscription_id is required');
  }
  if (!(_is_non_empty_string($params->{item_type}))) {
    return (0, 'protocol.invalid_params', 'runtime.subscription_event params.item_type is required');
  }
  if (
    !(
         $params->{item_type} eq 'event'
      || $params->{item_type} eq 'state'
      || $params->{item_type} eq 'private_message'
      || $params->{item_type} eq 'capability'
      || $params->{item_type} eq 'nostr.event'
    )
  ) {
    return (0, 'protocol.invalid_params', 'runtime.subscription_event params.item_type is invalid');
  }
  if (!(ref($params->{data}) eq 'HASH')) {
    return (0, 'protocol.invalid_params', 'runtime.subscription_event params.data must be an object');
  }
  if ($params->{item_type} eq 'private_message') {
    my ($ok, $code, $reason) = _validate_subscription_private_message_data($params->{data});
    if (!$ok) {
      return (0, $code, $reason);
    }
  }

  return (1, undef, undef);
}

sub _validate_subscription_private_message_data {
  my ($data) = @_;

  if (ref($data->{transport}) ne 'HASH') {
    return (0, 'protocol.invalid_params',
      'runtime.subscription_event private_message data.transport must be an object');
  }
  for my $field (qw(private_type object_type object_id)) {
    if (!(_is_non_empty_string($data->{$field}))) {
      return (0, 'protocol.invalid_params',
        "runtime.subscription_event private_message data.$field must be a non-empty string");
    }
  }

  return (1, undef, undef);
}

sub _validate_runtime_timer_fired_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (!(_is_non_empty_string($params->{timer_id}))) {
    return (0, 'protocol.invalid_params', 'runtime.timer_fired params.timer_id is required');
  }
  if (!(_is_integer($params->{fired_at}))) {
    return (0, 'protocol.invalid_params', 'runtime.timer_fired params.fired_at must be an integer');
  }
  if (exists $params->{payload} && ref($params->{payload}) ne 'HASH') {
    return (0, 'protocol.invalid_params', 'runtime.timer_fired params.payload must be an object');
  }

  return (1, undef, undef);
}

sub _validate_runtime_init_request {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (!(_is_non_empty_string($params->{protocol_version}))) {
    return (0, 'protocol.invalid_params', 'runtime.init params.protocol_version is required');
  }
  if (!(_is_non_empty_string($params->{instance_id}))) {
    return (0, 'protocol.invalid_params', 'runtime.init params.instance_id is required');
  }
  if (!(_is_non_empty_string($params->{program_id}))) {
    return (0, 'protocol.invalid_params', 'runtime.init params.program_id is required');
  }
  if (!(ref($params->{permissions}) eq 'ARRAY' && !any { !defined || ref || !length } @{$params->{permissions}})) {
    return (0, 'protocol.invalid_params', 'runtime.init params.permissions must be an array of strings');
  }
  if (!(ref($params->{config}) eq 'HASH')) {
    return (0, 'protocol.invalid_params', 'runtime.init params.config must be an object');
  }
  if (!(ref($params->{services}) eq 'HASH')) {
    return (0, 'protocol.invalid_params', 'runtime.init params.services must be an object');
  }

  return (1, undef, undef);
}

sub _validate_runtime_shutdown_request {
  my ($message) = @_;
  my $params = $message->{params} || {};

  if (exists $params->{reason}
    && !_is_non_empty_string($params->{reason})) {
    return (0, 'protocol.invalid_params', 'runtime.shutdown params.reason must be a non-empty string');
  }

  return (1, undef, undef);
}

sub _is_non_empty_string {
  my ($value) = @_;
  return defined $value && !ref($value) && length($value) ? 1 : 0;
}

sub _is_non_empty_string_array {
  my ($value) = @_;
  if (!(ref($value) eq 'ARRAY' && @{$value})) {
    return 0;
  }

  for my $item (@{$value}) {
    if (!(_is_non_empty_string($item))) {
      return 0;
    }
  }

  return 1;
}

sub _is_integer {
  my ($value) = @_;
  return defined $value && !ref($value) && $value =~ /\A-?\d+\z/mxs ? 1 : 0;
}

sub _require_string_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  if (!(defined $value && !ref($value) && length($value))) {
    croak "$name is required\n";
  }
  return;
}

sub _require_string_field_optional {
  my (%args) = @_;
  my ($name, $value) = each %args;
  if (!(defined $value)) {
    return;
  }
  if (ref($value) || !length($value)) {
    croak "$name must be a non-empty string\n";
  }
  return;
}

sub _require_object_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  if (!(defined $value)) {
    croak "$name is required\n";
  }
  if (ref($value) ne 'HASH') {
    croak "$name must be an object\n";
  }
  return;
}

sub _require_object_field_optional {
  my (%args) = @_;
  my ($name, $value) = each %args;
  if (!(defined $value)) {
    return;
  }
  if (ref($value) ne 'HASH') {
    croak "$name must be an object\n";
  }
  return;
}

sub _require_array_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  if (!(defined $value)) {
    croak "$name is required\n";
  }
  if (ref($value) ne 'ARRAY') {
    croak "$name must be an array\n";
  }
  return;
}

sub _require_string_array_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  if (!(defined $value)) {
    croak "$name is required\n";
  }
  if (!(ref($value) eq 'ARRAY' && @{$value})) {
    croak "$name must be an array of strings\n";
  }
  for my $item (@{$value}) {
    if (!defined($item) || ref($item) || !length($item)) {
      croak "$name must be an array of strings\n";
    }
  }
  return;
}

1;

=head1 NAME

Overnet::Program::Protocol - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Protocol;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 max_frame_size

Public API entry point.

=head2 buffered_bytes

Public API entry point.

=head2 is_program_notification_method

Public API entry point.

=head2 is_runtime_notification_method

Public API entry point.

=head2 is_runtime_request_method

Public API entry point.

=head2 is_service_request_method

Public API entry point.

=head2 service_request_methods

Public API entry point. Returns the sorted list of baseline service request
method names.

=head2 encode_message

Public API entry point.

=head2 validate_message

Public API entry point.

=head2 encode_request

Public API entry point.

=head2 encode_response_ok

Public API entry point.

=head2 encode_response_error

Public API entry point.

=head2 encode_notification

Public API entry point.

=head2 build_request

Public API entry point.

=head2 build_response_ok

Public API entry point.

=head2 build_response_error

Public API entry point.

=head2 build_notification

Public API entry point.

=head2 build_program_hello

Public API entry point.

=head2 build_runtime_init

Public API entry point.

=head2 build_program_ready

Public API entry point.

=head2 build_runtime_fatal

Public API entry point.

=head2 build_runtime_shutdown

Public API entry point.

=head2 feed

Public API entry point.

=head2 finish

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
