package Overnet::Auth::NativeMessaging;

use strictures 2;
use Carp       qw(croak);
use English    qw(-no_match_vars);
use JSON       ();
use List::Util qw(any);

use Overnet::Auth::SocketIO;
use Overnet::Auth::Exchange;
use Overnet::Program::Protocol;

use Overnet::Core::JSON ();

our $VERSION = '0.001';

my $JSON           = JSON->new->utf8->canonical;
my $MAX_FRAME_SIZE = 1024 * 1024;
my %METHODS        = map { $_ => 1 } qw(agent.info identities.list browser.authenticate);

sub serve {
  my ($class, %args) = @_;
  my $input  = $args{input};
  my $output = $args{output};

  while (1) {
    my $header = _read_exact($input, 4);
    last if !defined $header;
    my $length = unpack('L', $header);
    if (!$length || $length > $MAX_FRAME_SIZE) {
      croak 'Invalid native message length';
    }
    my $payload = _read_exact($input, $length);
    if (!defined $payload) {
      croak 'Truncated native message';
    }
    my $request  = Overnet::Core::JSON::decode_json($payload);
    my $response = _dispatch(\%args, $request);
    my $bytes    = $JSON->encode($response);
    if (length($bytes) > $MAX_FRAME_SIZE) {
      croak 'Native response exceeds maximum size';
    }
    Overnet::Auth::SocketIO->write_all(
      socket => $output,
      bytes  => pack('L', length($bytes)) . $bytes,
      target => 'native messaging output',
    );
  }
  return 1;
}

sub _dispatch {
  my ($args, $request) = @_;
  my $client = $args->{client};
  if ( ref($request) ne 'HASH'
    || !defined($request->{id})
    || ref($request->{id})
    || !length($request->{id})
    || !defined($request->{type})
    || ref($request->{type})
    || $request->{type} ne 'request') {
    croak 'Invalid native request envelope';
  }
  my $method = $request->{method};
  if (!defined($method) || ref($method) || !$METHODS{$method}) {
    return _error($request->{id}, 'protocol.unknown_method', 'Unsupported native connector method');
  }
  my $params = exists($request->{params}) ? $request->{params} : {};
  if (ref($params) ne 'HASH' || ($method ne 'browser.authenticate' && keys %{$params})) {
    return _error($request->{id}, 'protocol.invalid_params', 'Invalid connector parameters');
  }

  my $response;
  my $ok = eval {
    local $SIG{ALRM} = sub { croak 'Auth-agent request timed out'; };
    alarm 5;
    if ($args->{ensure_agent}) {
      $args->{ensure_agent}->();
    }
    if ($method eq 'browser.authenticate') {
      alarm 60;
      $response = Overnet::Program::Protocol::build_response_ok(
        id     => $request->{id},
        result => _authenticate($client, $params),
      );
    } else {
      $response = $client->request(method => $method, id => $request->{id}, params => {});
    }
    alarm 0;
    1;
  };
  my $error = $EVAL_ERROR;
  alarm 0;
  if (!$ok) {
    if (ref($error) eq 'HASH') {
      return _error($request->{id}, $error->{code}, $error->{message});
    }
    return _error($request->{id}, 'native.agent_unavailable', 'The local authentication agent could not be reached');
  }
  return $response;
}

sub _authenticate {
  my ($client, $params) = @_;
  my $challenge = _browser_challenge($params);
  my $scope     = $challenge->{scope};

  # This first browser binding has locator trust only. Do not downgrade an
  # existing cryptographic pin based on a descriptor supplied by a web page.
  my $pins = _agent_result($client, 'service_pins.list', {});
  if (any { $_->{locator} eq $scope } @{$pins->{service_pins}}) {
    CORE::die {
      code    => 'auth.service_identity_required',
      message => 'This service has a cryptographic pin; this browser binding cannot verify it yet'
    };
  }
  my %context = (
    identity_id => $params->{identity_id},
    program_id  => 'browser:' . $params->{origin} . q{#} . $params->{request_id},
    service     => {locators => [$scope]},
  );
  my @requests = (Overnet::Auth::Exchange->authentication_request(%{$challenge}));
  if ($challenge->{delegation}) {
    push @requests, Overnet::Auth::Exchange->delegation_request(scope => $scope, %{$challenge->{delegation}});
  }
  my (@policies, @sessions, @events);
  my $ok = eval {
    for my $request (@requests) {

      # The native host is the trusted approval UI's local agent client. These
      # administrative calls are never exposed to the page messaging channel.
      my $granted = _agent_result(
        $client,
        'policies.grant',
        {
          policy => {
            %context,
            scope  => $scope,
            action => $request->{action},
          }
        }
      );
      push @policies, $granted->{policy}{policy_id};
      my $authorized = _agent_result($client, 'sessions.authorize', {%context, %{$request}});
      push @sessions, $authorized->{session_handle};
      push @events,   $authorized->{artifacts}[0]{value};
    }
    1;
  };
  my $error = $EVAL_ERROR;

  # Revoke even after a signing failure or timeout, and do not return artifacts
  # if cleanup fails. These handles must not enable unattended renewal.
  alarm 5;
  my $cleanup = eval {
    for my $policy (@policies) {
      _agent_result($client, 'policies.revoke', {policy_id => $policy});
    }
    for my $session (@sessions) {
      _agent_result($client, 'sessions.revoke', {session_handle => $session});
    }
    1;
  };
  if (!$cleanup) {
    CORE::die {
      code    => 'native.cleanup_failed',
      message => 'Could not remove temporary browser approval from the local agent'
    };
  }
  if (!$ok) {
    CORE::die $error;
  }
  return Overnet::Auth::Exchange->response_payload(auth_event => $events[0], delegate_event => $events[1]);
}

sub _browser_challenge {
  my ($params) = @_;
  my $valid =
       _text($params->{origin}, 512)
    && $params->{origin} =~ /\Ahttps?:\/\/[a-zA-Z0-9.:[\]-]+\z/mxs
    && _text($params->{identity_id}, 256)
    && _text($params->{request_id},  128)
    && $params->{request_id} =~ /\A[a-zA-Z0-9-]+\z/mxs;
  my $challenge = Overnet::Auth::Exchange->parse_challenge($params->{challenge});
  if (!$valid || !$challenge || !_text($challenge->{scope}, 2048) || !_text($challenge->{challenge}, 4096)) {
    CORE::die {code => 'protocol.invalid_params', message => 'Invalid browser authentication request'};
  }
  if ($challenge->{delegation_required}) {
    my $grant = $challenge->{delegation};
    if ( !$grant
      || !_text($grant->{relay_url},  2048)
      || !_text($grant->{session_id}, 512)
      || $grant->{delegate_pubkey} !~ /\A[0-9a-f]{64}\z/mxs
      || $grant->{grant_kind} ne '14142'
      || $grant->{expires_at} !~ /\A[0-9]{1,12}\z/mxs
      || $grant->{expires_at} <= time
      || $grant->{expires_at} > time + 86_400) {
      CORE::die {
        code    => 'protocol.invalid_params',
        message => 'Invalid or expired session delegation (maximum 24 hours)'
      };
    }
  }
  return $challenge;
}

sub _text {
  my ($value, $max) = @_;
  return
       defined($value)
    && !ref($value)
    && length($value)
    && length($value) <= $max
    && $value !~ /[\x00-\x1f\x7f]/mxs;
}

sub _agent_result {
  my ($client, $method, $params) = @_;
  my $response = $client->request(method => $method, params => $params);
  if (!$response->{ok}) {

    # Backend diagnostics can contain local paths or key-store details. The
    # browser receives an actionable summary, never the backend's raw message.
    my $code = $response->{error}{code};
    CORE::die {
      code    => $code,
      message => $code eq 'auth.backend_unavailable'
      ? 'Your local identity could not be unlocked. Check your key store and try again.'
      : "The local authentication agent refused this request ($code)",
    };
  }
  return $response->{result};
}

sub _error {
  my ($id, $code, $message) = @_;
  return Overnet::Program::Protocol::build_response_error(id => $id, code => $code, message => $message);
}

sub _read_exact {
  my ($input, $length) = @_;
  my $bytes = q{};
  while (length($bytes) < $length) {
    my $read = sysread($input, $bytes, $length - length($bytes), length($bytes));
    if (!defined $read) {
      croak "Read native message failed: $OS_ERROR";
    }
    if (!$read) {
      return if !length($bytes);
      croak 'Truncated native message';
    }
  }
  return $bytes;
}

1;

=head1 NAME

Overnet::Auth::NativeMessaging - Browser approval bridge to the auth agent

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Auth::NativeMessaging->serve(
    input => $input, output => $output, client => $auth_client,
  );

=head1 DESCRIPTION

Translates browser native messaging frames (native-endian 32-bit lengths and
UTF-8 JSON) to the existing auth client. Requests and responses use the existing
Overnet envelopes. C<agent.info> and C<identities.list> accept empty parameters.
C<browser.authenticate> accepts a browser-derived C<origin>, unique C<request_id>,
selected C<identity_id>, and shared service C<challenge>. It is intended only for
the trusted extension after its own approval UI has obtained consent. The
endpoint is configured locally, never supplied by a browser request.

=head1 SUBROUTINES/METHODS

=head2 serve

Reads requests from C<input> and writes responses to C<output> until EOF. Both
handles must use raw binary I/O. C<client> is an Overnet auth client. Frames are
limited to one MiB. Status requests time out after five seconds; authentication
has sixty seconds plus five seconds for cleanup. A connection
failure returns C<native.agent_unavailable>; invalid framing ends the connection.

=head1 DIAGNOSTICS

Framing and I/O failures raise exceptions. Standard output must be reserved for
native messages; the command-line host reports exceptions on standard error.

=head1 CONFIGURATION AND ENVIRONMENT

The supplied client owns endpoint configuration. An optional C<ensure_agent>
callback runs before an accepted request, within a five-second startup timeout.
The command-line host uses this to start the configured agent when needed.
Browser requests cannot supply startup settings.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

The current auth client uses Unix-domain sockets.

=head1 BUGS AND LIMITATIONS

This temporary bridge supports provisional locator trust and refuses services
with existing cryptographic pins. It constructs only the shared authentication
and delegation artifacts, using narrowly scoped temporary policies and revoking
local renewal handles before replying. It exposes no general signing or admin API.
Forced process termination or agent failure can prevent cleanup; policy program
IDs include a unique approval ID and are never reused by the extension. The
process uses an alarm for request timeouts.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
