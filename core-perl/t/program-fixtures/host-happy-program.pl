use strictures 2;
use FindBin;
use IO::Handle;
use lib "$FindBin::Bin/../../lib";
use Overnet::Program::Protocol;

binmode(STDIN,  ':raw');
binmode(STDOUT, ':raw');
binmode(STDERR, ':raw');
STDOUT->autoflush(1);
STDERR->autoflush(1);

my $protocol = Overnet::Program::Protocol->new;
my @pending_messages;

sub _send_message {
  my ($message) = @_;
  my $frame     = $protocol->encode_message($message);
  my $offset    = 0;
  while ($offset < length $frame) {
    my $written = syswrite(STDOUT, $frame, length($frame) - $offset, $offset);
    die "write failed: $!\n" unless defined $written;
    $offset += $written;
  }
  return;
}

sub _next_message {
  while (!@pending_messages) {
    my $bytes = sysread(STDIN, my $chunk, 4096);
    die "unexpected EOF on stdin\n" unless defined $bytes && $bytes > 0;
    push @pending_messages, @{$protocol->feed($chunk)};
  }

  return shift @pending_messages;
}

sub _expect {
  my ($message, $type, $method, $id) = @_;
  die "expected $type message\n"
    unless ($message->{type} || '') eq $type;
  die "expected method $method\n"
    unless !defined $method || ($message->{method} || '') eq $method;
  die "expected id $id\n"
    unless !defined $id || ($message->{id} || '') eq $id;
  return;
}

sub _shutdown_and_exit {
  my ($message) = @_;
  _send_message(
    Overnet::Program::Protocol::build_response_ok(id => $message->{id}));
  print STDERR "fixture done\n";
  exit 0;
}

# Wait for the response to a specific in-flight request. Shutdown can legitimately
# interleave a pending program request -- the runtime is not obligated to answer
# in-flight requests once it begins tearing down -- so treat an interleaved
# runtime.shutdown request as an orderly stop rather than a protocol violation,
# and ignore async notifications that arrive while we await the reply.
sub _await_response {
  my ($id) = @_;
  while (1) {
    my $message = _next_message();
    my $type    = $message->{type} || q{};
    if ($type eq 'request' && ($message->{method} || q{}) eq 'runtime.shutdown') {
      _shutdown_and_exit($message);
    }
    next if $type eq 'notification';
    _expect($message, 'response', undef, $id);
    return $message;
  }
}

_send_message(
  Overnet::Program::Protocol::build_program_hello(
    program_id                  => 'fixture.host.program',
    supported_protocol_versions => ['0.1'],
    program_version             => '0.0.1',
    metadata                    => {fixture => 'host-happy-program'},
  )
);

my $message = _next_message();
_expect($message, 'request', 'runtime.init');
_send_message(
  Overnet::Program::Protocol::build_response_ok(
    id => $message->{id},
  )
);

_send_message(
  Overnet::Program::Protocol::build_notification(
    method => 'program.log',
    params => {
      level   => 'info',
      message => 'fixture entering ready state',
      context => {phase => 'awaiting_ready'},
    },
  )
);
_send_message(Overnet::Program::Protocol::build_program_ready());

_send_message(
  Overnet::Program::Protocol::build_request(
    id     => 'fixture-config',
    method => 'config.get',
  )
);
my $config_response = _await_response('fixture-config');
die "config.get failed\n" unless $config_response->{ok};
print STDERR "fixture config: " . ($config_response->{result}{config}{name} || '') . "\n";

_send_message(
  Overnet::Program::Protocol::build_request(
    id     => 'fixture-timer',
    method => 'timers.schedule',
    params => {
      timer_id => 'fixture-timer',
      delay_ms => 0,
      payload  => {source => 'host-happy-program'},
    },
  )
);
my $timer_response = _await_response('fixture-timer');
die "timers.schedule failed\n" unless $timer_response->{ok};

while (1) {
  $message = _next_message();

  if ( ($message->{type} || '') eq 'notification'
    && ($message->{method} || '') eq 'runtime.timer_fired') {
    _send_message(
      Overnet::Program::Protocol::build_notification(
        method => 'program.health',
        params => {
          status  => 'ok',
          message => 'timer observed',
          details => {
            timer_id => $message->{params}{timer_id},
          },
        },
      )
    );
    next;
  }

  if ( ($message->{type} || '') eq 'request'
    && ($message->{method} || '') eq 'runtime.shutdown') {
    _send_message(
      Overnet::Program::Protocol::build_response_ok(
        id => $message->{id},
      )
    );
    last;
  }

  die "unexpected message from runtime\n";
}

print STDERR "fixture done\n";
