use strictures 2;
use IO::Handle;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use Overnet::Program::Protocol;

binmode(STDIN,  ':raw');
binmode(STDOUT, ':raw');
binmode(STDERR, ':raw');
STDOUT->autoflush(1);
STDERR->autoflush(1);

my $protocol = Overnet::Program::Protocol->new;

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

_send_message(
  Overnet::Program::Protocol::build_program_hello(
    program_id                  => 'fixture.version.mismatch',
    supported_protocol_versions => ['9.9'],
  )
);

my $bytes = sysread(STDIN, my $chunk, 4096);
if (defined $bytes && $bytes > 0) {
  my $messages = $protocol->feed($chunk);
  if (@{$messages} && ($messages->[0]{method} || '') eq 'runtime.fatal') {
    print STDERR "received runtime.fatal\n";
  }
}

