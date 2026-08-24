use strictures 2;
use IO::Handle;

binmode(STDERR, ':raw');
STDERR->autoflush(1);

print STDERR "fixture fatal: child exploded before handshake\n";
exit 42;

