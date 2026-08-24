use strictures 2;
use IO::Handle;

binmode(STDOUT, ':raw');
STDOUT->autoflush(1);

print STDOUT "oops\n{}\n";
