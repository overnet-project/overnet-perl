use strictures 2;
use IO::Handle;

binmode(STDOUT, ':raw');
STDOUT->autoflush(1);

print STDOUT "50\n{\"type\":\"notification\",\"method\":\"program.hello\"";

