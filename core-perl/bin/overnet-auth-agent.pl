#!/usr/bin/env perl

use strictures 2;
use English qw(-no_match_vars);

use Carp         qw(croak);
use Getopt::Long qw(GetOptions);

use Overnet::Auth::Daemon;

our $VERSION = '0.001';

my %args;
my $help;
my $socket_mode;

GetOptions(
  'config-file=s' => \$args{config_file},
  'auth-sock=s'   => \$args{endpoint},
  'socket-mode=s' => \$socket_mode,
  'help'          => \$help,
) or croak _usage();

if ($help) {
  print {*STDOUT} _usage()
    or croak "Can't write auth-agent usage: $OS_ERROR";
  exit 0;
}

if (!(defined($args{config_file}) && !ref($args{config_file}) && length($args{config_file}))) {
  croak _usage();
}

if (defined $socket_mode) {
  if (!($socket_mode =~ /\A0?[0-7]{3,4}\z/smx)) {
    croak "--socket-mode must be an octal mode like 0600";
  }
  $args{socket_mode} = oct($socket_mode);
}

my $daemon = Overnet::Auth::Daemon->new(%args);
$daemon->run;

sub _usage {
  return <<'USAGE';
Usage: overnet-auth-agent.pl --config-file PATH [--auth-sock PATH] [--socket-mode OCTAL]

Options:
  --config-file PATH  JSON auth-agent config file
  --auth-sock PATH    Override the configured local auth socket path
  --socket-mode MODE  Socket file mode, for example 0600
  --help              Show this help text
USAGE
}
