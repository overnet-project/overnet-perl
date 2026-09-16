#!/usr/bin/env perl

use strictures 2;
use Carp         qw(carp croak);
use English      qw(-no_match_vars);
use Getopt::Long qw(GetOptions);
use FindBin;
use Fcntl          qw(O_CREAT O_WRONLY LOCK_EX);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use IO::Socket::UNIX;
use POSIX       qw(setsid WNOHANG _exit);
use Socket      qw(SOCK_STREAM);
use Time::HiRes qw(sleep);
use Overnet::Auth::Client;
use Overnet::Auth::NativeMessaging;

our $VERSION = '0.001';

my ($endpoint, $config_file, $help);
GetOptions('auth-sock=s' => \$endpoint, 'config-file=s' => \$config_file, 'help' => \$help)
  or croak 'Invalid native host options';
if ($help) {
  print {*STDOUT} "Usage: overnet-auth-native.pl [--auth-sock PATH] [--config-file PATH]\n"
    or croak "Write usage failed: $OS_ERROR";
  exit 0;
}

# Browsers may append their host manifest path and/or extension identity.
# The native host registration controls which extensions can launch this host.
binmode STDIN,  ':raw' or croak "Set native input mode failed: $OS_ERROR";
binmode STDOUT, ':raw' or croak "Set native output mode failed: $OS_ERROR";
my $client = Overnet::Auth::Client->new(endpoint => $endpoint);
Overnet::Auth::NativeMessaging->serve(
  input        => \*STDIN,
  output       => \*STDOUT,
  client       => $client,
  ensure_agent => $config_file ? sub { _ensure_agent($client->endpoint, $config_file); } : undef,
);

sub _ensure_agent {
  my ($socket_path, $config) = @_;
  return if _agent_listening($socket_path);

  make_path(dirname($socket_path), {mode => oct('0700')});
  sysopen my $lock, "$socket_path.lock", O_CREAT | O_WRONLY, oct('0600')
    or croak "Open agent startup lock failed: $OS_ERROR";
  flock $lock, LOCK_EX or croak "Lock agent startup failed: $OS_ERROR";
  return if _agent_listening($socket_path);

  my $pid = fork;
  croak "Fork auth agent failed: $OS_ERROR" if !defined $pid;
  if (!$pid) {

    # Detach from the browser and reserve its pipes for native messages.
    eval {
      close $lock   or croak "Close startup lock failed: $OS_ERROR";
      setsid() >= 0 or croak "Detach auth agent failed: $OS_ERROR";
      umask oct('0077');
      open STDIN,  '<',  '/dev/null'        or croak "Redirect agent input failed: $OS_ERROR";
      open STDOUT, '>',  '/dev/null'        or croak "Redirect agent output failed: $OS_ERROR";
      open STDERR, '>>', "$socket_path.log" or croak "Open agent log failed: $OS_ERROR";
      exec {$EXECUTABLE_NAME} $EXECUTABLE_NAME, "$FindBin::Bin/overnet-auth-agent.pl", '--config-file', $config,
        '--auth-sock', $socket_path
        or croak "Exec auth agent failed: $OS_ERROR";
    } or carp $EVAL_ERROR;
    _exit(1);
  }

  my $ready = eval {
    while (!_agent_listening($socket_path)) {
      croak 'Auth agent exited during startup' if waitpid($pid, WNOHANG) != 0;
      sleep 0.05;
    }
    1;
  };
  if (!$ready) {

    # A failed or timed-out startup must not leave a child behind.
    if (waitpid($pid, WNOHANG) == 0) {
      kill 'KILL', $pid;
      waitpid($pid, 0);
    }
    croak 'Auth agent did not become ready';
  }
  return;
}

sub _agent_listening {
  my ($socket_path) = @_;
  my $socket = IO::Socket::UNIX->new(Peer => $socket_path, Type => SOCK_STREAM);
  return 0 if !$socket;
  close $socket or croak "Close agent probe failed: $OS_ERROR";
  return 1;
}
