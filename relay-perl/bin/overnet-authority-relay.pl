#!/usr/bin/env perl
use strictures 2;

use AnyEvent;
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use FindBin;
use Getopt::Long qw(GetOptions);
use JSON         ();
use lib grep { -d $_ } ("$FindBin::Bin/../lib", "$FindBin::Bin/../../core-perl/lib",);

use Overnet::Authority::HostedChannel::Relay qw(build_authoritative_relay);

my %opt = (
  host               => '127.0.0.1',
  port               => 7448,
  grant_kind         => 14142,
  relay_url          => undef,
  store_file         => undef,
  max_content_events => undef,
);

my $help = 0;
my $host = $opt{host};
my $port = $opt{port};
my @snapshot_pubkeys;
my $health_file;
my $log_file;

GetOptions(
  'host=s'               => \$host,
  'port=i'               => \$port,
  'relay-url=s'          => \$opt{relay_url},
  'grant-kind=i'         => \$opt{grant_kind},
  'store-file=s'         => \$opt{store_file},
  'max-content-events=i' => \$opt{max_content_events},
  'snapshot-pubkey=s'    => \@snapshot_pubkeys,
  'health-file=s'        => \$health_file,
  'log-file=s'           => \$log_file,
  'help'                 => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--host is required\n" if !defined($host) || $host eq '';
die "--port must be a non-negative integer\n"
  if !defined($port) || $port !~ /\A\d+\z/mx;
die "--grant-kind must be a positive integer\n"
  if !defined($opt{grant_kind}) || $opt{grant_kind} !~ /\A[1-9]\d*\z/mx;
if (defined $opt{store_file}) {
  die "--store-file must be a non-empty string\n"
    if ref($opt{store_file}) || $opt{store_file} eq '';
}
for my $pubkey (@snapshot_pubkeys) {
  die "--snapshot-pubkey must be a 64-char lowercase hex pubkey\n"
    if !defined($pubkey) || $pubkey !~ /\A[0-9a-f]{64}\z/mx;
}

my $relay_url = $opt{relay_url};
if (!defined($relay_url) || $relay_url eq '') {
  $relay_url = sprintf 'ws://%s:%d', $host, $port;
}

if (defined $log_file) {
  die "--log-file must be a non-empty string\n"
    if ref($log_file) || $log_file eq '';
  my $log_dir = dirname($log_file);
  make_path($log_dir) unless -d $log_dir;
  open my $log_fh, '>>', $log_file
    or die "Can't open authority relay log file $log_file: $!";
  open STDOUT, '>&', $log_fh
    or die "Can't redirect STDOUT to authority relay log file $log_file: $!";
  open STDERR, '>&', $log_fh
    or die "Can't redirect STDERR to authority relay log file $log_file: $!";
  select((select(STDOUT), $| = 1)[0]);
  select((select(STDERR), $| = 1)[0]);
}

my $relay = build_authoritative_relay(
  relay_url        => $relay_url,
  grant_kind       => 0 + $opt{grant_kind},
  snapshot_pubkeys => \@snapshot_pubkeys,
  (defined $opt{store_file}         ? (store_file         => $opt{store_file})         : ()),
  (defined $opt{max_content_events} ? (max_content_events => $opt{max_content_events}) : ()),
);

my $shutdown = sub {
  _write_health_file(
    $health_file,
    {
      status      => 'stopping',
      listen_host => $host,
      listen_port => 0 + $port,
      details     => {
        listen_host => $host,
        listen_port => 0 + $port,
      },
    }
  ) if defined $health_file;
  print STDERR "[authority-relay.health] stopping\n";
  $relay->stop;
};

$SIG{INT}  = $shutdown;
$SIG{TERM} = $shutdown;

my $ready_timer;
if (defined $health_file) {
  $ready_timer = AnyEvent->timer(
    after => 0,
    cb    => sub {
      undef $ready_timer;
      _write_health_file(
        $health_file,
        {
          status      => 'ready',
          listen_host => $host,
          listen_port => 0 + $port,
          details     => {
            listen_host        => $host,
            listen_port        => 0 + $port,
            relay_url          => $relay_url,
            grant_kind         => 0 + $opt{grant_kind},
            snapshot_pubkeys   => [@snapshot_pubkeys],
            snapshot_pubkey_ct => scalar @snapshot_pubkeys,
          },
        }
      );
      print STDERR "[authority-relay.health] ready $host:$port\n";
    },
  );
} else {
  print STDERR "[authority-relay.health] ready $host:$port\n";
}

$relay->run($host, $port);
_write_health_file(
  $health_file,
  {
    status      => 'stopped',
    listen_host => $host,
    listen_port => 0 + $port,
    details     => {
      listen_host => $host,
      listen_port => 0 + $port,
    },
  }
) if defined $health_file;
print STDERR "[authority-relay.health] stopped\n";
exit 0;

sub _write_health_file {
  my ($path, $payload) = @_;
  return 1 unless defined $path;

  die "--health-file must be a non-empty string\n"
    if ref($path) || $path eq '';

  my $dir = dirname($path);
  make_path($dir) unless -d $dir;

  my $tmp_path = $path . '.tmp.' . $$;
  open my $fh, '>', $tmp_path
    or die "Can't open authority relay health temp file $tmp_path: $!";
  print {$fh} JSON->new->utf8->canonical->encode($payload)
    or die "Can't write authority relay health temp file $tmp_path: $!";
  close $fh
    or die "Can't close authority relay health temp file $tmp_path: $!";
  rename $tmp_path, $path
    or die "Can't rename authority relay health temp file $tmp_path to $path: $!";
  return 1;
}

sub _usage {
  return <<'USAGE';
Usage: overnet-authority-relay.pl [options]

  --host HOST
  --port PORT
  --relay-url URL
  --grant-kind KIND
  --store-file PATH
  --max-content-events N     bound retained non-authoritative events (never evicts
                             group state, snapshots, or delegation grants)
  --snapshot-pubkey PUBKEY   (repeatable; without it all 39xxx snapshots are rejected)
  --health-file PATH
  --log-file PATH
  --help
USAGE
}
