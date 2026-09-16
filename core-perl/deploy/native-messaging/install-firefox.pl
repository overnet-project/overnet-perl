#!/usr/bin/env perl

use strictures 2;
use Carp       qw(croak);
use Cwd        qw(abs_path getcwd);
use English    qw(-no_match_vars);
use File::Path qw(make_path);
use File::Spec;
use File::Temp qw(tempfile);
use FindBin;
use Getopt::Long qw(GetOptions);
use JSON         ();
use Overnet::Auth::Config;

my $workspace = getcwd();
my ($config_file, $manifest_dir, $help);
GetOptions(
  'config-file=s'  => \$config_file,
  'workspace=s'    => \$workspace,
  'manifest-dir=s' => \$manifest_dir,
  'help'           => \$help,
) or croak _usage();

if ($help) {
  print {*STDOUT} _usage() or croak "Write usage failed: $OS_ERROR";
  exit 0;
}
croak _usage()                                              if !defined($config_file) || !length($config_file);
croak 'This development installer currently supports Linux' if $OSNAME ne 'linux';
$workspace = abs_path($workspace);
croak 'Choose the top-level workspace containing .plx' if !defined($workspace) || !-d "$workspace/.plx";
$config_file = File::Spec->rel2abs($config_file);
my $endpoint = Overnet::Auth::Config->load_file(path => $config_file)->endpoint;
croak 'Auth-agent config must contain daemon.endpoint' if !defined($endpoint) || ref($endpoint) || !length($endpoint);
$endpoint = File::Spec->rel2abs($endpoint);
$manifest_dir //= File::Spec->catdir($ENV{HOME}, '.mozilla', 'native-messaging-hosts');
$manifest_dir = File::Spec->rel2abs($manifest_dir);

my ($plx) = grep { -f $_ && -x $_ } map { File::Spec->catfile($_, 'plx') } File::Spec->path();
croak 'plx must be available on PATH' if !defined $plx;
$plx = abs_path($plx);
my $host = abs_path(File::Spec->catfile($FindBin::Bin, '..', '..', 'bin', 'overnet-auth-native.pl'));
croak 'Native host script is missing' if !defined $host;
my $manifest_path = File::Spec->catfile($workspace, 'repos', 'overnet-client', 'manifests', 'firefox.json');
open my $input, '<:raw', $manifest_path or croak "Read $manifest_path failed: $OS_ERROR";
my $source = do { local $INPUT_RECORD_SEPARATOR; <$input> };
close $input or croak "Close manifest failed: $OS_ERROR";
my $extension = JSON->new->utf8->decode($source);
my $id        = $extension->{browser_specific_settings}{gecko}{id};
croak 'Firefox extension ID is missing' if !defined($id) || ref($id) || !length($id);

make_path($manifest_dir, {mode => oct('0700')});
my $launcher = File::Spec->catfile($manifest_dir, 'org.overnet.auth.sh');
my @command  = ($plx, '--base', $workspace, $host, '--auth-sock', $endpoint, '--config-file', $config_file);
_write_file($launcher, "#!/bin/sh\nexec " . join(q{ }, map { _shell_quote($_) } @command) . ' "$@"' . "\n",
  oct('0700'));
my $registration = File::Spec->catfile($manifest_dir, 'org.overnet.auth.json');
_write_file(
  $registration,
  JSON->new->utf8->canonical->pretty->encode(
    {
      name               => 'org.overnet.auth',
      description        => 'Overnet local authentication agent connector',
      path               => $launcher,
      type               => 'stdio',
      allowed_extensions => [$id],
    }
  ),
  oct('0600')
);
print {*STDOUT} "Registered Firefox connector: $registration\nAgent socket: $endpoint\n"
  or croak "Write install result failed: $OS_ERROR";

sub _shell_quote {
  my ($value) = @_;
  $value =~ s/'/'\\''/gmxs;
  return q{'} . $value . q{'};
}

sub _write_file {
  my ($path, $content, $mode) = @_;
  my ($output, $temporary) = tempfile('.overnet-XXXXXX', DIR => $manifest_dir, UNLINK => 0);
  binmode $output, ':raw' or croak "Set output mode failed: $OS_ERROR";
  print {$output} $content or croak "Write $temporary failed: $OS_ERROR";
  close $output            or croak "Close $temporary failed: $OS_ERROR";
  chmod $mode, $temporary or croak "Set file mode failed: $OS_ERROR";
  rename $temporary, $path or croak "Install $path failed: $OS_ERROR";
  return;
}

sub _usage {
  return <<'USAGE';
Usage: install-firefox.pl --config-file PATH [--workspace PATH] [--manifest-dir PATH]

Run through plx from the top-level Overnet workspace. Registers a development
launcher using this checkout and its plx configuration for the current user.
The connector starts the configured auth agent when needed.
USAGE
}
