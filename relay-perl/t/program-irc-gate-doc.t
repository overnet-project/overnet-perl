use strictures 2;
use Test::More;
use File::Spec;
use FindBin;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/ = undef;
  return <$fh>;
}

my $readme = File::Spec->catfile($FindBin::Bin, '..', 'README.md');

my $readme_text = _slurp($readme);

like $readme_text, qr/IRC\ verification\ path/imx,
  'README documents the IRC verification path';
like $readme_text, qr/t\/spec-conformance-irc-server\.t/mx,
  'README includes server conformance in the IRC verification path';
like $readme_text, qr/t\/program-irc-server\.t/mx,
  'README includes the fast IRC server suite in the IRC verification path';
like $readme_text, qr/t\/program-irc-server-relay\.t/mx,
  'README includes the relay IRC server suite in the IRC verification path';
like $readme_text, qr/t\/program-irc-server-relay-fault\.t/mx,
  'README includes the relay fault and recovery suite in the IRC verification path';
like $readme_text, qr/t\/program-irc-server-relay-failover\.t/mx,
  'README includes the two-relay failover suite in the IRC verification path';
like $readme_text, qr/t\/relay-live\.t/mx,
  'README includes live relay persistence and fault coverage in the IRC verification path';
like $readme_text, qr/t\/relay-sync-live\.t/mx,
  'README includes live relay sync coverage in the IRC verification path';
like $readme_text, qr/t\/deploy-restore-drill-live\.t/mx,
  'README includes the restore drill in the IRC verification path';

done_testing;
