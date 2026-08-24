use strictures 2;

use File::Spec;
use FindBin;
use IPC::Open3 qw(open3);
use Symbol     qw(gensym);
use Test2::V0;

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-authority-relay.pl');

ok -f $script, 'authority relay entrypoint exists';

# Run the entrypoint with the given arguments and capture its result. Only
# help and validation-failure paths are exercised here; both exit before the
# relay enters its event loop, so no timeout is needed.
sub _run {
  my (@args) = @_;
  my $stderr = gensym();
  my $pid    = open3(my $in, my $stdout, $stderr, $^X, $script, @args);
  close $in;
  my $out = do { local $/ = undef; <$stdout> };
  my $err = do { local $/ = undef; <$stderr> };
  close $stdout;
  close $stderr;
  waitpid $pid, 0;
  return { exit_code => $? >> 8, stdout => $out, stderr => $err };
}

my $help = _run('--help');
is $help->{exit_code}, 0, '--help exits cleanly';
like $help->{stdout}, qr/--snapshot-pubkey\b/mx, 'help documents snapshot pubkeys';
like $help->{stdout}, qr/--grant-kind\b/mx,      'help documents the grant kind';
like $help->{stdout}, qr/--store-file\b/mx,      'help documents the store file';
like $help->{stdout}, qr/--health-file\b/mx,     'help documents the health file';

my $bad_pubkey = _run('--snapshot-pubkey', 'not-hex');
isnt $bad_pubkey->{exit_code}, 0, 'a malformed snapshot pubkey is rejected';
like $bad_pubkey->{stderr}, qr/snapshot-pubkey/mx, 'the rejection names the offending option';

my $bad_grant = _run('--grant-kind', '0');
isnt $bad_grant->{exit_code}, 0, 'a non-positive grant kind is rejected';
like $bad_grant->{stderr}, qr/grant-kind/mx, 'the rejection names the grant kind';

my $bad_store = _run('--store-file', q{});
isnt $bad_store->{exit_code}, 0, 'an empty store-file is rejected';

done_testing;
