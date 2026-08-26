use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IPC::Open3;
use Symbol qw(gensym);
use Test2::V0;

my $code_root = File::Spec->catdir($FindBin::Bin, '..');
my $podman_dir = File::Spec->catdir($code_root, 'deploy', 'podman');
my $lookup = File::Spec->catfile($podman_dir, 'registry-tag-digest.sh');
my $publish = File::Spec->catfile($podman_dir, 'publish-image.sh');
my $temp = tempdir(CLEANUP => 1);
my $fake_bin = File::Spec->catdir($temp, 'bin');
mkdir $fake_bin or die "Can't create $fake_bin: $!";

my $curl_log = File::Spec->catfile($temp, 'curl.log');
my $podman_log = File::Spec->catfile($temp, 'podman.log');
my $fake_curl = File::Spec->catfile($fake_bin, 'curl');
my $fake_podman = File::Spec->catfile($fake_bin, 'podman');

_write_executable(
  $fake_curl,
  <<'FAKE_CURL',
#!/usr/bin/env bash
set -euo pipefail

headers=
url=
head_request=false
while (($#)); do
  case "$1" in
    --dump-header|--output|--write-out|--header)
      [[ "$1" == --dump-header ]] && headers="$2"
      shift 2
      ;;
    --head)
      head_request=true
      shift
      ;;
    --silent|--show-error)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done

if [[ "$head_request" != true ]]; then
  printf 'lookup did not use curl head mode\n' >&2
  exit 64
fi
printf '%s\n' "$url" >> "$FAKE_CURL_LOG"
case "${FAKE_CURL_MODE:?}" in
  exists)
    printf 'HTTP/2 200\r\nDocker-Content-Digest: %s\r\n\r\n' \
      "${FAKE_CURL_DIGEST:?}" > "$headers"
    printf '200'
    ;;
  missing)
    printf 'HTTP/2 404\r\n\r\n' > "$headers"
    printf '404'
    ;;
  invalid-digest)
    printf 'HTTP/2 200\r\nDocker-Content-Digest: not-a-digest\r\n\r\n' \
      > "$headers"
    printf '200'
    ;;
  server-error)
    printf 'HTTP/2 503\r\n\r\n' > "$headers"
    printf '503'
    ;;
  transport-error)
    printf 'registry unavailable\n' >&2
    exit 7
    ;;
  *)
    printf 'unknown fake curl mode\n' >&2
    exit 64
    ;;
esac
FAKE_CURL
);

_write_executable(
  $fake_podman,
  <<'FAKE_PODMAN',
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "$FAKE_PODMAN_LOG"
if [[ "$1" == push ]]; then
  digest_file=
  while (($#)); do
    if [[ "$1" == --digestfile ]]; then
      digest_file="$2"
      shift 2
    else
      shift
    fi
  done
  if [[ -z "$digest_file" ]]; then
    printf 'missing digest file\n' >&2
    exit 64
  fi
  printf '%s\n' "${FAKE_PODMAN_DIGEST:?}" > "$digest_file"
fi
FAKE_PODMAN
);

my $sha = '1' x 40;
my $digest = 'sha256:' . ('a' x 64);
my $other_digest = 'sha256:' . ('b' x 64);
my $repository = 'quay.io/overnet/relay';

subtest 'registry lookup returns an existing digest' => sub {
  my $result = _run(
    [ $lookup, $repository, "sha-$sha" ],
    FAKE_CURL_MODE => 'exists',
    FAKE_CURL_DIGEST => $digest,
  );
  is $result->{exit}, 0, 'lookup succeeds';
  is $result->{stdout}, "$digest\n", 'lookup prints the registry digest';
  is $result->{stderr}, '', 'lookup is quiet on success';
  like _slurp($curl_log), qr{/v2/overnet/relay/manifests/sha-$sha\s*\z}mx,
    'lookup uses the standard registry manifest endpoint';
};

subtest 'registry lookup treats only 404 as absence' => sub {
  my $missing = _run(
    [ $lookup, $repository, "sha-$sha" ],
    FAKE_CURL_MODE => 'missing',
  );
  is $missing->{exit}, 0, 'missing tag is a successful lookup';
  is $missing->{stdout}, '', 'missing tag has no digest';

  for my $case (
    [ 'server-error', 'non-404 registry response' ],
    [ 'transport-error', 'transport failure' ],
    [ 'invalid-digest', 'malformed digest' ],
  ) {
    my $result = _run(
      [ $lookup, $repository, "sha-$sha" ],
      FAKE_CURL_MODE => $case->[0],
    );
    isnt $result->{exit}, 0, "$case->[1] fails closed";
  }
};

subtest 'registry inputs reject path and tag injection' => sub {
  for my $case (
    [ 'quay.io/../relay', "sha-$sha", 'repository traversal' ],
    [ $repository, '../main', 'tag traversal' ],
  ) {
    my $result = _run(
      [ $lookup, $case->[0], $case->[1] ],
      FAKE_CURL_MODE => 'transport-error',
    );
    is $result->{exit}, 64, "$case->[2] is rejected as usage error";
    ok !-e $curl_log || !-s $curl_log, 'invalid input never reaches curl';
  }
};

subtest 'new commit tags are published before main' => sub {
  my $summary = File::Spec->catfile($temp, 'new-summary');
  my $result = _run(
    [ $publish, 'overnet-relay:ci', $repository, $sha, '', $summary ],
    FAKE_CURL_MODE => 'missing',
    FAKE_PODMAN_DIGEST => $digest,
  );
  is $result->{exit}, 0, 'new image publication succeeds';
  is [ _lines($podman_log) ], [
    "tag overnet-relay:ci $repository:sha-$sha",
    "push --digestfile <digest-file> $repository:sha-$sha",
    "tag overnet-relay:ci $repository:main",
    "push --digestfile <digest-file> $repository:main",
  ], 'commit image is sealed before main is moved';
  like _slurp($summary), qr{Published.*\Q$repository:sha-$sha\E\@\Q$digest\E}mx,
    'summary records the newly published immutable reference';
};

subtest 'existing commit tags are reused without a push' => sub {
  my $summary = File::Spec->catfile($temp, 'existing-summary');
  my $result = _run(
    [ $publish, 'overnet-relay:ci', $repository, $sha, $digest, $summary ],
    FAKE_CURL_MODE => 'exists',
    FAKE_CURL_DIGEST => $digest,
    FAKE_PODMAN_DIGEST => $digest,
  );
  is $result->{exit}, 0, 'existing image publication succeeds';
  is [ _lines($podman_log) ], [
    "tag overnet-relay:ci $repository:main",
    "push --digestfile <digest-file> $repository:main",
  ], 'existing commit tag is never tagged or pushed';
  like _slurp($summary), qr{Reused.*\Q$repository:sha-$sha\E\@\Q$digest\E}mx,
    'summary records the reused immutable reference';
};

subtest 'a reused commit tag must remain on the tested digest' => sub {
  my $summary = File::Spec->catfile($temp, 'moved-summary');
  my $result = _run(
    [ $publish, 'overnet-relay:ci', $repository, $sha, $digest, $summary ],
    FAKE_CURL_MODE => 'exists',
    FAKE_CURL_DIGEST => $other_digest,
    FAKE_PODMAN_DIGEST => $digest,
  );
  isnt $result->{exit}, 0, 'moved existing tag fails publication';
  like $result->{stderr}, qr{changed\s+during\s+verification}mx,
    'failure identifies the changed tag';
  ok !-e $podman_log || !-s $podman_log, 'main is not moved after the change';
};

subtest 'a tag appearing during a build stops publication' => sub {
  my $summary = File::Spec->catfile($temp, 'race-summary');
  my $result = _run(
    [ $publish, 'overnet-relay:ci', $repository, $sha, '', $summary ],
    FAKE_CURL_MODE => 'exists',
    FAKE_CURL_DIGEST => $other_digest,
    FAKE_PODMAN_DIGEST => $digest,
  );
  isnt $result->{exit}, 0, 'racing commit tag fails publication';
  like $result->{stderr}, qr{refusing\s+to\s+overwrite}mx,
    'failure explains the write-once violation';
  ok !-e $podman_log || !-s $podman_log, 'nothing is pushed after the race';
};

subtest 'digest mismatches stop publication' => sub {
  my $summary = File::Spec->catfile($temp, 'mismatch-summary');
  my $result = _run(
    [ $publish, 'overnet-relay:ci', $repository, $sha, $digest, $summary ],
    FAKE_CURL_MODE => 'exists',
    FAKE_CURL_DIGEST => $digest,
    FAKE_PODMAN_DIGEST => $other_digest,
  );
  isnt $result->{exit}, 0, 'main digest mismatch fails publication';
  like $result->{stderr}, qr{digest\s+mismatch}mx,
    'failure identifies the digest mismatch';
};

done_testing;

sub _lines {
  my ($path) = @_;
  return () if !-e $path;
  my @lines = split /\n/, _slurp($path);
  s{--digestfile\s+\S+}{--digestfile <digest-file>} for @lines;
  return @lines;
}

sub _run {
  my ($command, %extra_env) = @_;
  unlink $curl_log if -e $curl_log;
  unlink $podman_log if -e $podman_log;

  local %ENV = %ENV;
  $ENV{PATH} = "$fake_bin:$ENV{PATH}";
  $ENV{FAKE_CURL_LOG} = $curl_log;
  $ENV{FAKE_PODMAN_LOG} = $podman_log;
  @ENV{keys %extra_env} = values %extra_env;

  my $stderr = gensym;
  my $pid = open3(undef, my $stdout, $stderr, @{$command});
  my $out = do { local $/; <$stdout> // '' };
  my $err = do { local $/; <$stderr> // '' };
  waitpid $pid, 0;

  return {
    exit => $? >> 8,
    stdout => $out,
    stderr => $err,
  };
}

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't open $path: $!";
  local $/ = undef;
  return <$fh>;
}

sub _write_executable {
  my ($path, $contents) = @_;
  open my $fh, '>', $path or die "Can't write $path: $!";
  print {$fh} $contents;
  close $fh or die "Can't close $path: $!";
  chmod 0700, $path or die "Can't make $path executable: $!";
}
