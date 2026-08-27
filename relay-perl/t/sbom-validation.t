use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IPC::Open3;
use JSON::PP ();
use Symbol   qw(gensym);
use Test2::V0;

my $code_root = File::Spec->catdir($FindBin::Bin, '..');
my $validator = File::Spec->catfile($code_root, 'deploy', 'podman', 'validate-sbom.pl');
my $temp      = tempdir(CLEANUP => 1);
my $json      = JSON::PP->new->canonical;
my $sequence  = 0;

ok -f $validator, 'SBOM validator exists';
ok -x $validator, 'SBOM validator is executable';

my $valid = {
  spdxVersion       => 'SPDX-2.3',
  dataLicense       => 'CC0-1.0',
  SPDXID            => 'SPDXRef-DOCUMENT',
  name              => 'quay.io/overnet/relay',
  documentNamespace => 'https://anchore.com/syft/image/test',
  creationInfo      => {
    created  => '2026-08-26T12:34:56Z',
    creators => ['Organization: Anchore, Inc', 'Tool: syft-1.42.3'],
  },
  packages => [
    {
      SPDXID           => 'SPDXRef-Package-perl',
      name             => 'perl',
      downloadLocation => 'NOASSERTION',
    },
  ],
};

subtest 'accepts a populated Syft SPDX 2.3 document' => sub {
  my $result = _validate($valid);
  is $result->{exit}, 0, 'valid SBOM succeeds';
  like $result->{stdout}, qr{validated SPDX 2\.3 SBOM: 1 package\b}m, 'success reports the package count';
  is $result->{stderr}, '', 'valid SBOM has no diagnostics';
};

subtest 'rejects malformed or empty documents' => sub {
  my $malformed = File::Spec->catfile($temp, 'malformed.json');
  _write($malformed, "{not json\n");
  my $malformed_result = _run($malformed);
  isnt $malformed_result->{exit}, 0, 'malformed JSON fails';
  like $malformed_result->{stderr}, qr{invalid JSON}m, 'malformed JSON is identified';

  my $empty = File::Spec->catfile($temp, 'empty.json');
  _write($empty, '');
  my $empty_result = _run($empty);
  isnt $empty_result->{exit}, 0, 'empty file fails';
  like $empty_result->{stderr}, qr{empty}m, 'empty file is identified';
};

subtest 'enforces the SPDX document contract' => sub {
  my @cases = (
    ['version',      sub { $_[0]->{spdxVersion}            = 'SPDX-2.2' },    qr{SPDX-2\.3}],
    ['license',      sub { $_[0]->{dataLicense}            = 'NOASSERTION' }, qr{CC0-1\.0}],
    ['document id',  sub { $_[0]->{SPDXID}                 = 'other' },       qr{SPDXRef-DOCUMENT}],
    ['name',         sub { $_[0]->{name}                   = '' },            qr{document name}],
    ['namespace',    sub { $_[0]->{documentNamespace}      = '' },            qr{namespace}],
    ['timestamp',    sub { $_[0]->{creationInfo}{created}  = 'yesterday' },   qr{timestamp}],
    ['Syft creator', sub { $_[0]->{creationInfo}{creators} = ['Person: Example'] }, qr{Syft creator}],
    ['packages',     sub { $_[0]->{packages}               = [] }, qr{at least one package}],
    ['package id',   sub { $_[0]->{packages}[0]{SPDXID}    = '../bad' }, qr{package SPDXID}],
    ['package name', sub { $_[0]->{packages}[0]{name}      = '' },       qr{package name}],
    [
      'duplicate package id',
      sub { push @{$_[0]->{packages}}, {%{$_[0]->{packages}[0]}} },
      qr{duplicate package SPDXID},
    ],
  );

  for my $case (@cases) {
    my $document = $json->decode($json->encode($valid));
    $case->[1]->($document);
    my $result = _validate($document);
    isnt $result->{exit}, 0, "$case->[0] violation fails";
    like $result->{stderr}, $case->[2], "$case->[0] failure is specific";
  }
};

subtest 'rejects unsafe invocation' => sub {
  my $missing = _run(File::Spec->catfile($temp, 'missing.json'));
  isnt $missing->{exit}, 0, 'missing file fails';
  like $missing->{stderr}, qr{regular file}m, 'missing file is identified';

  my $stderr = gensym;
  my $pid    = open3(my $in, my $out, $stderr, $^X, $validator);
  close $in;
  my $stdout_text = do { local $/; <$out>    // '' };
  my $stderr_text = do { local $/; <$stderr> // '' };
  waitpid $pid, 0;
  isnt $? >> 8,    0,  'missing argument fails';
  is $stdout_text, '', 'usage error has no standard output';
  like $stderr_text, qr{usage:}m, 'usage error explains invocation';
};

done_testing;

sub _validate {
  my ($document) = @_;
  ++$sequence;
  my $path = File::Spec->catfile($temp, "sbom-$sequence.json");
  _write($path, $json->encode($document));
  return _run($path);
}

sub _run {
  my ($path) = @_;
  my $stderr = gensym;
  my $pid    = open3(my $in, my $out, $stderr, $^X, $validator, $path);
  close $in;
  my $stdout = do { local $/; <$out>    // '' };
  my $errors = do { local $/; <$stderr> // '' };
  waitpid $pid, 0;
  return {exit => $? >> 8, stdout => $stdout, stderr => $errors};
}

sub _write {
  my ($path, $contents) = @_;
  open my $fh, '>', $path or die "Can't write $path: $!";
  print {$fh} $contents;
  close $fh or die "Can't close $path: $!";
}
