use 5.040;
use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

my $root = File::Spec->catdir($FindBin::Bin, File::Spec->updir);
my $workflow_dir = File::Spec->catdir($root, '.github', 'workflows');

subtest 'policy semantics' => sub {
  my $sha = 'a' x 40;
  my $digest = 'b' x 64;
  my @cases = (
    [ "uses: actions/checkout\@$sha", undef, 'full action commit SHA' ],
    [ "uses: owner/repository/path/to/action\@$sha", undef, 'action subdirectory at a full SHA' ],
    [ "uses: owner/repository/.github/workflows/test.yml\@$sha", undef, 'reusable workflow at a full SHA' ],
    [ 'uses: ./path/to/action', undef, 'repository-local action' ],
    [ "uses: docker://ghcr.io/example/action\@sha256:$digest", undef, 'digest-pinned Docker action' ],
    [ 'uses: actions/checkout@v4', qr/not\s+pinned/mx, 'mutable major version' ],
    [ 'uses: actions/checkout@main', qr/not\s+pinned/mx, 'mutable branch' ],
    [ 'uses: actions/checkout@abcdef1', qr/not\s+pinned/mx, 'short commit SHA' ],
    [ 'uses: actions/checkout', qr/not\s+pinned/mx, 'missing action reference' ],
    [ 'uses: docker://alpine:3.22', qr/not\s+pinned/mx, 'mutable Docker action tag' ],
    [ 'uses: ${{ matrix.action }}', qr/not\s+pinned/mx, 'dynamic external action' ],
    [ '- { uses: actions/checkout@v4 }', qr/must\s+be\s+standalone/mx, 'inline action directive' ],
    [ '"uses": actions/checkout@v4', qr/must\s+be\s+standalone/mx, 'quoted action key' ],
    [ 'uses : actions/checkout@v4', qr/must\s+be\s+standalone/mx, 'spaced action key' ],
    [ 'uses: ./../outside/action', qr/not\s+pinned/mx, 'local path traversal' ],
    [ '# uses: actions/checkout@v4', undef, 'commented action directive' ],
  );

  for my $case (@cases) {
    my ($line, $expected, $name) = @{$case};
    my $violation = _uses_violation($line);
    if (defined $expected) {
      like $violation, $expected, "$name is rejected";
    }
    else {
      is $violation, undef, "$name is allowed";
    }
  }
};

opendir my $workflow_dh, $workflow_dir
  or die "unable to open $workflow_dir: $!";
my @workflows = sort map { File::Spec->catfile($workflow_dir, $_) }
  grep { /[.]ya?ml\z/mx } readdir $workflow_dh;
closedir $workflow_dh
  or die "unable to close $workflow_dir: $!";

ok @workflows, 'repository has GitHub Actions workflows to inspect';

my $external_actions = 0;
for my $workflow (@workflows) {
  open my $fh, '<', $workflow
    or die "unable to open $workflow: $!";

  my $line_number = 0;
  while (my $line = <$fh>) {
    ++$line_number;
    next if !_contains_uses_directive($line);
    ++$external_actions if $line !~ m{uses:\s*["']?[.]/}mx;

    my $violation = _uses_violation($line);
    my $relative = File::Spec->abs2rel($workflow, $root);
    ok !defined $violation,
      "$relative:$line_number pins its external action to an immutable digest"
      or diag $violation;
  }

  close $fh or die "unable to close $workflow: $!";
}

cmp_ok $external_actions, '>', 0,
  'policy inspected at least one external action reference';

my $dependabot = _slurp(File::Spec->catfile($root, '.github', 'dependabot.yml'));
my ($actions_updates) = $dependabot =~ m{
  (^\s+-\s+package-ecosystem:\s*["']github-actions["'].*?)
  (?=^\s+-\s+package-ecosystem:|\z)
}msx;
ok defined $actions_updates,
  'Dependabot maintains pinned GitHub Action references';
if (defined $actions_updates) {
  like $actions_updates, qr{^\s+directory:\s*["']/["']\s*$}mx,
    'GitHub Actions updates cover the repository workflow directory';
  like $actions_updates, qr{^\s+interval:\s*["']weekly["']\s*$}mx,
    'GitHub Actions updates run weekly';
}

my $layout_workflow = _slurp(File::Spec->catfile($workflow_dir, 'monorepo-test.yml'));
like $layout_workflow, qr{run:\s+prove\s+-v\s+t/[*][.]t\s*$}mx,
  'monorepo CI executes every root policy test';

done_testing;

sub _uses_violation {
  my ($line) = @_;
  return if $line =~ /^\s*[#]/mx;
  if ($line !~ /^\s*(?:-\s*)?uses:\s*(.*?)\s*$/mx) {
    return 'uses directive must be standalone for immutable-reference validation'
      if _contains_uses_directive($line);
    return;
  }

  my $reference = $1;
  $reference =~ s/\s+[#].*\z//mx;
  if ($reference =~ /\A(["'])(.*)\1\z/mx) {
    $reference = $2;
  }

  if ($reference =~ m{\A[.]/}mx) {
    my @segments = split m{/}mx, substr($reference, 2);
    return if @segments
      && !grep { $_ eq '.' || $_ eq '..' || $_ !~ /\A[A-Za-z0-9_.-]+\z/mx }
        @segments;
  }
  return if $reference =~ m{
    \Adocker://[A-Za-z0-9._/:+-]+[\@]sha256:[0-9a-f]{64}\z
  }mx;
  return if $reference =~ m{
    \A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+
    (?:/[A-Za-z0-9_./-]+)?
    [\@][0-9a-f]{40}\z
  }mx;

  return "external action '$reference' is not pinned to a full commit SHA or image digest";
}

sub _contains_uses_directive {
  my ($line) = @_;
  return if $line =~ /^\s*[#]/mx;
  return 1 if $line =~ /^\s*(?:-\s*)?uses\s*:/mx;
  return 1 if $line =~ /^\s*(?:-\s*)?["']uses["']\s*:/mx;
  return 1 if $line =~ /(?:\A|[{,])\s*["']?uses["']?\s*:/mx;
  return;
}

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "unable to open $path: $!";
  local $/ = undef;
  return <$fh>;
}
