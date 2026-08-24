use 5.040;
use strict;
use warnings;

use File::Spec;
use FindBin;
use Test::More;

my $root = File::Spec->catdir($FindBin::Bin, File::Spec->updir);

my @components = qw(
  core-perl
  relay-perl
  adapter-irc-perl
  overnet-burner
  overnet-perl-style
);

for my $component (@components) {
  my $component_root = File::Spec->catdir($root, $component);
  ok -d $component_root, "$component is present";
  ok -f File::Spec->catfile($component_root, 'Makefile.PL'),
    "$component remains an independent Perl distribution";
  ok !-d File::Spec->catdir($component_root, '.github', 'workflows'),
    "$component does not retain inactive nested workflows";
}

for my $workflow (qw(
  adapter-irc-mutation.yml
  adapter-irc-test.yml
  burner-mutation.yml
  burner-test.yml
  core-mutation.yml
  core-test.yml
  monorepo-test.yml
  relay-container.yml
  relay-mutation.yml
  relay-test.yml
  style-mutation.yml
  style-test.yml
)) {
  ok -f File::Spec->catfile($root, '.github', 'workflows', $workflow),
    "$workflow is active at the monorepo root";
}

for my $workflow (qw(
  adapter-irc-mutation.yml
  adapter-irc-test.yml
  burner-mutation.yml
  burner-test.yml
  core-mutation.yml
  core-test.yml
  relay-mutation.yml
  relay-test.yml
)) {
  my $content = _slurp(File::Spec->catfile($root, '.github', 'workflows', $workflow));
  my $dependency_steps = () = $content =~ /name:\s+Install\s+dependencies/gmx;
  my $coherent_nostr_installs = () = $content =~ m{
    cpanm\s+--local-lib\s+~/perl5\s+--notest\s+--reinstall\s+
    Net::Nostr::Core\s+Net::Nostr::Client\s+Net::Nostr::Relay
  }gmx;
  is $coherent_nostr_installs, $dependency_steps,
    "$workflow refreshes every split Net::Nostr distribution in each dependency step";
}

my $gitignore = _slurp(File::Spec->catfile($root, '.gitignore'));
like $gitignore, qr{^/\.plx/$}mx,
  'machine-local plx state is excluded from the monorepo';
like $gitignore, qr{^/spec$}mx,
  'the machine-local specification checkout or symlink is excluded from the monorepo';

done_testing;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "unable to open $path: $!";
  local $/ = undef;
  return <$fh>;
}
