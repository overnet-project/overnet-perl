use strictures 2;
use Test2::V0;
use JSON ();
use FindBin;
use File::Spec;

use lib File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib');

use Overnet::Adapter::IRC;
use Overnet::Core::ProfileContract;

my $spec_root    = _spec_root();
my @contracts    = _contract_set($spec_root);
my $contract_set = Overnet::Core::ProfileContract::validate_contract_set(\@contracts);
ok $contract_set->{valid}, 'IRC adapter profile contract set is valid'
  or diag(JSON->new->canonical(1)->pretty(1)->encode($contract_set->{errors}));

my $adapter = Overnet::Adapter::IRC->new;

for my $path (_fixture_paths($spec_root, 'irc')) {
  my $fixture = _load_json($path);
  next unless $fixture->{expected}{overnet_valid};

  subtest _case_name($path, $fixture) => sub {
    my $result = $adapter->map_input(%{$fixture->{input}});
    ok $result->{valid}, 'adapter maps fixture input';
    _assert_profile_event_valid($result->{event}, \@contracts);
  };
}

for my $path (_fixture_paths($spec_root, 'irc-derived')) {
  my $fixture = _load_json($path);
  next unless $fixture->{expected}{overnet_valid};

  subtest _case_name($path, $fixture) => sub {
    my $result = $adapter->derive_channel_presence(%{$fixture->{input}});
    ok $result->{valid}, 'adapter derives fixture input';
    _assert_profile_event_valid($result->{event}, \@contracts);
  };
}

done_testing;

sub _assert_profile_event_valid {
  my ($event, $contracts) = @_;
  my $result = Overnet::Core::ProfileContract::validate_profile_event(
    event     => $event,
    contracts => $contracts,
  );

  ok $result->{applicable}, 'profile contract applies to adapter event';
  ok $result->{valid}, 'adapter event satisfies profile contract'
    or diag(JSON->new->canonical(1)->pretty(1)->encode($result->{errors}));
  return;
}

sub _contract_set {
  my ($spec_root) = @_;
  my $fixture = _load_json(
    File::Spec->catfile($spec_root, 'fixtures', 'profile-contracts', 'valid-irc-adapter-contract-set.json',));

  return
    map { _load_json(File::Spec->catfile($spec_root, split m{/}mx, $_))->{input}{contract} }
    @{$fixture->{input}{contract_fixtures}};
}

sub _fixture_paths {
  my ($spec_root, $family) = @_;
  my $dir = File::Spec->catdir($spec_root, 'fixtures', $family);
  opendir my $dh, $dir or die "Can't open $dir: $!";
  my @files = sort grep {/\.json\z/mx} readdir $dh;
  closedir $dh;
  return map { File::Spec->catfile($dir, $_) } @files;
}

sub _case_name {
  my ($path, $fixture) = @_;
  my ($file) = $path =~ m{([^/]+)\z}mx;
  return "$file - $fixture->{description}";
}

sub _load_json {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;
  return JSON::decode_json($json);
}

sub _spec_root {
  for my $dir (
    File::Spec->catdir($FindBin::Bin, '..', '..', '..', 'spec'),
    File::Spec->catdir($FindBin::Bin, '..', '..', 'spec'),
  ) {
    my $abs = File::Spec->rel2abs($dir);
    return $abs if -d $abs;
  }

  die "Can't locate spec root\n";
}
