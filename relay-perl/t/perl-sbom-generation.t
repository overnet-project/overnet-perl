use strictures 2;

use File::Path qw(make_path);
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IPC::Open3;
use JSON::PP ();
use Symbol qw(gensym);
use Test2::V0;

my $code_root = File::Spec->catdir($FindBin::Bin, '..');
my $generator = File::Spec->catfile(
  $code_root, 'deploy', 'podman', 'generate-perl-sbom.pl'
);
my $temp = tempdir(CLEANUP => 1);
my $json = JSON::PP->new->canonical->pretty;

ok -f $generator, 'Perl SBOM generator exists';
ok -x $generator, 'Perl SBOM generator is executable';

subtest 'inventories CPAN and local distributions deterministically' => sub {
  my $fixture = _fixture('complete');
  my $output  = File::Spec->catfile($fixture->{dir}, 'perl.spdx.json');
  my $result  = _run(
    '--root',           $fixture->{root},
    '--local-metadata', "$fixture->{local_meta}=Overnet",
    '--output',         $output,
  );

  is $result->{exit}, 0, 'complete inventory succeeds';
  is $result->{stderr}, '', 'complete inventory has no diagnostics';
  like $result->{stdout}, qr{wrote Perl SPDX inventory: 2 distributions\b}m,
    'success reports the distribution count';

  my $document = _read_json($output);
  is $document->{spdxVersion}, 'SPDX-2.3', 'generator emits SPDX 2.3';
  is $document->{dataLicense}, 'CC0-1.0', 'SPDX data license is explicit';
  is $document->{creationInfo}{created}, '1970-01-01T00:00:00Z',
    'SOURCE_DATE_EPOCH controls the creation timestamp';
  like $document->{documentNamespace},
    qr{\Ahttps://github\.com/overnet-project/overnet-perl/sbom/perl/sha256-[0-9a-f]{64}\z},
    'document namespace is content-addressed';

  my %packages = map { $_->{name} => $_ } @{$document->{packages}};
  is [sort keys %packages], ['Moo', 'Overnet-Core'],
    'all CPAN and local distributions are included';
  is $packages{Moo}{versionInfo}, '2.005005', 'CPAN version is exact';
  is $packages{'Overnet-Core'}{versionInfo}, '0.001', 'local version is exact';
  is _purl($packages{Moo}), 'pkg:cpan/Moo@2.005005',
    'CPAN distribution has a CPAN package URL';
  is _purl($packages{'Overnet-Core'}), 'pkg:generic/Overnet-Core@0.001',
    'local distribution has a generic package URL';
  is $packages{Moo}{downloadLocation},
    'https://cpan.metacpan.org/authors/id/H/HA/HAARG/Moo-2.005005.tar.gz',
    'CPAN download location comes from cpanm install metadata';
  is $packages{'Overnet-Core'}{downloadLocation}, 'NOASSERTION',
    'local source does not claim a CPAN download location';
  is scalar @{$document->{relationships}}, 2,
    'document describes every inventoried distribution';

  my $second = File::Spec->catfile($fixture->{dir}, 'perl-second.spdx.json');
  is _run(
    '--root',           $fixture->{root},
    '--local-metadata', "$fixture->{local_meta}=Overnet",
    '--output',         $second,
  )->{exit}, 0, 'second generation succeeds';
  is _slurp($second), _slurp($output),
    'identical inputs and SOURCE_DATE_EPOCH produce identical output';
};

subtest 'fails closed when installation evidence is incomplete' => sub {
  my @cases = (
    [
      'unclaimed packlist',
      sub {
        my ($fixture) = @_;
        _write(
          File::Spec->catfile(
            $fixture->{root}, 'lib', 'perl5', 'arch', 'auto', 'Unknown', '.packlist'
          ),
          "/tmp/unknown.pm\n",
        );
      },
      qr{unclaimed \.packlist.*Unknown}ms,
    ],
    [
      'missing cpanm install metadata',
      sub {
        my ($fixture) = @_;
        unlink $fixture->{install_meta} or die "Can't unlink $fixture->{install_meta}: $!";
      },
      qr{missing paired install\.json}m,
    ],
    [
      'metadata version mismatch',
      sub {
        my ($fixture) = @_;
        my $install = _read_json($fixture->{install_meta});
        $install->{version} = '1.0';
        _write_json($fixture->{install_meta}, $install);
      },
      qr{version mismatch}m,
    ],
    [
      'distribution mismatch',
      sub {
        my ($fixture) = @_;
        my $install = _read_json($fixture->{install_meta});
        $install->{dist} = 'Different-2.005005';
        _write_json($fixture->{install_meta}, $install);
      },
      qr{distribution mismatch}m,
    ],
    [
      'missing local packlist',
      sub {
        my ($fixture) = @_;
        unlink $fixture->{local_packlist}
          or die "Can't unlink $fixture->{local_packlist}: $!";
      },
      qr{no \.packlist.*Overnet}ms,
    ],
  );

  for my $case (@cases) {
    my $fixture = _fixture($case->[0]);
    $case->[1]->($fixture);
    my $result = _run(
      '--root',           $fixture->{root},
      '--local-metadata', "$fixture->{local_meta}=Overnet",
      '--output',         File::Spec->catfile($fixture->{dir}, 'out.json'),
    );
    isnt $result->{exit}, 0, "$case->[0] fails";
    like $result->{stderr}, $case->[2], "$case->[0] has a specific diagnostic";
  }
};

subtest 'rejects malformed invocation and metadata' => sub {
  my $without_args = _run();
  isnt $without_args->{exit}, 0, 'missing arguments fail';
  like $without_args->{stderr}, qr{usage:}m, 'missing arguments show usage';

  my $fixture = _fixture('malformed');
  _write($fixture->{cpan_meta}, "{not json\n");
  my $malformed = _run(
    '--root',           $fixture->{root},
    '--local-metadata', "$fixture->{local_meta}=Overnet",
    '--output',         File::Spec->catfile($fixture->{dir}, 'out.json'),
  );
  isnt $malformed->{exit}, 0, 'malformed metadata fails';
  like $malformed->{stderr}, qr{invalid JSON}m, 'malformed JSON is identified';
};

done_testing;

sub _fixture {
  my ($label) = @_;
  $label =~ s/[^A-Za-z0-9]+/-/g;
  my $dir  = File::Spec->catdir($temp, $label);
  my $root = File::Spec->catdir($dir, 'runtime');
  my $meta_dir = File::Spec->catdir(
    $root, 'lib', 'perl5', 'arch', '.meta', 'Moo-2.005005'
  );
  my $cpan_meta    = File::Spec->catfile($meta_dir, 'MYMETA.json');
  my $install_meta = File::Spec->catfile($meta_dir, 'install.json');
  my $moo_packlist = File::Spec->catfile(
    $root, 'lib', 'perl5', 'arch', 'auto', 'Moo', '.packlist'
  );
  my $local_meta = File::Spec->catfile($dir, 'Overnet-Core-MYMETA.json');
  my $local_packlist = File::Spec->catfile(
    $root, 'lib', 'perl5', 'arch', 'auto', 'Overnet', '.packlist'
  );

  make_path($meta_dir, File::Spec->catdir($root, 'lib', 'perl5', 'arch', 'auto', 'Moo'));
  make_path(File::Spec->catdir($root, 'lib', 'perl5', 'arch', 'auto', 'Overnet'));
  _write_json($cpan_meta, {
    abstract => 'Minimal object system',
    license  => ['perl_5'],
    name     => 'Moo',
    version  => '2.005005',
  });
  _write_json($install_meta, {
    dist     => 'Moo-2.005005',
    name     => 'Moo',
    pathname => 'H/HA/HAARG/Moo-2.005005.tar.gz',
    target   => 'H/HA/HAARG/Moo-2.005005.tar.gz',
    version  => 'v2.005005',
  });
  _write($moo_packlist, "/runtime/lib/perl5/Moo.pm\n");
  _write_json($local_meta, {
    abstract => 'Overnet core',
    license  => ['gpl_3'],
    name     => 'Overnet-Core',
    version  => '0.001',
  });
  _write($local_packlist, "/runtime/lib/perl5/Overnet.pm\n");

  return {
    cpan_meta     => $cpan_meta,
    dir           => $dir,
    install_meta  => $install_meta,
    local_meta    => $local_meta,
    local_packlist => $local_packlist,
    root          => $root,
  };
}

sub _run {
  my (@args) = @_;
  my $stderr = gensym;
  local $ENV{SOURCE_DATE_EPOCH} = 0;
  my $pid = open3(my $in, my $out, $stderr, $^X, $generator, @args);
  close $in;
  my $stdout = do { local $/; <$out>    // '' };
  my $errors = do { local $/; <$stderr> // '' };
  waitpid $pid, 0;
  return {exit => $? >> 8, stdout => $stdout, stderr => $errors};
}

sub _purl {
  my ($package) = @_;
  my ($reference) = grep {
    ($_->{referenceType} // '') eq 'purl'
  } @{$package->{externalRefs} // []};
  return $reference ? $reference->{referenceLocator} : undef;
}

sub _read_json {
  my ($path) = @_;
  return JSON::PP->new->utf8->decode(_slurp($path));
}

sub _slurp {
  my ($path) = @_;
  open my $fh, '<:raw', $path or die "Can't open $path: $!";
  local $/ = undef;
  my $contents = <$fh>;
  close $fh or die "Can't close $path: $!";
  return $contents;
}

sub _write_json {
  my ($path, $value) = @_;
  _write($path, $json->encode($value));
}

sub _write {
  my ($path, $contents) = @_;
  my (undef, $directory) = File::Spec->splitpath($path);
  make_path($directory) if !-d $directory;
  open my $fh, '>:raw', $path or die "Can't write $path: $!";
  print {$fh} $contents;
  close $fh or die "Can't close $path: $!";
}
