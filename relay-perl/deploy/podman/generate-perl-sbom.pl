#!/usr/bin/env perl

use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use File::Find qw(find);
use File::Path qw(make_path);
use File::Spec;
use Getopt::Long qw(GetOptionsFromArray);
use JSON::PP ();
use POSIX qw(strftime);

sub _usage {
  return "usage: $0 --root DIR --output FILE "
    . "[--local-metadata MYMETA.json=Module::Name ...]\n";
}

sub _fail {
  my ($message) = @_;
  die "Perl SBOM generation failed: $message\n";
}

sub _read_json {
  my ($path) = @_;
  open my $fh, '<:raw', $path or _fail("cannot open $path: $!");
  local $/ = undef;
  my $contents = <$fh>;
  close $fh or _fail("cannot close $path: $!");
  my $value = eval { JSON::PP->new->utf8->decode($contents) };
  _fail("invalid JSON in $path: $@") if $@;
  ref($value) eq 'HASH' or _fail("metadata in $path must be a JSON object");
  return $value;
}

sub _nonempty_scalar {
  my ($value) = @_;
  return defined($value) && !ref($value) && "$value" =~ /\S/mxs;
}

sub _metadata_identity {
  my ($metadata, $path) = @_;
  _nonempty_scalar($metadata->{name})
    or _fail("metadata name must be a non-empty scalar in $path");
  _nonempty_scalar($metadata->{version})
    or _fail("metadata version must be a non-empty scalar in $path");
  my $name    = "$metadata->{name}";
  my $version = "$metadata->{version}";
  $name =~ /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/mxs
    or _fail("unsupported distribution name in $path: $name");
  $version =~ /\A[A-Za-z0-9][A-Za-z0-9._+~-]*\z/mxs
    or _fail("unsupported distribution version in $path: $version");
  return ($name, $version);
}

sub _purl_escape {
  my ($value) = @_;
  my $escaped = q{};
  for my $character (split //, $value) {
    if ($character =~ /[A-Za-z0-9._~-]/mxs) {
      $escaped .= $character;
    }
    else {
      $escaped .= sprintf '%%%02X', ord $character;
    }
  }
  return $escaped;
}

sub _discover_files {
  my ($root, $wanted) = @_;
  my @paths;
  find(
    {
      no_chdir => 1,
      wanted   => sub {
        return if !-f $_;
        push @paths, $File::Find::name if $wanted->($File::Find::name);
      },
    },
    $root,
  );
  return sort @paths;
}

sub _packlist_for_target {
  my ($target, $packlists, $metadata_path) = @_;
  $target =~ /\A[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\z/mxs
    or _fail("invalid install target in $metadata_path: $target");
  (my $relative = $target) =~ s{::}{/}g;
  my @matches = grep {
    my $path = $_;
    $path =~ s{\\}{/}g;
    $path =~ m{(?:\A|/)auto/\Q$relative\E/\.packlist\z}mxs;
  } @{$packlists};
  @matches == 1
    or _fail(
      @matches
      ? "multiple .packlist files claim $target from $metadata_path"
      : "no .packlist found for $target from $metadata_path"
    );
  return $matches[0];
}

sub _cpan_download_location {
  my ($pathname, $metadata_path) = @_;
  _nonempty_scalar($pathname)
    or _fail("cpanm pathname must be a non-empty scalar in $metadata_path");
  $pathname = "$pathname";
  $pathname !~ m{(?:\A|/)\.\.?(/|\z)}mxs
    or _fail("unsafe cpanm pathname in $metadata_path: $pathname");
  $pathname =~ /\A[A-Za-z0-9][A-Za-z0-9._+\/-]*\z/mxs
    or _fail("unsupported cpanm pathname in $metadata_path: $pathname");
  return "https://cpan.metacpan.org/authors/id/$pathname";
}

sub _package {
  my (%args) = @_;
  my ($name, $version) = _metadata_identity($args{metadata}, $args{metadata_path});
  my $type = $args{type};
  my $purl = join q{}, 'pkg:', $type, '/', _purl_escape($name), '@', _purl_escape($version);
  my $id   = 'SPDXRef-Perl-' . substr(sha256_hex($purl), 0, 24);
  my $package = {
    SPDXID           => $id,
    name             => $name,
    versionInfo      => $version,
    downloadLocation => $args{download_location},
    filesAnalyzed    => JSON::PP::false,
    licenseConcluded => 'NOASSERTION',
    licenseDeclared  => 'NOASSERTION',
    copyrightText    => 'NOASSERTION',
    externalRefs     => [
      {
        referenceCategory => 'PACKAGE-MANAGER',
        referenceType     => 'purl',
        referenceLocator  => $purl,
      },
    ],
  };
  if (_nonempty_scalar($args{metadata}{abstract})) {
    $package->{summary} = "$args{metadata}{abstract}";
  }
  return ($package, $purl, $name, $version);
}

my %options = (local_metadata => []);
GetOptionsFromArray(
  \@ARGV,
  'root=s'           => \$options{root},
  'output=s'         => \$options{output},
  'local-metadata=s@' => $options{local_metadata},
) or die _usage();
@ARGV == 0 && _nonempty_scalar($options{root}) && _nonempty_scalar($options{output})
  or die _usage();

my $root = File::Spec->rel2abs($options{root});
-d $root or _fail("runtime root is not a directory: $root");
my @packlists = _discover_files($root, sub { $_[0] =~ m{/\.packlist\z}mxs });
@packlists or _fail("no .packlist files found below $root");

my @cpan_metadata = _discover_files(
  $root,
  sub { $_[0] =~ m{/\.meta/[^/]+/MYMETA\.json\z}mxs },
);
my @packages;
my %claimed_packlists;
my %seen_purls;
my @identities;

for my $metadata_path (@cpan_metadata) {
  (my $install_path = $metadata_path) =~ s{MYMETA\.json\z}{install.json};
  -f $install_path
    or _fail("missing paired install.json for $metadata_path");
  my $metadata = _read_json($metadata_path);
  my $install  = _read_json($install_path);
  my ($name, $version) = _metadata_identity($metadata, $metadata_path);
  _nonempty_scalar($install->{version})
    or _fail("install version must be a non-empty scalar in $install_path");
  (my $metadata_version = $version) =~ s/\Av//mxs;
  (my $install_version = "$install->{version}") =~ s/\Av//mxs;
  $metadata_version eq $install_version
    or _fail("version mismatch between $metadata_path and $install_path");
  _nonempty_scalar($install->{dist})
    or _fail("install distribution must be a non-empty scalar in $install_path");
  "$install->{dist}" eq "$name-$version"
    or _fail("distribution mismatch between $metadata_path and $install_path");
  _nonempty_scalar($install->{name})
    or _fail("installed module name must be a non-empty scalar in $install_path");
  my $packlist = _packlist_for_target("$install->{name}", \@packlists, $install_path);
  !$claimed_packlists{$packlist}++
    or _fail(".packlist claimed by multiple distributions: $packlist");
  my ($package, $purl) = _package(
    metadata          => $metadata,
    metadata_path     => $metadata_path,
    type              => 'cpan',
    download_location => _cpan_download_location($install->{pathname}, $install_path),
  );
  !$seen_purls{$purl}++ or _fail("duplicate package URL: $purl");
  push @packages,   $package;
  push @identities, $purl;
}

for my $specification (@{$options{local_metadata}}) {
  my ($metadata_path, $target) = $specification =~ /\A(.+)=([^=]+)\z/mxs;
  defined($metadata_path) && defined($target)
    or _fail("invalid --local-metadata value: $specification");
  -f $metadata_path or _fail("local metadata is not a regular file: $metadata_path");
  my $metadata = _read_json($metadata_path);
  my $packlist = _packlist_for_target($target, \@packlists, $metadata_path);
  !$claimed_packlists{$packlist}++
    or _fail(".packlist claimed by multiple distributions: $packlist");
  my ($package, $purl) = _package(
    metadata          => $metadata,
    metadata_path     => $metadata_path,
    type              => 'generic',
    download_location => 'NOASSERTION',
  );
  !$seen_purls{$purl}++ or _fail("duplicate package URL: $purl");
  push @packages,   $package;
  push @identities, $purl;
}

my @unclaimed = grep { !$claimed_packlists{$_} } @packlists;
_fail("unclaimed .packlist files:\n" . join("\n", @unclaimed)) if @unclaimed;
@packages or _fail('no Perl distributions were inventoried');

@packages = sort {
  $a->{name} cmp $b->{name} || $a->{versionInfo} cmp $b->{versionInfo}
} @packages;
my $epoch = exists $ENV{SOURCE_DATE_EPOCH} ? $ENV{SOURCE_DATE_EPOCH} : time;
defined($epoch) && !ref($epoch) && $epoch =~ /\A\d+\z/mxs
  or _fail('SOURCE_DATE_EPOCH must be a non-negative integer');
my $identity_hash = sha256_hex(join "\n", sort @identities);
my $document = {
  spdxVersion       => 'SPDX-2.3',
  dataLicense       => 'CC0-1.0',
  SPDXID            => 'SPDXRef-DOCUMENT',
  name              => 'Overnet relay Perl distributions',
  documentNamespace => "https://github.com/overnet-project/overnet-perl/sbom/perl/sha256-$identity_hash",
  creationInfo      => {
    created  => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime $epoch),
    creators => ['Tool: overnet-perl-sbom-1'],
  },
  packages      => \@packages,
  relationships => [
    map {
      {
        spdxElementId      => 'SPDXRef-DOCUMENT',
        relationshipType  => 'DESCRIBES',
        relatedSpdxElement => $_->{SPDXID},
      }
    } @packages
  ],
};

my $output = File::Spec->rel2abs($options{output});
my (undef, $output_directory) = File::Spec->splitpath($output);
make_path($output_directory) if !-d $output_directory;
my $temporary = "$output.tmp.$$";
open my $output_fh, '>:raw', $temporary
  or _fail("cannot create $temporary: $!");
print {$output_fh} JSON::PP->new->canonical->pretty->utf8->encode($document), "\n"
  or _fail("cannot write $temporary: $!");
close $output_fh or _fail("cannot close $temporary: $!");
rename $temporary, $output or _fail("cannot replace $output: $!");

my $count = scalar @packages;
print "wrote Perl SPDX inventory: $count distributions\n";
