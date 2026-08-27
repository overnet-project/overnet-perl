#!/usr/bin/env perl

use strict;
use warnings;

use JSON::PP ();

sub _fail {
  my ($message) = @_;
  print STDERR "invalid SBOM: $message\n";
  exit 1;
}

sub _nonempty_string {
  my ($value) = @_;
  return defined($value) && !ref($value) && $value =~ /\S/;
}

@ARGV == 1 or do {
  print STDERR "usage: $0 SBOM.spdx.json\n";
  exit 64;
};

my ($path) = @ARGV;
-f $path or _fail("$path is not a regular file");
-s $path or _fail("$path is empty");

open my $fh, '<:raw', $path or _fail("cannot open $path: $!");
local $/ = undef;
my $contents = <$fh>;
close $fh or _fail("cannot close $path: $!");

my $document = eval { JSON::PP->new->utf8->decode($contents) };
_fail("invalid JSON: $@") if $@;
ref($document) eq 'HASH' or _fail('document must be a JSON object');

($document->{spdxVersion} // '') eq 'SPDX-2.3'
  or _fail('spdxVersion must be SPDX-2.3');
($document->{dataLicense} // '') eq 'CC0-1.0'
  or _fail('dataLicense must be CC0-1.0');
($document->{SPDXID} // '') eq 'SPDXRef-DOCUMENT'
  or _fail('document SPDXID must be SPDXRef-DOCUMENT');
_nonempty_string($document->{name})
  or _fail('document name must be a non-empty string');
_nonempty_string($document->{documentNamespace})
  or _fail('document namespace must be a non-empty string');

my $creation = $document->{creationInfo};
ref($creation) eq 'HASH' or _fail('creationInfo must be an object');
($creation->{created} // '') =~ /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\z/
  or _fail('creation timestamp must be UTC ISO 8601');
my $creators = $creation->{creators};
ref($creators) eq 'ARRAY' or _fail('creationInfo.creators must be an array');
grep { _nonempty_string($_) && /^Tool:\s*syft(?:\b|-)/i } @{$creators}
  or _fail('creationInfo must identify a Syft creator');

my $packages = $document->{packages};
ref($packages) eq 'ARRAY' && @{$packages}
  or _fail('document must contain at least one package');

my %package_ids;
for my $package (@{$packages}) {
  ref($package) eq 'HASH' or _fail('each package must be an object');
  my $id = $package->{SPDXID};
  _nonempty_string($id) && $id =~ /\ASPDXRef-[A-Za-z0-9.-]+\z/
    or _fail('each package SPDXID must be a valid SPDX identifier');
  !$package_ids{$id}++ or _fail("duplicate package SPDXID: $id");
  _nonempty_string($package->{name})
    or _fail("package name must be a non-empty string: $id");
}

my $count = scalar @{$packages};
my $noun  = $count == 1 ? 'package' : 'packages';
print "validated SPDX 2.3 SBOM: $count $noun\n";
