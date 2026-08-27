#!/usr/bin/env perl

use strict;
use warnings;

use Bytes::Random::Secure qw(random_bytes);

random_bytes(32);
pipe(my $reader, my $writer) or die "pipe failed: $!\n";
my $pid = fork;
die "fork failed: $!\n" if !defined $pid;

if (!$pid) {
  close $reader;
  print {$writer} unpack('H*', random_bytes(32));
  close $writer;
  exit 0;
}

close $writer;
my $child = do { local $/; <$reader> };
close $reader;
waitpid $pid, 0;
die "fork-safety child failed\n" if $? != 0;
my $parent = unpack('H*', random_bytes(32));
die "forked PRNG streams are identical\n" if $parent eq $child;

print "verified Bytes::Random::Secure fork safety\n";
