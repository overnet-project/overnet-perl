#!/usr/bin/perl

use strict;
use warnings;

use File::Spec;
use FindBin;

my %scripts = (
  relay     => 'overnet-relay.pl',
  authority => 'overnet-authority-relay.pl',
);

my $role = @ARGV && $ARGV[0] !~ /\A-/mxs ? shift @ARGV : 'relay';
die "unknown relay role: $role\n" if !exists $scripts{$role};

my $script = File::Spec->catfile($FindBin::Bin, $scripts{$role});
exec $^X, $script, @ARGV
  or die "exec failed: $!\n";
