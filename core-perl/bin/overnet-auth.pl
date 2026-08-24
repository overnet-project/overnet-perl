#!/usr/bin/env perl

use strictures 2;
use English qw(-no_match_vars);

use Carp qw(croak);
use Overnet::Auth::CLI;

our $VERSION = '0.001';

my $result = Overnet::Auth::CLI->run(argv => \@ARGV);
print {*STDOUT} $result->{output}
  or croak "Can't write auth command output: $OS_ERROR";
exit $result->{exit_code};
