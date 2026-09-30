use strict;
use warnings;

use ExtUtils::MakeMaker;

our $VERSION = '0.001';

my $space = chr 32;

WriteMakefile(
  NAME               => 'Overnet::Adapter::IRC',
  DISTNAME           => 'Overnet-Adapter-IRC',
  AUTHOR             => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT           => 'Perl reference implementation of the Overnet IRC adapter',
  VERSION_FROM       => 'lib/Overnet/Adapter/IRC.pm',
  LICENSE            => 'gpl_3',
  MIN_PERL_VERSION   => '5.040',
  CONFIGURE_REQUIRES => {
    'ExtUtils::MakeMaker' => 0,
  },
  PREREQ_PM => {
    'JSON'       => 0,
    'Moo'        => 0,
    'Net::Nostr' => 0,
    'Overnet'    => 0.001,
    'strictures' => 2,
  },
  test => {
    TESTS => join(
      $space,
      qw(
        t/00-load.t
        t/component-boundaries.t
        t/input-validation.t
        t/30-nip29-authoritative.t
        t/50-znc-overnetauth.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/shared-perl-layout.t
      )
    ),
  },
  META_MERGE => {
    resources => {
      repository => 'https://github.com/overnet-project/overnet-perl',
      bugtracker => 'https://github.com/overnet-project/overnet-perl/issues',
    },
  },
);
