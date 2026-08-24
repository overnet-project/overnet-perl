use strict;
use warnings;

use ExtUtils::MakeMaker;

our $VERSION = '0.001';

my $space = chr 32;

WriteMakefile(
  NAME               => 'Overnet',
  DISTNAME           => 'Overnet-Core',
  AUTHOR             => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT           => 'Perl reference implementation of the Overnet core and program runtime',
  VERSION_FROM       => 'lib/Overnet.pm',
  LICENSE            => 'gpl_3',
  MIN_PERL_VERSION   => '5.040',
  EXE_FILES          => ['bin/overnet-auth.pl', 'bin/overnet-auth-agent.pl',],
  CONFIGURE_REQUIRES => {
    'ExtUtils::MakeMaker' => 0,
  },
  PREREQ_PM => {
    'AnyEvent'             => 0,
    'CryptX'               => 0,
    'IO::Socket::SSL'      => 0,
    'JSON'                 => 0,
    'JSON::Schema::Modern' => 0,
    'Moo'                  => 0,
    'Net::Nostr'           => 0,
    'strictures'           => 2,
  },
  test => {
    TESTS => join(
      $space,
      qw(
        t/00-load-program-runtime.t
        t/auth-agent.t
        t/auth-backends.t
        t/auth-bridge-irc.t
        t/auth-client.t
        t/auth-cli.t
        t/auth-config.t
        t/auth-daemon-cli.t
        t/auth-daemon.t
        t/auth-readme.t
        t/auth-socket-io.t
        t/auth-state-store.t
        t/auth-write-all.t
        t/auth-fixtures.t
        t/authority-delegation.t
        t/authority-hosted-channel.t
        t/core-nostr.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/profile-contract-oracle.t
        t/profile-contract.t
        t/program-adapter-registry.t
        t/program-host.t
        t/program-instance.t
        t/program-protocol.t
        t/program-runtime-config.t
        t/program-runtime-construction.t
        t/program-runtime-edges.t
        t/program-runtime-emission.t
        t/program-runtime-private-messaging.t
        t/program-runtime-secrets.t
        t/program-runtime-store.t
        t/program-runtime-subscriptions.t
        t/program-runtime-timers.t
        t/program-runtime-tls.t
        t/program-services-dispatch.t
        t/repo-split.t
        t/validator.t
      )
    ),
  },
  META_MERGE => {
    resources => {
      repository => 'https://github.com/overnet-project/core-perl',
      bugtracker => 'https://github.com/overnet-project/core-perl/issues',
    },
  },
);
