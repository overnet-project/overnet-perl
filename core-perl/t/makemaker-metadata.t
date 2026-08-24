use strictures 2;

use Cwd qw(getcwd);
use File::Spec;
use FindBin;
use Test2::V0;

my $makefile_pl = File::Spec->catfile($FindBin::Bin, '..', 'Makefile.PL');

ok -f $makefile_pl, 'Makefile.PL exists'
  or bail_out('Makefile.PL is required');

my $args = _capture_makefile_args($makefile_pl);

is $args->{NAME},     'Overnet',                                                               'distribution name';
is $args->{DISTNAME}, 'Overnet-Core',                                                          'CPAN dist name';
is $args->{AUTHOR},   'Nicholas B. Hubbard <nicholashubbard@posteo.net>',                      'author';
is $args->{ABSTRACT}, 'Perl reference implementation of the Overnet core and program runtime', 'abstract';
is $args->{VERSION_FROM},     'lib/Overnet.pm', 'version comes from root module';
is $args->{LICENSE},          'gpl_3',          'license';
is $args->{MIN_PERL_VERSION}, '5.040',          'minimum Perl version';
is(
  $args->{CONFIGURE_REQUIRES},
  {
    'ExtUtils::MakeMaker' => 0,
  },
  'configure prerequisites include modules required to load Makefile.PL',
);
is($args->{EXE_FILES}, ['bin/overnet-auth.pl', 'bin/overnet-auth-agent.pl',], 'auth scripts are installed',);

is(
  $args->{PREREQ_PM},
  {
    'AnyEvent'             => 0,
    'CryptX'               => 0,
    'IO::Socket::SSL'      => 0,
    'JSON'                 => 0,
    'JSON::Schema::Modern' => 0,
    'Moo'                  => 0,
    'Net::Nostr'           => 0,
    'strictures'           => 2,
  },
  'runtime prerequisites are limited to top-level non-core distributions',
);

is($args->{TEST_REQUIRES} || {}, {}, 'no extra non-core test-only prerequisites',);

is(
  $args->{META_MERGE},
  {
    resources => {
      repository => 'https://github.com/overnet-project/core-perl',
      bugtracker => 'https://github.com/overnet-project/core-perl/issues',
    },
  },
  'metadata resources point at the public repo',
);

is(
  $args->{test},
  {
    TESTS => join(
      ' ',
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
  'default test suite stays CPAN-safe',
);

done_testing;

sub _capture_makefile_args {
  my ($makefile_pl) = @_;
  my $args;
  my $cwd = getcwd();
  my ($volume, $dirs) = File::Spec->splitpath($makefile_pl);
  my $repo_root = File::Spec->catpath($volume, $dirs, '');
  $repo_root =~ s{/$}{}mx;

  {
    require ExtUtils::MakeMaker;

    no warnings qw(redefine once);
    local *ExtUtils::MakeMaker::WriteMakefile = sub {
      $args = {@_};
      return 1;
    };
    local *main::WriteMakefile = \&ExtUtils::MakeMaker::WriteMakefile;

    chdir $repo_root or die "unable to chdir to $repo_root: $!";
    my $rv    = do $makefile_pl;
    my $error = $@;
    chdir $cwd or die "unable to restore cwd to $cwd: $!";

    die $error if $error;
    die "unable to load $makefile_pl: $!" unless defined $rv;
  }

  return $args;
}
