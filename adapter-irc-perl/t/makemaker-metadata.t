use strictures 2;

use Cwd qw(getcwd);
use File::Spec;
use FindBin;
use Test2::V0;

my $makefile_pl = File::Spec->catfile($FindBin::Bin, '..', 'Makefile.PL');

ok -f $makefile_pl, 'Makefile.PL exists'
  or bail_out('Makefile.PL is required');

my $args = _capture_makefile_args($makefile_pl);

is $args->{NAME},             'Overnet::Adapter::IRC',                                    'distribution name';
is $args->{DISTNAME},         'Overnet-Adapter-IRC',                                      'CPAN dist name';
is $args->{AUTHOR},           'Nicholas B. Hubbard <nicholashubbard@posteo.net>',         'author';
is $args->{ABSTRACT},         'Perl reference implementation of the Overnet IRC adapter', 'abstract';
is $args->{VERSION_FROM},     'lib/Overnet/Adapter/IRC.pm', 'version comes from adapter module';
is $args->{LICENSE},          'gpl_3',                      'license';
is $args->{MIN_PERL_VERSION}, '5.040',                      'minimum Perl version';
is(
  $args->{CONFIGURE_REQUIRES},
  {
    'ExtUtils::MakeMaker' => 0,
  },
  'configure prerequisites include modules required to load Makefile.PL',
);

is(
  $args->{PREREQ_PM},
  {
    'JSON'       => 0,
    'Moo'        => 0,
    'Net::Nostr' => 0,
    'Overnet'    => 0.001,
    'strictures' => 2,
  },
  'runtime prerequisites stay on top-level non-core distributions',
);

is($args->{TEST_REQUIRES} || {}, {}, 'no extra non-core test-only prerequisites',);

is(
  $args->{META_MERGE},
  {
    resources => {
      repository => 'https://github.com/overnet-project/adapter-irc-perl',
      bugtracker => 'https://github.com/overnet-project/adapter-irc-perl/issues',
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
        t/00-load.t
        t/component-boundaries.t
        t/input-validation.t
        t/30-nip29-authoritative.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/shared-perl-layout.t
      )
    ),
  },
  'default test suite excludes fixture and sibling-spec integration coverage',
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
