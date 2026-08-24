package Overnet::Auth::Backend::Pass;

use strictures 2;
use Moo;

extends 'Overnet::Auth::Backend';

use English qw(-no_match_vars);
use Overnet::Core::Nostr;

our $VERSION = '0.001';

has command_runner => (is => 'ro');

no Moo;

sub backend_type { return 'pass'; }

sub load_signing_key {
  my ($self, %args) = @_;
  my $config = $args{backend_config} || {};
  my $entry  = $config->{entry};

  if (!(defined $entry && !ref($entry) && length($entry))) {
    return (
      undef,
      {
        code    => 'auth.backend_unavailable',
        message => 'no pass entry is configured for the selected identity',
      }
    );
  }

  my $runner =
       $config->{command_runner}
    || $self->{command_runner}
    || \&_default_command_runner;
  my ($stdout, $error) = $runner->('pass', 'show', $entry);

  if (defined $error) {
    return (
      undef,
      {
        code    => 'auth.backend_unavailable',
        message => $error,
      }
    );
  }

  my $secret = $stdout // q{};
  if (!($secret =~ /\A-----BEGIN\ [^-]+-----\R/smx)) {
    ($secret) = split /\R/smx, $secret, 2;
  }
  if (!(defined $secret && $secret =~ /\S/smx)) {
    return (
      undef,
      {
        code    => 'auth.backend_unavailable',
        message => "pass entry $entry did not return a usable secret",
      }
    );
  }

  my $key       = eval { Overnet::Core::Nostr->load_key(privkey => $secret) };
  my $exception = $EVAL_ERROR;
  if (!$key) {
    return (
      undef,
      {
        code    => 'auth.backend_unavailable',
        message => "$exception",
      }
    );
  }

  return ($key, undef);
}

sub _default_command_runner {
  my (@cmd) = @_;

  my $pid = open my $fh, q{-|}, @cmd;
  if (!(defined $pid)) {
    return (undef, "unable to execute @cmd: $OS_ERROR");
  }

  my $stdout = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  if (!close $fh) {
    return (undef, "@cmd exited with status " . ($CHILD_ERROR >> 8));
  }

  return ($stdout, undef);
}

1;

=head1 NAME

Overnet::Auth::Backend::Pass - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Backend::Pass;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 backend_type

Public API entry point.

=head2 load_signing_key

Public API entry point.

=head1 DIAGNOSTICS

This module reports errors through normal Perl exceptions or structured return values.

=head1 CONFIGURATION AND ENVIRONMENT

No module-specific environment configuration is required.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

No known bugs are documented.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
