package Overnet::Auth::Backend::DirectSecret;

use strictures 2;
use Moo;
use English qw(-no_match_vars);

extends 'Overnet::Auth::Backend';

use Overnet::Core::Nostr;

our $VERSION = '0.001';

no Moo;

sub backend_type { return 'direct_secret'; }

sub load_signing_key {
  my ($self, %args) = @_;
  my $identity = $args{identity}       || {};
  my $config   = $args{backend_config} || {};

  my $secret = $config->{secret};
  if (!(defined $secret && !ref($secret) && length($secret))) {
    $secret = $identity->{private_key};
  }
  if (!(defined $secret && !ref($secret) && length($secret))) {
    $secret = $identity->{privkey_secret};
  }

  if (!(defined $secret && !ref($secret) && length($secret))) {
    return (
      undef,
      {
        code    => 'auth.backend_unavailable',
        message => 'no direct secret is configured for the selected identity',
      }
    );
  }

  my $key = eval { Overnet::Core::Nostr->load_key(privkey => $secret) };
  if (!($key)) {
    return (
      undef,
      {
        code    => 'auth.backend_unavailable',
        message => "$EVAL_ERROR",
      }
    );
  }

  return ($key, undef);
}

1;

=head1 NAME

Overnet::Auth::Backend::DirectSecret - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Backend::DirectSecret;

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
