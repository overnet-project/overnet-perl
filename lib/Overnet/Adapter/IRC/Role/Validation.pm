package Overnet::Adapter::IRC::Role::Validation;

use strictures 2;
use Moo::Role;

sub _non_empty_scalar {
  my ($value) = @_;

  if (!defined $value) {
    return 0;
  }
  if (ref($value)) {
    return 0;
  }
  if (!length $value) {
    return 0;
  }

  return 1;
}

sub _valid_non_empty_scalar_array {
  my ($values) = @_;

  if (ref($values) ne 'ARRAY') {
    return 0;
  }

  for my $value (@{$values}) {
    if (!_non_empty_scalar($value)) {
      return 0;
    }
  }

  return 1;
}

sub _valid_hex_pubkey {
  my ($value) = @_;

  if (defined($value) && !ref($value) && $value =~ /\A[0-9a-f]{64}\z/msx) {
    return 1;
  }

  return 0;
}

sub _positive_integer_string {
  my ($value) = @_;

  if (defined($value) && !ref($value) && $value =~ /\A[1-9][0-9]*\z/msx) {
    return 1;
  }

  return 0;
}

sub _non_negative_integer {
  my ($value) = @_;

  if (defined($value) && !ref($value) && $value =~ /\A[0-9]+\z/msx) {
    return 1;
  }

  return 0;
}

sub _is_channel_target {
  my ($target) = @_;

  if (defined $target && $target =~ /\A[#&]/msx) {
    return 1;
  }

  return 0;
}

sub _channel_has_mode {
  my ($channel_modes, $mode_letter) = @_;
  my $mode_pattern = qr/\+[^ ]*\Q$mode_letter\E/msx;

  if (($channel_modes || q{}) =~ $mode_pattern) {
    return 1;
  }

  return 0;
}

sub _session_config_from_args {
  my ($session_config) = @_;
  if (ref($session_config) eq 'HASH') {
    return $session_config;
  }
  return {};
}

sub _error {
  my ($reason) = @_;
  return {
    valid  => 0,
    reason => $reason,
  };
}

no Moo::Role;

1;

=head1 NAME

Overnet::Adapter::IRC::Role::Validation - Shared internal IRC adapter validation

=head1 DESCRIPTION

This internal role keeps scalar, identity, target, and structured-error
validation consistent across the IRC adapter collaborators.

=head1 SYNOPSIS

  package Overnet::Adapter::IRC::InternalComponent;
  use Moo;
  with 'Overnet::Adapter::IRC::Role::Validation';

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

This private role exposes only internal validation helpers to its consumers.

=head1 DIAGNOSTICS

The role returns structured invalid adapter results through its internal
helpers.

=head1 CONFIGURATION AND ENVIRONMENT

This internal role requires no configuration.

=head1 DEPENDENCIES

This role depends on Moo.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

This role is private to the IRC adapter distribution.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
