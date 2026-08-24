package Overnet::Program::TLSConfig;

use strictures 2;
use Carp            qw(croak);
use JSON            ();
use IO::Socket::SSL qw(SSL_VERIFY_NONE SSL_VERIFY_PEER);

our $VERSION = '0.001';

sub normalize {
  my ($class, %args) = @_;

  if (!(exists $args{tls})) {
    return;
  }
  my $tls           = $args{tls};
  my $implicit_mode = $args{implicit_mode};

  if (!(ref($tls) eq 'HASH')) {
    croak "tls must be an object\n";
  }
  if ( defined $implicit_mode
    && $implicit_mode ne 'client'
    && $implicit_mode ne 'server') {
    croak "implicit_mode must be client or server\n";
  }

  if (!(exists $tls->{enabled})) {
    croak "tls.enabled is required\n";
  }

  my $enabled = _normalize_bool('tls.enabled', $tls->{enabled});
  my $mode    = _normalize_mode($tls, $implicit_mode);

  my %normalized = (enabled => $enabled,);
  _copy_mode(\%normalized, $mode);
  _copy_string_fields(\%normalized, $tls);
  _copy_verify_peer(\%normalized, $tls);
  _copy_min_version(\%normalized, $tls);
  _require_server_files(\%normalized);
  _require_peer_ca(\%normalized);

  return \%normalized;
}

sub _normalize_mode {
  my ($tls, $implicit_mode) = @_;
  my $mode = exists $tls->{mode} ? $tls->{mode} : $implicit_mode;
  if (defined $mode && !(!ref($mode) && ($mode eq 'client' || $mode eq 'server'))) {
    croak "tls.mode must be client or server\n";
  }
  return $mode;
}

sub _copy_mode {
  my ($normalized, $mode) = @_;
  if (defined $mode) {
    $normalized->{mode} = $mode;
  }
  return;
}

sub _copy_string_fields {
  my ($normalized, $tls) = @_;
  for my $field (qw(server_name cert_chain_file private_key_file ca_file)) {
    if (!(exists $tls->{$field})) {
      next;
    }
    if (!(defined $tls->{$field} && !ref($tls->{$field}) && length($tls->{$field}))) {
      croak "tls.$field must be a non-empty string\n";
    }
    $normalized->{$field} = $tls->{$field};
  }
  return;
}

sub _copy_verify_peer {
  my ($normalized, $tls) = @_;
  if (exists $tls->{verify_peer}) {
    $normalized->{verify_peer} =
      _normalize_bool('tls.verify_peer', $tls->{verify_peer});
  }
  return;
}

sub _copy_min_version {
  my ($normalized, $tls) = @_;
  if (!(exists $tls->{min_version})) {
    return;
  }
  if (!(_valid_min_version($tls->{min_version}))) {
    croak "tls.min_version must be TLSv1.2 or TLSv1.3\n";
  }
  $normalized->{min_version} = $tls->{min_version};
  return;
}

sub _valid_min_version {
  my ($min_version) = @_;
  return
       defined $min_version
    && !ref($min_version)
    && ($min_version eq 'TLSv1.2' || $min_version eq 'TLSv1.3') ? 1 : 0;
}

sub _require_server_files {
  my ($normalized) = @_;
  if (!($normalized->{enabled} && defined $normalized->{mode} && $normalized->{mode} eq 'server')) {
    return;
  }
  if (!(defined $normalized->{cert_chain_file})) {
    croak "tls.cert_chain_file is required when tls.enabled is true for server mode\n";
  }
  if (!(defined $normalized->{private_key_file})) {
    croak "tls.private_key_file is required when tls.enabled is true for server mode\n";
  }
  return;
}

sub _require_peer_ca {
  my ($normalized) = @_;
  if (!($normalized->{enabled} && ($normalized->{verify_peer} || 0))) {
    return;
  }
  if (!(defined $normalized->{ca_file})) {
    croak "tls.ca_file is required when tls.verify_peer is true\n";
  }
  return;
}

sub server_start_args {
  my ($class, $tls) = @_;

  if (!(defined $tls)) {
    return;
  }
  if (!(ref($tls) eq 'HASH')) {
    croak "tls must be an object\n";
  }
  if (!($tls->{enabled})) {
    return;
  }
  if (!(($tls->{mode} || q{}) eq 'server')) {
    croak "tls.mode must be server when building server TLS arguments\n";
  }

  my %args = (
    SSL_server         => 1,
    SSL_startHandshake => 1,
    SSL_cert_file      => $tls->{cert_chain_file},
    SSL_key_file       => $tls->{private_key_file},
    SSL_verify_mode    => ($tls->{verify_peer} ? SSL_VERIFY_PEER() : SSL_VERIFY_NONE()),
  );
  if (defined $tls->{ca_file}) {
    $args{SSL_ca_file} = $tls->{ca_file};
  }
  if (defined $tls->{min_version}) {
    $args{SSL_version} =
      _ssl_version_for_min_version($tls->{min_version});
  }

  return \%args;
}

sub _normalize_bool {
  my ($label, $value) = @_;

  if (JSON::is_bool($value)) {
    return $value ? 1 : 0;
  }
  if (defined $value && !ref($value) && ($value eq '0' || $value eq '1')) {
    return 0 + $value;
  }

  croak "$label must be a boolean\n";
}

sub _ssl_version_for_min_version {
  my ($min_version) = @_;

  if ($min_version eq 'TLSv1.2') {
    return 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1';
  }
  if ($min_version eq 'TLSv1.3') {
    return 'TLSv1_3';
  }

  croak "Unsupported tls.min_version: $min_version\n";
}

1;

=head1 NAME

Overnet::Program::TLSConfig - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::TLSConfig;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 normalize

Public API entry point.

=head2 server_start_args

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
