package Overnet::Auth::Bridge::IRC;

use strictures 2;
use Carp qw(croak);

use JSON         ();
use MIME::Base64 qw(encode_base64 decode_base64);

our $VERSION = '0.001';

sub encode_artifact {
  my ($class, %args) = @_;
  my $artifact = $args{artifact};
  my $command  = $args{command};
  my $encoding = $args{encoding};

  if (!(ref($artifact) eq 'HASH')) {
    croak "artifact must be an object\n";
  }
  if (!(defined $command && !ref($command) && length($command))) {
    croak "command is required\n";
  }
  if (!(defined $encoding && !ref($encoding) && length($encoding))) {
    croak "encoding is required\n";
  }
  if (
    !(
         (($artifact->{type} || q{}) eq 'nostr.event')
      && (($artifact->{format} || q{}) eq 'nostr.event')
      && ref($artifact->{value}) eq 'HASH'
    )
  ) {
    croak "artifact must be a nostr.event\n";
  }
  if (!($encoding eq 'base64-json')) {
    croak "unsupported IRC artifact encoding: $encoding\n";
  }

  return {
    command  => $command,
    encoding => $encoding,
    payload  => encode_base64(JSON::encode_json($artifact->{value}), q{}),
  };
}

sub decode_artifact {
  my ($class, %args) = @_;
  my $encoding = $args{encoding};
  my $payload  = $args{payload};

  if (!(defined $encoding && !ref($encoding) && length($encoding))) {
    croak "encoding is required\n";
  }
  if (!(defined $payload && !ref($payload) && length($payload))) {
    croak "payload is required\n";
  }
  if (!($encoding eq 'base64-json')) {
    croak "unsupported IRC artifact encoding: $encoding\n";
  }

  return {
    type   => 'nostr.event',
    format => 'nostr.event',
    value  => JSON::decode_json(decode_base64($payload)),
  };
}

1;

=head1 NAME

Overnet::Auth::Bridge::IRC - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Bridge::IRC;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 encode_artifact

Public API entry point.

=head2 decode_artifact

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
