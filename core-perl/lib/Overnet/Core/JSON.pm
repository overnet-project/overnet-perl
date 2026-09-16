package Overnet::Core::JSON;

use strictures 2;
use Carp             qw(croak);
use MIME::Base64     qw(encode_base64 decode_base64);
use Cpanel::JSON::XS ();
use Encode           qw(encode FB_CROAK LEAVE_SRC);

our $VERSION = '0.001';

my $PARSER = Cpanel::JSON::XS->new->utf8->allow_dupkeys(0);
$PARSER->max_depth(64);

sub decode_json {
  my ($text) = @_;
  if (!defined $text || ref $text) {
    croak 'JSON input must be text';
  }
  my $bytes = utf8::is_utf8($text) ? encode('utf8', $text, FB_CROAK | LEAVE_SRC) : $text;
  return $PARSER->decode($bytes);
}

sub decode_base64_json {
  my ($encoded) = @_;
  croak 'Invalid base64 JSON encoding' if !defined($encoded) || ref($encoded);
  my $decoded = decode_base64($encoded);
  croak 'Invalid base64 JSON encoding' if encode_base64($decoded, q{}) ne $encoded;
  return decode_json($decoded);
}

1;

=head1 NAME

Overnet::Core::JSON - Unambiguous UTF-8 JSON decoding for Overnet boundaries

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $value = Overnet::Core::JSON::decode_json($wire);

=head1 DESCRIPTION

Decodes UTF-8 octets or Perl character strings without modifying the input.
Rejects duplicate object members (including escaped aliases), malformed UTF-8,
invalid Unicode scalar values and nesting beyond 64 levels. Signed content
remains unchanged; only a separate decoded value is returned.

=head1 SUBROUTINES/METHODS

=head2 decode_json

Returns the decoded value or throws an exception for invalid input.

=head2 decode_base64_json

Decodes canonical standard base64, then validates the decoded JSON.

=head1 DIAGNOSTICS

Malformed input is reported through exceptions from the JSON or UTF-8 decoder.

=head1 CONFIGURATION AND ENVIRONMENT

No configuration is required.

=head1 DEPENDENCIES

Cpanel::JSON::XS and Encode.

=head1 INCOMPATIBILITIES

JSON with duplicate member names is rejected rather than silently overwritten.

=head1 BUGS AND LIMITATIONS

Callers must apply their protocol's frame-size limits before decoding.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the repository LICENSE file.

=cut
