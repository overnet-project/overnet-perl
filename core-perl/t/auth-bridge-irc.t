use strictures 2;

use JSON ();
use Test2::V0;

use Overnet::Auth::Bridge::IRC;

my $EVENT = {
  kind       => 22_242,
  created_at => 1,
  content    => q{},
  tags       => [['relay', 'irc://irc.example.test/overnet'], ['challenge', 'abcd']],
};

subtest 'artifacts round-trip through the base64-json IRC encoding' => sub {
  my $wire = Overnet::Auth::Bridge::IRC->encode_artifact(
    artifact => {type => 'nostr.event', format => 'nostr.event', value => $EVENT},
    command  => 'AUTHENTICATE',
    encoding => 'base64-json',
  );
  is($wire->{command},  'AUTHENTICATE', 'the IRC command is preserved');
  is($wire->{encoding}, 'base64-json',  'the encoding is preserved');
  unlike($wire->{payload}, qr/\s/, 'the payload is a single base64 token');

  my $decoded = Overnet::Auth::Bridge::IRC->decode_artifact(
    encoding => $wire->{encoding},
    payload  => $wire->{payload},
  );
  is(
    $decoded,
    {type => 'nostr.event', format => 'nostr.event', value => $EVENT},
    'decoding restores the artifact',
  );
};

subtest 'encode_artifact rejects malformed requests' => sub {
  my %valid = (
    artifact => {type => 'nostr.event', format => 'nostr.event', value => $EVENT},
    command  => 'AUTHENTICATE',
    encoding => 'base64-json',
  );
  my $encode_error = sub {
    my (%override) = @_;
    return dies { Overnet::Auth::Bridge::IRC->encode_artifact(%valid, %override) };
  };

  like($encode_error->(artifact => 'junk'), qr/artifact must be an object/, 'artifacts must be hashes');
  like($encode_error->(command  => q{}),  qr/command is required/,  'a command is required');
  like($encode_error->(encoding => q{}),  qr/encoding is required/, 'an encoding is required');
  like(
    $encode_error->(artifact => {type => 'opaque', format => 'opaque', value => {}}),
    qr/artifact must be a nostr[.]event/,
    'non-nostr artifacts are refused',
  );
  like(
    $encode_error->(artifact => {type => 'nostr.event', format => 'nostr.event', value => 'junk'}),
    qr/artifact must be a nostr[.]event/,
    'artifact values must be objects',
  );
  like(
    $encode_error->(encoding => 'hex'),
    qr/unsupported IRC artifact encoding: hex/,
    'unknown encodings are refused',
  );
};

subtest 'decode_artifact rejects malformed requests' => sub {
  my $decode_error = sub {
    my (%args) = @_;
    return dies { Overnet::Auth::Bridge::IRC->decode_artifact(%args) };
  };

  like($decode_error->(payload => 'eyJ9'), qr/encoding is required/, 'an encoding is required');
  like(
    $decode_error->(encoding => 'base64-json', payload => q{}),
    qr/payload is required/,
    'a payload is required',
  );
  like(
    $decode_error->(encoding => 'hex', payload => 'abcd'),
    qr/unsupported IRC artifact encoding: hex/,
    'unknown encodings are refused',
  );
};

done_testing;
