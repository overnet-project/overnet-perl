use strictures 2;

use File::Basename qw(dirname);
use File::Spec;
use JSON ();
use Test2::V0;
use Test2::Tools::ClassicCompare qw(is is_deeply);

use Overnet::Core::PrivateMessaging;

my $fixtures_dir = File::Spec->catdir(_spec_root(), 'fixtures', 'private-messaging',);

plan skip_all => "private-messaging fixtures not found at $fixtures_dir"
  unless -d $fixtures_dir;

opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
my @fixture_files = sort grep {/\.json\z/mx} readdir $dh;
closedir $dh;

for my $file (@fixture_files) {
  my $path = File::Spec->catfile($fixtures_dir, $file);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;

  my $fixture  = JSON::decode_json($json);
  my $desc     = $fixture->{description};
  my $input    = $fixture->{input};
  my $expected = $fixture->{expected};

  subtest "$file - $desc" => sub {
    my $result = Overnet::Core::PrivateMessaging::validate_transport($input);

    is $result->{valid}, $expected->{private_transport_valid}, "valid = $expected->{private_transport_valid}";

    if (!$expected->{private_transport_valid} && $expected->{reason}) {
      my $found =
        grep {/\Q$expected->{reason}\E/imx} @{$result->{errors}};
      ok $found, "errors contain: $expected->{reason}";
    }

    for my $assertion (@{$expected->{assertions} || []}) {
      my $value = _path_get($result, $assertion->{path});

      if (exists $assertion->{equals}) {
        is_deeply $value, $assertion->{equals}, "$assertion->{path} equals expected value";
      } else {
        fail("Unsupported assertion shape in $file for path $assertion->{path}");
      }
    }
  };
}

sub _load_valid_input {
  my ($name) = @_;
  my $path = File::Spec->catfile($fixtures_dir, $name);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/ = undef; <$fh> };
  close $fh;
  return JSON::decode_json($json)->{input};
}

sub _copy {
  my ($value) = @_;
  return JSON::decode_json(JSON::encode_json($value));
}

sub _first_error_like {
  my ($input, $pattern, $description) = @_;
  my $result = Overnet::Core::PrivateMessaging::validate_transport($input);
  ok !$result->{valid}, "$description is invalid";
  my $found = grep {/$pattern/imx} @{$result->{errors} || []};
  ok $found, "$description reports the expected error"
    or diag join "\n", @{$result->{errors} || []};
  return;
}

subtest 'malformed transports and relay-carried intents' => sub {
  my $valid = _load_valid_input('valid-private-dm-message-nip17.json');

  _first_error_like('junk', qr/input\ must\ be\ a\ hash\ object/, 'a non-object input');
  _first_error_like({transport => 'junk'}, qr/transport\ must\ be\ a\ hash\ object/,
    'a non-object transport');

  my $bad_kind = _copy($valid);
  $bad_kind->{transport}{kind} = 'many';
  _first_error_like($bad_kind, qr/kind\ must\ be\ an\ integer/, 'a non-integer transport kind');

  my $wrong_kind = _copy($valid);
  $wrong_kind->{transport}{kind} = 4;
  _first_error_like($wrong_kind, qr/kind\ 1059\ gift\ wrap/, 'a non-gift-wrap transport kind');

  _first_error_like(
    {
      relay_carried_private_intent => 1,
      event                        => {
        kind => 7_800,
        tags => ['junk', ['overnet_ot', 'chat.dm'], ['overnet_et', 'chat.dm_message']],
      },
    },
    qr/must\ use\ NIP-17/,
    'a public core event carrying a private intent',
  );
  _first_error_like(
    {relay_carried_private_intent => 1, event => {kind => 1, tags => []}},
    qr/must\ use\ NIP-17/,
    'a non-core event carrying a private intent',
  );

  my $bad_rumor = _copy($valid);
  $bad_rumor->{transport}{decrypted_rumor}{pubkey} = 'short';
  _first_error_like($bad_rumor, qr/Invalid\ NIP-17\ rumor/, 'an unparseable rumor');

  my $wrong_rumor_kind = _copy($valid);
  $wrong_rumor_kind->{transport}{decrypted_rumor}{kind} = 15;
  _first_error_like($wrong_rumor_kind, qr/kind\ 14\ rumors/, 'a non-kind-14 rumor');
};

subtest 'rumor payload content validation' => sub {
  my $valid = _load_valid_input('valid-private-dm-message-nip17.json');

  my $string_content = _copy($valid);
  $string_content->{transport}{decrypted_rumor}{content} =
    JSON::encode_json($string_content->{transport}{decrypted_rumor}{content});
  my $string_result = Overnet::Core::PrivateMessaging::validate_transport($string_content);
  ok $string_result->{valid}, 'JSON string rumor content is accepted';

  my $junk_content = _copy($valid);
  $junk_content->{transport}{decrypted_rumor}{content} = 'not json';
  _first_error_like($junk_content, qr/must\ decode\ to\ a\ JSON\ object/, 'undecodable rumor content');

  my $ref_content = _copy($valid);
  $ref_content->{transport}{decrypted_rumor}{content} = ['ref'];
  _first_error_like($ref_content, qr/JSON\ object\ or\ JSON\ object\ string/,
    'reference rumor content');

  my %payload_cases = (
    overnet_v    => [undef,          qr/overnet_v\ must\ be\ a\ non-empty\ string/],
    private_type => ['chat.other',   qr/private_type\ must\ be/],
    object_type  => ['chat.channel', qr/object_type\ must\ be\ chat\.dm/],
    object_id    => [q{},            qr/object_id\ must\ be\ a\ non-empty\ string/],
    body         => ['junk',         qr/body\ must\ be\ an\ object/],
  );
  for my $field (sort keys %payload_cases) {
    my ($value, $pattern) = @{$payload_cases{$field}};
    my $mutated = _copy($valid);
    if (defined $value) {
      $mutated->{transport}{decrypted_rumor}{content}{$field} = $value;
    } else {
      delete $mutated->{transport}{decrypted_rumor}{content}{$field};
    }
    _first_error_like($mutated, $pattern, "a payload with a bad $field");
  }

  my $bad_text = _copy($valid);
  $bad_text->{transport}{decrypted_rumor}{content}{body}{text} = ['ref'];
  _first_error_like($bad_text, qr/body\.text\ must\ be\ a\ string/, 'a payload with non-string text');
};

subtest 'IRC source bindings' => sub {
  my $valid  = _load_valid_input('valid-irc-dm-binding-private-transport.json');
  my $opaque = _load_valid_input('valid-irc-dm-binding-opaque-private-transport.json');

  my $mutate_source = sub {
    my ($base, %changes) = @_;
    my $mutated = _copy($base);
    for my $key (sort keys %changes) {
      if (defined $changes{$key}) {
        $mutated->{source}{$key} = $changes{$key};
      } else {
        delete $mutated->{source}{$key};
      }
    }
    return $mutated;
  };

  _first_error_like($mutate_source->($valid, network => q{}),
    qr/non-empty\ source\.network/, 'an empty network');
  _first_error_like($mutate_source->($valid, line => q{}),
    qr/non-empty\ source\.line/, 'an empty line');
  _first_error_like($mutate_source->($valid, line => ':Alice JOIN #chan'),
    qr/direct-message\ PRIVMSG\ or\ NOTICE/, 'a non-DM line');
  _first_error_like($mutate_source->($valid, line => ':Alice PRIVMSG #chan :hello'),
    qr/must\ target\ a\ nick/, 'a channel-targeted line');
  _first_error_like($mutate_source->($valid, line => ':Alice NOTICE Bob :hello'),
    qr/chat\.dm_notice\ for\ NOTICE/, 'a NOTICE line with a message payload');

  my $notice_payload = _copy($valid);
  $notice_payload->{transport}{decrypted_rumor}{content}{private_type} = 'chat.dm_notice';
  _first_error_like($notice_payload, qr/chat\.dm_message\ for\ PRIVMSG/,
    'a PRIVMSG line with a notice payload');

  my $wrong_object = _copy($valid);
  $wrong_object->{transport}{decrypted_rumor}{content}{object_id} = 'irc:local:dm:Carol';
  _first_error_like($wrong_object, qr/object_id\ must\ be\ irc:local:dm:Bob/,
    'a mismatched binding object id');

  my $wrong_provenance = _copy($valid);
  $wrong_provenance->{transport}{decrypted_rumor}{content}{provenance}{protocol} = 'xmpp';
  _first_error_like($wrong_provenance, qr/provenance\.protocol\ must\ be\ irc/,
    'a non-IRC provenance protocol');

  my $wrong_identity = _copy($valid);
  $wrong_identity->{transport}{decrypted_rumor}{content}{provenance}{external_identity} = 'Mallory';
  _first_error_like($wrong_identity, qr/external_identity\ must\ match/,
    'a mismatched external identity');

  _first_error_like($mutate_source->($opaque, network => q{}),
    qr/non-empty\ source\.network/, 'an empty opaque network');
  _first_error_like($mutate_source->($opaque, line => q{}),
    qr/non-empty\ source\.line/, 'an empty opaque line');
  _first_error_like($mutate_source->($opaque, line => ':Alice JOIN #chan'),
    qr/direct-message\ PRIVMSG\ or\ NOTICE/, 'a non-DM opaque line');
  _first_error_like($mutate_source->($opaque, line => ':Alice PRIVMSG #chan :+overnet-e2ee-v1 x'),
    qr/must\ target\ a\ nick/, 'a channel-targeted opaque line');
  _first_error_like($mutate_source->($opaque, line => ':Alice PRIVMSG Bob :hello'),
    qr/overnet-e2ee-v1\ transport\ body/, 'an opaque line without a transport body');
  _first_error_like($mutate_source->($opaque, line => ':Alice NOTICE Bob :+overnet-e2ee-v1 x'),
    qr/chat\.dm_notice\ for\ NOTICE/, 'an opaque NOTICE line with message metadata');
};

subtest 'opaque metadata and provenance validation' => sub {
  my $opaque = _load_valid_input('valid-irc-dm-binding-opaque-private-transport.json');
  my $nip17  = _load_valid_input('valid-private-dm-message-nip17.json');

  my $mutate = sub {
    my (%changes) = @_;
    my $mutated = _copy($opaque);
    for my $key (sort keys %changes) {
      if (defined $changes{$key}) {
        $mutated->{$key} = $changes{$key};
      } else {
        delete $mutated->{$key};
      }
    }
    return $mutated;
  };

  _first_error_like($mutate->(private_type => 'chat.other'),
    qr/private_type\ must\ be\ chat\.dm_message\ or\ chat\.dm_notice/,
    'an opaque payload with an unknown private type');
  _first_error_like($mutate->(object_type => 'chat.channel'),
    qr/object_type\ must\ be\ chat\.dm/, 'an opaque payload with a foreign object type');
  _first_error_like($mutate->(object_id => 'irc:local:dm:Carol'),
    qr/object_id\ must\ be/, 'an opaque payload with a mismatched object id');
  _first_error_like($mutate->(sender_identity => undef),
    qr/requires\ sender_identity/, 'an opaque payload without a sender identity');
  _first_error_like($mutate->(sender_identity => 'Mallory'),
    qr/sender_identity\ must\ match/, 'an opaque payload with a mismatched sender identity');
  _first_error_like($mutate->(sender_identity => q{}),
    qr/sender_identity\ must\ be\ a\ non-empty\ string/,
    'an opaque payload with an empty sender identity');

  my $extra_tag = _copy($opaque);
  push @{$extra_tag->{transport}{tags}}, ['p', 'c' x 64];
  _first_error_like($extra_tag, qr/exactly\ one\ visible\ transport\ p\ tag/,
    'an opaque transport with two recipient tags');

  my $bad_provenance = _copy($nip17);
  $bad_provenance->{transport}{decrypted_rumor}{content}{provenance} = 'junk';
  _first_error_like($bad_provenance, qr/provenance\ must\ be\ an\ object/,
    'a payload with a non-object provenance');
  my $bad_ptype = _copy($nip17);
  $bad_ptype->{transport}{decrypted_rumor}{content}{provenance}{type} = 'other';
  _first_error_like($bad_ptype, qr/provenance\ type\ must\ be/,
    'a payload with an unknown provenance type');
};

done_testing;



sub _spec_root {
  for my $dir (
    File::Spec->catdir(dirname(__FILE__), '..', '..', 'spec'),
    File::Spec->catdir(dirname(__FILE__), '..', '..', '..', 'spec'),
  ) {
    my $abs = File::Spec->rel2abs($dir);
    return $abs if -d $abs;
  }

  return File::Spec->rel2abs(File::Spec->catdir(dirname(__FILE__), '..', '..', 'spec'),);
}

sub _path_get {
  my ($root, $path) = @_;
  my @parts = split /\./mx, $path;
  my $value = $root;

  for my $part (@parts) {
    return if !defined $value;

    if (ref($value) eq 'HASH') {
      $value = $value->{$part};
      next;
    }

    if (ref($value) eq 'ARRAY' && $part =~ /\A\d+\z/mx) {
      $value = $value->[$part];
      next;
    }

    return;
  }

  return $value;
}
