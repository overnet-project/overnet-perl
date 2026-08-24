use strictures 2;
use Test2::V0;
use JSON ();
use FindBin;
use File::Spec;

use Overnet::Adapter::IRC;

my $adapter      = Overnet::Adapter::IRC->new;
my $fixtures_dir = File::Spec->catdir(_spec_root(), 'fixtures', 'irc-derived');

opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
my @fixture_files = sort grep {/\.json$/mx} readdir $dh;
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
    my $result = $adapter->derive_channel_presence(%{$input});

    my $expected_valid = $expected->{overnet_valid} ? 1 : 0;
    my $got_valid      = $result->{valid}           ? 1 : 0;
    is $got_valid, $expected_valid, "valid = $expected_valid";

    if ($expected->{overnet_valid}) {
      my $got_event      = {%{$result->{event}}};
      my $expected_event = {%{$expected->{event}}};

      my $got_content      = delete $got_event->{content};
      my $expected_content = delete $expected_event->{content};

      is $got_event, $expected_event, 'derived event envelope matches fixture';
      is JSON::decode_json($got_content), JSON::decode_json($expected_content),
        'derived event content matches fixture semantically';
    } else {
      is $result->{reason}, $expected->{reason}, 'reason matches fixture';
    }
  };
}

subtest 'generic derive dispatches channel_presence' => sub {
  my $result = $adapter->derive(
    operation => 'channel_presence',
    input     => {
      network    => 'irc.libera.chat',
      target     => '#overnet',
      created_at => 1744300900,
      events     => [
        {
          command    => 'JOIN',
          network    => 'irc.libera.chat',
          target     => '#overnet',
          nick       => 'alice',
          created_at => 1744300870,
        },
      ],
    },
  );

  ok $result->{valid}, 'generic derive returns a valid result';
  is $result->{event}{kind}, 37800, 'generic derive returns derived state event';
};

subtest 'generic derive rejects unsupported operations' => sub {
  my $result = $adapter->derive(
    operation => 'unknown_operation',
    input     => {},
  );

  ok !$result->{valid}, 'unsupported derive operation is rejected';
  is $result->{reason}, 'Unsupported derive operation: unknown_operation', 'unsupported operation reason is reported';
};

subtest 'adapter declares secure secret slots for runtime session opens' => sub {
  is(
    $adapter->supported_secret_slots,
    ['server_password', 'nickserv_password', 'sasl_password'],
    'IRC adapter declares the supported runtime secret slots',
  );
};

subtest 'open_session accepts declared secret slots without exposing plaintext back out' => sub {
  my $result = $adapter->open_session(
    adapter_session_id => 'adapter-1',
    session_config     => {
      network => 'irc.libera.chat',
      nick    => 'overnet-bot',
    },
    secret_values => {
      sasl_password => 'super-secret',
    },
  );

  ok $result->{accepted}, 'open_session accepts valid declared secret slots';

  like(
    do {
      my $error;
      eval {
        $adapter->open_session(
          adapter_session_id => 'adapter-2',
          session_config     => {},
          secret_values      => {
            unsupported_slot => 'secret',
          },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/Unsupported\ IRC\ secret\ slot:\ unsupported_slot/mx,
    'open_session rejects unsupported secret slots',
  );
};

subtest 'derived presence only folds events for the requested channel' => sub {
  my $result = $adapter->derive_channel_presence(
    network    => 'irc.libera.chat',
    target     => '#overnet',
    created_at => 1_744_300_950,
    partial    => 0,
    events     => [
      {
        command    => 'JOIN',
        network    => 'irc.libera.chat',
        target     => '#overnet',
        nick       => 'alice',
        created_at => 1_744_300_900,
      },
      {
        command    => 'JOIN',
        network    => 'irc.libera.chat',
        target     => '#elsewhere',
        nick       => 'zoe',
        created_at => 1_744_300_901,
      },
      {
        command    => 'PART',
        network    => 'irc.libera.chat',
        target     => '#elsewhere',
        nick       => 'alice',
        created_at => 1_744_300_902,
      },
      {
        command     => 'KICK',
        network     => 'irc.libera.chat',
        target      => '#elsewhere',
        nick        => 'zoe',
        target_nick => 'alice',
        created_at  => 1_744_300_903,
      },
      {
        command    => 'JOIN',
        network    => 'irc.libera.chat',
        target     => '#overnet',
        nick       => 'bob',
        created_at => 1_744_300_900,
      },
      {
        command     => 'KICK',
        network     => 'irc.libera.chat',
        target      => '#overnet',
        nick        => 'alice',
        target_nick => 'bob',
        created_at  => 1_744_300_910,
      },
      {
        command    => 'NICK',
        network    => 'irc.libera.chat',
        nick       => 'carol',
        new_nick   => 'karol',
        created_at => 1_744_300_911,
      },
      {
        command    => 'NICK',
        network    => 'irc.libera.chat',
        nick       => 'alice',
        new_nick   => 'alice2',
        created_at => 1_744_300_912,
      },
    ],
  );

  ok $result->{valid}, 'multi-channel presence derivation succeeds';
  my $body = JSON::decode_json($result->{event}{content})->{body};
  is(
    $body->{members},
    [
      {
        nick            => 'alice2',
        last_event_type => 'irc.nick',
      },
    ],
    'other-channel events, kicked members, and unknown nick renames are excluded',
  );
  is $body->{as_of},   1_744_300_912, 'as_of tracks the newest folded event';
  is $body->{partial}, JSON::false,   'an explicit non-partial snapshot is disclosed as complete';

  my $limitations = JSON::decode_json($result->{event}{content})->{provenance}{limitations};
  ok !(grep { $_ eq 'irc.partial_membership' } @{$limitations}),
    'complete snapshots do not carry the partial-membership limitation';
};

subtest 'derived presence discloses explicitly partial snapshots' => sub {
  my $result = $adapter->derive_channel_presence(
    network    => 'irc.libera.chat',
    target     => '#overnet',
    created_at => 1_744_300_960,
    partial    => 1,
    events     => [
      {
        command    => 'JOIN',
        network    => 'irc.libera.chat',
        target     => '#overnet',
        nick       => 'alice',
        created_at => 1_744_300_955,
      },
    ],
  );

  ok $result->{valid}, 'explicitly partial presence derivation succeeds';
  my $content = JSON::decode_json($result->{event}{content});
  is $content->{body}{partial}, JSON::true, 'an explicitly partial snapshot stays partial';
  ok((grep { $_ eq 'irc.partial_membership' } @{$content->{provenance}{limitations}}),
    'partial snapshots carry the partial-membership limitation');
};

subtest 'close_session discards recorded session state' => sub {
  my $opened = $adapter->open_session(
    adapter_session_id => 'adapter-close-1',
    session_config     => {network => 'irc.libera.chat',},
    secret_values      => {sasl_password => 'super-secret',},
  );
  ok $opened->{accepted}, 'the session opens before closing';

  is $adapter->close_session(adapter_session_id => 'adapter-close-1'), 1, 'close_session succeeds';
  is $adapter->close_session(adapter_session_id => 'adapter-close-1'), 1,
    'closing an already-closed session stays idempotent';
};

subtest 'map_message aliases map_input for message events' => sub {
  my %message_args = (
    command    => 'PRIVMSG',
    network    => 'irc.libera.chat',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'hello overnet',
    created_at => 1_744_300_970,
  );

  my $aliased = $adapter->map_message(%message_args);
  my $direct  = $adapter->map_input(%message_args);

  ok $aliased->{valid}, 'map_message maps a channel PRIVMSG';
  my %aliased_envelope = %{$aliased->{event}};
  my %direct_envelope  = %{$direct->{event}};
  my $aliased_content  = delete $aliased_envelope{content};
  my $direct_content   = delete $direct_envelope{content};
  is \%aliased_envelope, \%direct_envelope, 'map_message produces the map_input event envelope';
  is JSON::decode_json($aliased_content), JSON::decode_json($direct_content),
    'map_message produces the map_input event content';
};

done_testing;

sub _spec_root {
  for my $dir (
    File::Spec->catdir($FindBin::Bin, '..', '..', '..', 'spec'),
    File::Spec->catdir($FindBin::Bin, '..', '..', 'spec'),
  ) {
    my $abs = File::Spec->rel2abs($dir);
    return $abs if -d $abs;
  }

  die "Can't locate spec root\n";
}
