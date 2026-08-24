use strictures 2;
use Test::More;
use JSON ();
use File::Basename;
use File::Spec;

use Overnet::Core::Validator;

my $fixtures_dir = File::Spec->catdir(dirname(__FILE__), 'fixtures');
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
  my $context  = $fixture->{context};

  subtest "$file - $desc" => sub {
    my $result = Overnet::Core::Validator::validate($input, $context);

    is $result->{valid}, $expected->{overnet_valid}, "valid = $expected->{overnet_valid}";

    if (!$expected->{overnet_valid} && $expected->{reason}) {
      my $found =
        grep {/\Q$expected->{reason}\E/imx} @{$result->{errors}};
      ok $found, "errors contain: $expected->{reason}";
    }
  };
}

require Overnet::Core::Nostr;

my $AUTHORITY = Overnet::Core::Nostr->generate_key;
my $DELEGATE  = Overnet::Core::Nostr->generate_key;
my $STRANGER  = Overnet::Core::Nostr->generate_key;
my $OID       = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

sub _signed_event {
  my ($key, %args) = @_;
  return $key->sign_event_hash(
    event => {
      kind       => $args{kind} // 7800,
      created_at => $args{created_at} // 1_744_300_950,
      content    => $args{content} // JSON::encode_json(
        {provenance => {type => 'native'}, body => $args{body} // {}},
      ),
      tags => $args{tags},
    },
  );
}

sub _core_tags {
  my (%args) = @_;
  my $et  = $args{et};
  my $ot  = $args{ot}  // 'chat.channel';
  my $oid = $args{oid} // $OID;
  return [
    ['overnet_v', '0.1.0'], ['overnet_et', $et], ['overnet_ot', $ot], ['overnet_oid', $oid],
    ['v', '0.1.0'], ['t', $et], ['o', $ot], ['d', $oid],
    @{$args{extra} || []},
  ];
}

sub _delegation_event {
  my (%args) = @_;
  my $key = $args{key} // $AUTHORITY;
  return _signed_event(
    $key,
    tags    => _core_tags(et => 'core.delegation', %args),
    content => JSON::encode_json(
      {
        provenance => {type => 'native'},
        body       => $args{body} // {
          action          => 'remove',
          delegate_pubkey => $DELEGATE->pubkey_hex,
          expires_at      => 1_744_304_600,
        },
      },
    ),
    %args,
  );
}

sub _removal_for {
  my (%args) = @_;
  my $target     = $args{target};
  my $delegation = $args{delegation};
  my $key        = $args{key} // $DELEGATE;
  return _signed_event(
    $key,
    kind       => 7801,
    created_at => 1_744_301_000,
    tags       => _core_tags(
      et    => 'core.removal',
      extra => [
        ['e', $target->{id}],
        (
          defined $args{delegate_tag} ? (['overnet_delegate', $args{delegate_tag}])
          : $delegation               ? (['overnet_delegate', $delegation->{id}])
          : ()
        ),
      ],
    ),
    content => JSON::encode_json({provenance => {type => 'native'}, body => {}}),
  );
}

sub _delegated_removal_errors {
  my (%args) = @_;
  my $target     = $args{target}     // _signed_event($AUTHORITY, tags => _core_tags(et => 'chat.message'));
  my $delegation = $args{delegation} // _delegation_event();
  my $removal    = _removal_for(target => $target, delegation => $delegation, %args);
  my $result     = Overnet::Core::Validator::validate(
    $removal,
    {
      target_event     => $target,
      delegation_event => exists $args{delegation_context} ? $args{delegation_context} : $delegation,
    },
  );
  return $result->{errors} || [];
}

subtest 'structural guards outside the fixture corpus' => sub {
  my $junk = Overnet::Core::Validator::validate('junk');
  ok !$junk->{valid}, 'non-object inputs are invalid';
  like $junk->{errors}[0], qr/Invalid\ Nostr\ event/mx, 'the parse failure is reported';

  my $unparseable_content = Overnet::Core::Validator::validate(
    _signed_event($AUTHORITY, tags => _core_tags(et => 'chat.message'), content => 'not json'),
  );
  ok !$unparseable_content->{valid}, 'undecodable content is invalid';

  my $empty_tag = Overnet::Core::Validator::validate(
    _signed_event(
      $AUTHORITY,
      tags => [@{_core_tags(et => 'chat.message')}, []],
    ),
  );
  ok defined $empty_tag->{valid}, 'events with empty tag arrays still validate structurally';
};

subtest 'delegation grant field validation' => sub {
  my $bad_pubkey = Overnet::Core::Validator::validate(
    _delegation_event(
      body => {action => 'remove', delegate_pubkey => 'SHORT', expires_at => 1},
    ),
  );
  ok !$bad_pubkey->{valid}, 'malformed delegate pubkeys are invalid';
  ok((grep {/delegate_pubkey\ must\ be/mx} @{$bad_pubkey->{errors}}), 'the pubkey rule is reported');
};

subtest 'delegated removal context validation' => sub {
  my $target = _signed_event($AUTHORITY, tags => _core_tags(et => 'chat.message'));

  my $errors = _delegated_removal_errors(target => $target);
  is_deeply $errors, [], 'a well-formed delegated removal is valid';

  $errors = _delegated_removal_errors(target => $target, delegation_context => 'junk');
  like $errors->[0], qr/Invalid\ delegation\ event/mx, 'unparseable delegation context is refused';

  $errors = _delegated_removal_errors(target => $target, delegate_tag => 'e' x 64);
  like $errors->[0], qr/does\ not\ match\ overnet_delegate/mx,
    'a mismatched delegation id is refused';

  my $not_delegation = _signed_event($AUTHORITY, tags => _core_tags(et => 'chat.message'));
  $errors = _delegated_removal_errors(target => $target, delegation => $not_delegation);
  like $errors->[0], qr/requires\ a\ core\.delegation\ event/mx,
    'a non-delegation context event is refused';

  my $wrong_scope = _delegation_event(oid => 'another-object');
  $errors = _delegated_removal_errors(target => $target, delegation => $wrong_scope);
  like $errors->[0], qr/must\ cover\ the\ removed\ object|scope/imx,
    'a delegation for another object is refused';

  my $foreign_author = _delegation_event(key => $STRANGER);
  $errors = _delegated_removal_errors(target => $target, delegation => $foreign_author);
  like $errors->[0], qr/authored\ by\ the\ same\ pubkey/mx,
    'a delegation from a foreign author is refused';

  my $wrong_action = _delegation_event(
    body => {action => 'grant', delegate_pubkey => $DELEGATE->pubkey_hex, expires_at => 1_744_304_600},
  );
  $errors = _delegated_removal_errors(target => $target, delegation => $wrong_action);
  like $errors->[0], qr/action\ must\ be\ remove/mx, 'a non-remove delegation action is refused';

  my $wrong_delegate = _delegation_event(
    body => {action => 'remove', delegate_pubkey => $STRANGER->pubkey_hex, expires_at => 1_744_304_600},
  );
  $errors = _delegated_removal_errors(target => $target, delegation => $wrong_delegate);
  like $errors->[0], qr/does\ not\ authorize\ this\ removal\ pubkey/mx,
    'a delegation for another delegate is refused';

  my $invalid_content = _delegation_event(content => 'not json');
  $errors = _delegated_removal_errors(target => $target, delegation => $invalid_content);
  like $errors->[0], qr/Invalid\ delegation\ event\ content/mx,
    'a delegation with undecodable content is refused';
};

done_testing;

