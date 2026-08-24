use strictures 2;

use FindBin;
use File::Glob qw(bsd_glob);
use File::Spec;
use File::Temp qw(tempdir);
use JSON       ();
use Test::More;

use Overnet::Auth::StateStore;

subtest 'load_state returns undef when the state file does not exist yet' => sub {
  my $dir  = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $path = File::Spec->catfile($dir, 'auth-state.json');

  my $store = Overnet::Auth::StateStore->new(path => $path);
  my $state = $store->load_state;

  ok !defined($state), 'missing state file returns undef';
};

subtest 'save_state writes atomically and load_state reads the same state back' => sub {
  my $dir  = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $path = File::Spec->catfile($dir, 'auth-state.json');

  my $store = Overnet::Auth::StateStore->new(path => $path);
  my $state = {
    policies => [
      {
        policy_id   => 'policy-1',
        identity_id => 'default',
        program_id  => 'irc.bridge',
        locators    => ['irc://irc.example.test/overnet'],
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
      },
    ],
    service_pins => {
      'wss://relay.example.test/auth' => {
        scheme => 'nostr.pubkey',
        value  => ('1' x 64),
      },
    },
    sessions => [
      {
        session_handle => {id => 'sess-1'},
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => ['wss://relay.example.test/auth'],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        renewable => 1,
        artifacts => [],
      },
    ],
  };

  $store->save_state(state => $state);
  my $loaded = $store->load_state;

  is_deeply $loaded,                  $state, 'saved state loads back unchanged';
  is_deeply [bsd_glob($path . '.*')], [],     'atomic save leaves no temp files behind';
};

subtest 'load_state rejects invalid JSON state objects' => sub {
  my $dir  = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $path = File::Spec->catfile($dir, 'auth-state.json');

  open my $fh, '>', $path or die "open $path failed: $!";
  print {$fh} JSON::encode_json(['not', 'an', 'object'])
    or die "write $path failed: $!";
  close $fh or die "close $path failed: $!";

  my $store = Overnet::Auth::StateStore->new(path => $path);
  my $error = eval {
    $store->load_state;
    1;
  } ? undef : $@;

  like $error, qr/auth\ state\ must\ decode\ to\ an\ object/mx, 'non-object state files are rejected';
};

subtest 'constructor and load_state reject unusable inputs' => sub {
  my $build_error = sub {
    my (@args) = @_;
    return eval { Overnet::Auth::StateStore->new(@args); 1 } ? undef : $@;
  };
  ok !defined $build_error->({path => '/tmp/state.json'}), 'a hashref constructor argument is accepted';
  like $build_error->('odd'), qr/constructor\ arguments\ must\ be\ a\ hash/mx,
    'odd argument lists are rejected';
  like $build_error->(path => q{}), qr/path\ is\ required/mx, 'empty paths are rejected';

  my $dir      = tempdir(CLEANUP => 1);
  my $bad_json = File::Spec->catfile($dir, 'bad-state.json');
  open my $fh, '>', $bad_json or die "open $bad_json failed: $!";
  print {$fh} 'not json' or die "write $bad_json failed: $!";
  close $fh or die "close $bad_json failed: $!";

  my $store = Overnet::Auth::StateStore->new(path => $bad_json);
  my $error = eval { $store->load_state; 1 } ? undef : $@;
  like $error, qr/is\ not\ valid\ JSON/mx, 'invalid JSON state files are rejected';
};

subtest 'state normalization validates each section' => sub {
  my $dir   = tempdir(CLEANUP => 1);
  my $store = Overnet::Auth::StateStore->new(path => File::Spec->catfile($dir, 'state.json'));

  my $save_error = sub {
    my ($state) = @_;
    return eval { $store->save_state(state => $state); 1 } ? undef : $@;
  };
  like $save_error->({policies => {}}), qr/policies\ must\ be\ an\ array/mx,
    'non-array policies are rejected';
  like $save_error->({service_pins => []}), qr/service_pins\ must\ be\ an\ object/mx,
    'non-object service pins are rejected';
  like $save_error->({sessions => {}}), qr/sessions\ must\ be\ an\ array/mx,
    'non-array sessions are rejected';
};

subtest 'save_state creates missing parent directories and clones values' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = File::Spec->catfile($dir, 'nested', 'deeper', 'state.json');

  my $store = Overnet::Auth::StateStore->new(path => $path);
  ok $store->save_state(
    state => {
      policies => [{policy_id => 'p1', tags => [undef, 'kept']}],
      sessions => [],
    },
    ),
    'saving into a missing directory succeeds';
  ok -f $path, 'the state file was created below the new directories';

  my $loaded = $store->load_state;
  is_deeply $loaded->{policies}[0]{tags}, [undef, 'kept'],
    'undef entries are preserved in cloned arrays';
  is_deeply $loaded->{service_pins}, {}, 'missing sections default to empty containers';
};

subtest 'JSON null values round-trip through save and load' => sub {
  my $dir   = tempdir(CLEANUP => 1);
  my $path  = File::Spec->catfile($dir, 'state.json');
  my $store = Overnet::Auth::StateStore->new(path => $path);

  my $saved = eval {
    $store->save_state(
      state => {
        sessions => [{session_handle => {id => 'sess-1'}, service => undef, scope => 's'}],
      },
    );
  };
  is $@, '', 'saving state containing undef hash values does not die';
  ok $saved, 'the save succeeds';

  my $loaded = eval { $store->load_state };
  is $@, '', 'loading state containing JSON nulls does not die';
  is_deeply $loaded->{sessions},
    [{session_handle => {id => 'sess-1'}, service => undef, scope => 's'}],
    'null values are preserved without shifting hash keys';
};

subtest 'filesystem failures surface as croaks' => sub {
  require IO::Socket::UNIX;
  my $dir = tempdir(CLEANUP => 1);

  my $dir_store = Overnet::Auth::StateStore->new(path => $dir);
  my $error = eval { $dir_store->load_state; 1 } ? undef : $@;
  like $error, qr/close\ .*\ failed/mx, 'reading a directory path fails on close';

  my $socket_path = File::Spec->catfile($dir, 'listener.sock');
  IO::Socket::UNIX->new(Type => IO::Socket::UNIX::SOCK_STREAM(), Local => $socket_path, Listen => 1)
    or die "listen on $socket_path failed: $!";
  my $socket_store = Overnet::Auth::StateStore->new(path => $socket_path);
  $error = eval { $socket_store->load_state; 1 } ? undef : $@;
  like $error, qr/open\ .*\ failed/mx, 'unopenable state files fail on open';

  my $dangling = File::Spec->catfile($dir, 'dangling.json');
  symlink File::Spec->catfile($dir, 'missing-dir', 'x'), "$dangling.tmp.$$"
    or die "symlink failed: $!";
  my $dangling_store = Overnet::Auth::StateStore->new(path => $dangling);
  $error = eval { $dangling_store->save_state(state => {}); 1 } ? undef : $@;
  like $error, qr/open\ .*\.tmp\.\d+\ failed/mx, 'unwritable temp files fail on open';

  my $full_small = File::Spec->catfile($dir, 'full-small.json');
  symlink '/dev/full', "$full_small.tmp.$$" or die "symlink failed: $!";
  $error = eval { Overnet::Auth::StateStore->new(path => $full_small)->save_state(state => {}); 1 } ? undef : $@;
  like $error, qr/close\ .*\.tmp\.\d+\ failed/mx, 'a full device fails on close';

  my $full_big = File::Spec->catfile($dir, 'full-big.json');
  symlink '/dev/full', "$full_big.tmp.$$" or die "symlink failed: $!";
  $error = eval {
    Overnet::Auth::StateStore->new(path => $full_big)
      ->save_state(state => {sessions => [{blob => ('x' x 300_000)}]});
    1;
  } ? undef : $@;
  like $error, qr/(?:(?:write|close)\ .*\ failed|No\ space\ left\ on\ device)/mx,
    'a full device fails on buffered writes';

  my $occupied = File::Spec->catdir($dir, 'occupied');
  mkdir $occupied or die "mkdir $occupied failed: $!";
  open my $keep, '>', File::Spec->catfile($occupied, 'keep') or die "open keep failed: $!";
  close $keep or die "close keep failed: $!";
  $error = eval { Overnet::Auth::StateStore->new(path => $occupied)->save_state(state => {}); 1 } ? undef : $@;
  like $error, qr/rename\ .*\ failed/mx, 'renames over occupied paths fail';
};

done_testing;
