use strict;
use warnings;

use File::Spec;
use FindBin;
use lib File::Spec->catdir($FindBin::Bin, '..', 'contrib', 'znc');
use Test::More;

BEGIN {
  package ZNC::Module;
}

my $root = File::Spec->catdir($FindBin::Bin, '..');
my $src  = File::Spec->catfile($root, 'contrib', 'znc', 'overnetauth.pm');

ok -f $src, 'ZNC overnetauth module source exists';

require_ok 'overnetauth';

my $config = overnetauth::Core::default_config();
$config->{helper} = '/opt/overnet auth';
$config->{helper_args} = '--auth-sock /tmp/auth.sock';
$config->{scope} = 'irc://irc.example.test/overnet';

my $line = ":server NOTICE alice :OVERNETAUTH CHALLENGE abc'def";
my $command = overnetauth::Core::build_bridge_command($config, $line);
like $command, qr/'irc:\/\/irc\.example\.test\/overnet'/, 'scope is shell-quoted';
like $command, qr/abc'\\''def/, 'server line is shell-quoted';
unlike $command, qr/--no-quote\z/, 'quoted helper output is used by default';

$config->{no_quote} = 1;
$command = overnetauth::Core::build_bridge_command($config, $line);
like $command, qr/--no-quote\z/, 'no_quote can be requested explicitly';

ok overnetauth::Core::contains_auth_prompt(
  ':server NOTICE alice :OVERNETAUTH CHALLENGE ' . ('a' x 64)
), 'OVERNETAUTH prompt detected';
is overnetauth::Core::auth_prompt_kind(
  ':server NOTICE alice :OVERNETAUTH CHALLENGE ' . ('a' x 64)
), 'overnetauth', 'OVERNETAUTH prompt kind detected';
ok overnetauth::Core::contains_auth_prompt(
  ':server NOTICE alice :OVERNETAUTH DELEGATE ' . ('b' x 64) . ' session-1 ws://127.0.0.1:7448 1782057273'
), 'OVERNETAUTH delegation prompt detected';
ok overnetauth::Core::contains_auth_prompt('AUTHENTICATE deadbeef'),
  'bare SASL AUTHENTICATE prompt detected';
is overnetauth::Core::auth_prompt_kind('AUTHENTICATE deadbeef'), 'sasl',
  'SASL prompt kind detected';
ok !overnetauth::Core::contains_auth_prompt(
  ':server NOTICE alice :OVERNETAUTH AUTH ' . ('a' x 64)
), 'OVERNETAUTH success is not treated as a helper prompt';
ok !overnetauth::Core::contains_auth_prompt(
  ':server NOTICE alice :OVERNETAUTH DELEGATE is required for authoritative JOIN'
), 'OVERNETAUTH error is not treated as a helper prompt';
ok !overnetauth::Core::contains_auth_prompt(':server 001 alice :welcome'),
  'ordinary server line ignored';
ok overnetauth::Core::is_overnetauth_auth_success(
  ':irc.overnet.local NOTICE alice :OVERNETAUTH AUTH ' . ('a' x 64)
), 'OVERNETAUTH AUTH success is detected';
ok !overnetauth::Core::is_overnetauth_auth_success(
  ':irc.overnet.local NOTICE alice :OVERNETAUTH AUTH requires a valid signed Nostr event'
), 'OVERNETAUTH AUTH error is not treated as success';
ok overnetauth::Core::mode_handles_prompt('overnetauth', 'overnetauth'),
  'overnetauth mode handles overnetauth prompts';
ok !overnetauth::Core::mode_handles_prompt('sasl', 'overnetauth'),
  'sasl mode ignores overnetauth prompts';
ok !overnetauth::Core::mode_handles_prompt('passive', 'overnetauth'),
  'passive mode ignores overnetauth prompts';

is_deeply(
  [ overnetauth::Core::sanitize_helper_output(
      "/quote OVERNETAUTH AUTH payload\n" .
      "AUTHENTICATE payload2\r\n" .
      "PRIVMSG #overnet :bad\n"
    )
  ],
  [ 'OVERNETAUTH AUTH payload', 'AUTHENTICATE payload2' ],
  'helper output is sanitized before forwarding',
);

my ($helper_output, $status) =
  overnetauth::Core::run_helper_command(q{printf 'OVERNETAUTH AUTH from-helper\n'});
is $status, 0, 'helper command exits successfully';
is $helper_output, "OVERNETAUTH AUTH from-helper\n", 'helper command output captured';

($helper_output, $status) =
  overnetauth::Core::run_helper_command(q{printf 'bad helper\n' >&2; exit 13});
is overnetauth::Core::status_summary($status), 'exit 13',
  'helper exit status is summarized';
is overnetauth::Core::first_helper_diagnostic($helper_output), 'bad helper',
  'helper stderr is captured for diagnostics';

is_deeply(
  [
    overnetauth::Core::config_warnings(
      { %{ overnetauth::Core::default_config() }, scope => '', no_quote => 1 },
      'overnetauth',
    )
  ],
  [
    'scope is required for OVERNETAUTH helper signing',
    'no_quote=true requires a helper that emits complete raw IRC commands',
  ],
  'config warnings catch missing scope and risky no_quote mode',
);

{
  no warnings qw(once redefine);
  local *overnetauth::PutModule = sub {
    my ($self, $line) = @_;
    push @{ $self->{test_module_output} }, $line;
  };
  local *overnetauth::PutIRC = sub {
    my ($self, $line) = @_;
    push @{ $self->{test_irc_output} }, $line;
  };
  local *overnetauth::SetNV = sub {
    my ($self, $key, $value) = @_;
    $self->{test_nv}{$key} = $value;
  };

  my $module = bless {
    config => overnetauth::Core::default_config(),
    mode   => 'overnetauth',
    debug  => 0,
  }, 'overnetauth';

  is $module->OnModCommand('Show'), 1,
    'OnModCommand returns a defined value so ZNC does not run the fallback';
  like $module->{test_module_output}[0], qr/\Ahelper: /,
    'Show command emits module output';

  is $module->OnModCommand('Challenge'), 1,
    'Challenge command is handled';
  is $module->{test_irc_output}[0], 'OVERNETAUTH CHALLENGE',
    'Challenge command sends OVERNETAUTH challenge upstream';

  is $module->OnModCommand('Delegate'), 1,
    'Delegate command is handled';
  is $module->{test_irc_output}[1], 'OVERNETAUTH DELEGATE',
    'Delegate command sends OVERNETAUTH delegate request upstream';

  is $module->OnModCommand('Set'), 1,
    'invalid Set command is still handled';
}

{
  no warnings qw(once redefine);
  local *overnetauth::PutModule = sub {
    my ($self, $line) = @_;
    push @{ $self->{test_module_output} }, $line;
  };
  local *overnetauth::PutIRC = sub {
    my ($self, $line) = @_;
    push @{ $self->{test_irc_output} }, $line;
  };

  my $module = bless {
    config => overnetauth::Core::default_config(),
    mode   => 'overnetauth',
    debug  => 0,
  }, 'overnetauth';

  $module->_handle_helper_output("helper exploded\n", 13 << 8);
  is_deeply $module->{test_irc_output}, undef,
    'failed helper output is not forwarded upstream';
  like $module->{test_module_output}[0], qr/\Ahelper failed: exit 13\z/,
    'helper failure is reported even when debug is off';
  like $module->{test_module_output}[1], qr/\Ahelper diagnostic: helper exploded\z/,
    'helper diagnostic is reported';
}

{
  no warnings qw(once redefine);
  local *overnetauth::PutIRC = sub {
    my ($self, $line) = @_;
    push @{ $self->{test_irc_output} }, $line;
  };
  local *overnetauth::Core::run_helper = sub {
    return ('', 0);
  };

  my $module = bless {
    config => {
      %{ overnetauth::Core::default_config() },
      auto_delegate => 1,
    },
    mode   => 'overnetauth',
    debug  => 0,
  }, 'overnetauth';

  $module->OnRaw(':irc.overnet.local NOTICE alice :OVERNETAUTH AUTH ' . ('a' x 64));
  is_deeply $module->{test_irc_output}, [ 'OVERNETAUTH DELEGATE' ],
    'successful OVERNETAUTH AUTH response requests delegation automatically';
}

{
  no warnings qw(once redefine);
  my $helper_calls = 0;
  local *overnetauth::PutIRC = sub {
    my ($self, $line) = @_;
    push @{ $self->{test_irc_output} }, $line;
  };
  local *overnetauth::Core::run_helper = sub {
    $helper_calls++;
    return ('OVERNETAUTH AUTH should-not-send', 0);
  };

  my $module = bless {
    config => {
      %{ overnetauth::Core::default_config() },
      auto_delegate => 1,
    },
    mode   => 'passive',
    debug  => 0,
  }, 'overnetauth';

  $module->OnRaw(':irc.overnet.local NOTICE alice :OVERNETAUTH CHALLENGE ' . ('a' x 64));
  $module->OnRaw(':irc.overnet.local NOTICE alice :OVERNETAUTH AUTH ' . ('b' x 64));
  is $helper_calls, 0,
    'passive mode does not run the helper for auth prompts';
  is_deeply $module->{test_irc_output}, undef,
    'passive mode does not auto-delegate after manual auth';
}

{
  no warnings qw(once redefine);
  my @helper_lines;
  local *overnetauth::Core::run_helper = sub {
    my ($config, $line) = @_;
    push @helper_lines, $line;
    return ('', 0);
  };

  my $module = bless {
    config => overnetauth::Core::default_config(),
    mode   => 'sasl',
    debug  => 0,
  }, 'overnetauth';

  $module->OnRaw(':irc.overnet.local NOTICE alice :OVERNETAUTH CHALLENGE ' . ('a' x 64));
  $module->OnRaw('AUTHENTICATE deadbeef');
  is scalar(@helper_lines), 1,
    'sasl mode only runs helper for SASL prompts';
  is $helper_lines[0], 'AUTHENTICATE deadbeef',
    'sasl mode passes SASL prompt to helper';
}

done_testing;
