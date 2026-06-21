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
like $command, qr/--no-quote\z/, 'no_quote is passed by default';

ok overnetauth::Core::contains_auth_prompt($line), 'OVERNETAUTH prompt detected';
ok overnetauth::Core::contains_auth_prompt('AUTHENTICATE deadbeef'),
  'bare SASL AUTHENTICATE prompt detected';
ok !overnetauth::Core::contains_auth_prompt(':server 001 alice :welcome'),
  'ordinary server line ignored';

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

  is $module->OnModCommand('Set'), 1,
    'invalid Set command is still handled';
}

done_testing;
