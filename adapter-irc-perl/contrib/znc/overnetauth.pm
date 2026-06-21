package overnetauth;

use strict;
use warnings;

our @ISA = qw(ZNC::Module);

sub description {
  'Delegates OVERNETAUTH and SASL NOSTR replies to an external Overnet helper.'
}

sub module_types {
  return $ZNC::CModInfo::NetworkModule if defined $ZNC::CModInfo::NetworkModule;
  return;
}

sub wiki_page {
  'overnetauth'
}

sub has_args {
  1
}

sub args_help_text {
  'helper=COMMAND helper_args=ARGS scope=IRC_SCOPE mode=overnetauth|sasl|both|passive no_quote=true|false auto_delegate=true|false debug=true|false'
}

sub OnLoad {
  my ($self, $args, $message) = @_;

  $self->{config} = overnetauth::Core::default_config();
  $self->{config}->{helper} = $self->GetNV('helper')
    if $self->_nv_has_value('helper');
  $self->{config}->{helper_args} = $self->GetNV('helper_args')
    if $self->_nv_has_value('helper_args');
  $self->{config}->{scope} = $self->GetNV('scope')
    if $self->_nv_has_value('scope');
  $self->{config}->{no_quote} =
    overnetauth::Core::parse_bool($self->GetNV('no_quote'), 0);
  $self->{config}->{auto_delegate} =
    overnetauth::Core::parse_bool($self->GetNV('auto_delegate'), 1);
  $self->{mode} = $self->_nv_has_value('mode') ? $self->GetNV('mode') : 'overnetauth';
  $self->{debug} = overnetauth::Core::parse_bool($self->GetNV('debug'), 0);

  for my $token (grep { length } split /\s+/, ($args // '')) {
    my ($key, $value) = split /=/, $token, 2;
    next unless defined $key && length $key;
    $value //= '';
    $self->_set_value(lc $key, $value, 0);
  }

  $self->_save;
  return 1;
}

sub OnIRCConnected {
  my ($self) = @_;

  if ($self->{mode} eq 'overnetauth' || $self->{mode} eq 'both') {
    $self->PutIRC('OVERNETAUTH CHALLENGE');
  }
  if ($self->{mode} eq 'sasl' || $self->{mode} eq 'both') {
    $self->PutIRC('AUTHENTICATE NOSTR');
  }

  return;
}

sub OnRaw {
  my ($self, $line) = @_;

  if (overnetauth::Core::contains_auth_prompt($line)) {
    $self->PutModule('running helper for auth prompt') if $self->{debug};
    my ($output, $status) =
      overnetauth::Core::run_helper($self->{config}, $line);
    $self->_handle_helper_output($output, $status);
  }
  if ($self->{config}->{auto_delegate}
      && overnetauth::Core::is_overnetauth_auth_success($line)) {
    $self->PutIRC('OVERNETAUTH DELEGATE');
  }

  return defined $ZNC::CONTINUE ? $ZNC::CONTINUE : 0;
}

sub OnModCommand {
  my ($self, $line) = @_;

  my ($command, $rest) = split /\s+/, ($line // ''), 2;
  $command = lc($command // '');
  $rest //= '';

  if ($command eq 'show') {
    $self->_show;
  } elsif ($command eq 'set') {
    my ($key, $value) = split /\s+/, $rest, 2;
    if (!defined $key || !defined $value || $key eq '' || $value eq '') {
      $self->PutModule('Usage: Set <key> <value>');
      return 1;
    }
    $self->_save if $self->_set_value(lc $key, $value, 1);
  } elsif ($command eq 'clear') {
    my ($key) = split /\s+/, $rest, 2;
    $self->_clear(lc($key // ''));
  } elsif ($command eq 'challenge') {
    $self->PutIRC('OVERNETAUTH CHALLENGE');
  } elsif ($command eq 'delegate') {
    $self->PutIRC('OVERNETAUTH DELEGATE');
  } elsif ($command eq 'sasl') {
    $self->PutIRC('AUTHENTICATE NOSTR');
  } elsif ($command eq 'doctor') {
    $self->_doctor;
  } else {
    $self->PutModule('Commands: Show, Set, Clear, Challenge, Delegate, SASL, Doctor');
  }

  return 1;
}

sub _handle_helper_output {
  my ($self, $output, $status) = @_;

  if ($status != 0) {
    $self->PutModule('helper failed: ' . overnetauth::Core::status_summary($status));
    my $diagnostic = overnetauth::Core::first_helper_diagnostic($output);
    $self->PutModule('helper diagnostic: ' . $diagnostic)
      if length $diagnostic;
  }

  my @lines = overnetauth::Core::sanitize_helper_output($output);
  $self->PutIRC($_) for @lines;

  if (!@lines && $self->{debug}) {
    $self->PutModule('helper emitted no IRC auth commands');
  }

  return;
}

sub _show {
  my ($self) = @_;

  $self->PutModule('helper: ' . $self->{config}->{helper});
  $self->PutModule('helper_args: ' . $self->{config}->{helper_args});
  $self->PutModule('scope: ' . $self->{config}->{scope});
  $self->PutModule('mode: ' . $self->{mode});
  $self->PutModule('no_quote: ' . ($self->{config}->{no_quote} ? 'true' : 'false'));
  $self->PutModule('auto_delegate: ' . ($self->{config}->{auto_delegate} ? 'true' : 'false'));
  $self->PutModule('debug: ' . ($self->{debug} ? 'true' : 'false'));
  $self->_show_warnings;
  return;
}

sub _doctor {
  my ($self) = @_;

  $self->_show;
  $self->PutModule('identity: helper must sign as the IRC account owner');
  return;
}

sub _show_warnings {
  my ($self) = @_;

  my @warnings = overnetauth::Core::config_warnings($self->{config}, $self->{mode});
  $self->PutModule('warning: ' . $_) for @warnings;
  return;
}

sub _set_value {
  my ($self, $key, $value, $report) = @_;

  if ($key eq 'helper') {
    $self->{config}->{helper} = $value;
  } elsif ($key eq 'helper_args') {
    $self->{config}->{helper_args} = $value;
  } elsif ($key eq 'scope') {
    $self->{config}->{scope} = $value;
  } elsif ($key eq 'mode') {
    my $mode = lc $value;
    if ($mode !~ /\A(?:overnetauth|sasl|both|passive)\z/) {
      $self->PutModule('mode must be overnetauth, sasl, both, or passive')
        if $report;
      return 0;
    }
    $self->{mode} = $mode;
  } elsif ($key eq 'no_quote') {
    $self->{config}->{no_quote} = overnetauth::Core::parse_bool($value, 0);
  } elsif ($key eq 'auto_delegate') {
    $self->{config}->{auto_delegate} = overnetauth::Core::parse_bool($value, 0);
  } elsif ($key eq 'debug') {
    $self->{debug} = overnetauth::Core::parse_bool($value, 0);
  } else {
    $self->PutModule("unknown key: $key") if $report;
    return 0;
  }

  $self->PutModule("Updated $key") if $report;
  return 1;
}

sub _clear {
  my ($self, $key) = @_;

  if ($key eq 'helper_args') {
    $self->{config}->{helper_args} = '';
  } elsif ($key eq 'scope') {
    $self->{config}->{scope} = '';
  } else {
    $self->PutModule('Only helper_args and scope can be cleared');
    return;
  }

  $self->_save;
  $self->PutModule("Cleared $key");
  return;
}

sub _save {
  my ($self) = @_;

  $self->SetNV('helper',      $self->{config}->{helper});
  $self->SetNV('helper_args', $self->{config}->{helper_args});
  $self->SetNV('scope',       $self->{config}->{scope});
  $self->SetNV('no_quote',    $self->{config}->{no_quote} ? 'true' : 'false');
  $self->SetNV('auto_delegate', $self->{config}->{auto_delegate} ? 'true' : 'false');
  $self->SetNV('mode',        $self->{mode});
  $self->SetNV('debug',       $self->{debug} ? 'true' : 'false');
  return;
}

sub _nv_has_value {
  my ($self, $key) = @_;
  return $self->ExistsNV($key) if $self->can('ExistsNV');
  return length($self->GetNV($key) // '') ? 1 : 0;
}

package overnetauth::Core;

use strict;
use warnings;

sub default_config {
  return {
    helper      => 'overnet-irc-auth.pl',
    helper_args => '',
    scope       => '',
    no_quote    => 0,
    auto_delegate => 1,
  };
}

sub parse_bool {
  my ($value, $default) = @_;
  return $default unless defined $value && length $value;
  return $value =~ /\A(?:1|true|yes|on)\z/i ? 1 : 0;
}

sub trim {
  my ($value) = @_;
  $value //= '';
  $value =~ s/\A[ \t\r\n]+//;
  $value =~ s/[ \t\r\n]+\z//;
  return $value;
}

sub shell_quote {
  my ($value) = @_;
  $value //= '';
  $value =~ s/'/'\\''/g;
  return "'$value'";
}

sub contains_auth_prompt {
  my ($line) = @_;
  my $trimmed = trim($line);
  return 1 if $trimmed =~ /\bOVERNETAUTH\s+CHALLENGE\s+[0-9a-f]{64}\b/i;
  return 1 if $trimmed =~ /\bOVERNETAUTH\s+DELEGATE\s+[0-9a-f]{64}\s+\S+\s+\S+\s+\d+\b/i;
  return 1 if index($trimmed, ' AUTHENTICATE ') >= 0;
  return 1 if $trimmed =~ /\AAUTHENTICATE /;
  return 0;
}

sub is_overnetauth_auth_success {
  my ($line) = @_;
  my $trimmed = trim($line);
  return $trimmed =~ /\bOVERNETAUTH\s+AUTH\s+[0-9a-f]{64}\b/i ? 1 : 0;
}

sub build_bridge_command {
  my ($config, $line) = @_;

  my $command = $config->{helper} . ' bridge';
  $command .= ' ' . $config->{helper_args}
    if length($config->{helper_args} // '');
  $command .= ' --scope ' . shell_quote($config->{scope})
    if length($config->{scope} // '');
  $command .= ' --line ' . shell_quote($line);
  $command .= ' --no-quote' if $config->{no_quote};

  return $command;
}

sub allowed_client_command {
  my ($line) = @_;
  return $line =~ /\A(?:OVERNETAUTH|AUTHENTICATE) / ? 1 : 0;
}

sub status_summary {
  my ($status) = @_;
  return 'timeout or launch failure' if !defined($status) || $status < 0;
  my $exit = $status >> 8;
  my $signal = $status & 127;
  return "signal $signal" if $signal;
  return "exit $exit";
}

sub first_helper_diagnostic {
  my ($output) = @_;

  for my $line (split /\n/, ($output // '')) {
    $line = trim($line);
    $line = trim(substr $line, 7) if index($line, '/quote ') == 0;
    next unless length $line;
    next if allowed_client_command($line);
    $line = substr($line, 0, 200) . '...' if length($line) > 200;
    return $line;
  }

  return '';
}

sub config_warnings {
  my ($config, $mode) = @_;
  my @warnings;

  if (($mode || '') =~ /\A(?:overnetauth|both)\z/
      && !length($config->{scope} // '')) {
    push @warnings, 'scope is required for OVERNETAUTH helper signing';
  }
  if ($config->{no_quote}) {
    push @warnings, 'no_quote=true requires a helper that emits complete raw IRC commands';
  }

  return @warnings;
}

sub sanitize_helper_output {
  my ($output) = @_;
  my @lines;

  for my $line (split /\n/, ($output // '')) {
    $line = trim($line);
    $line = trim(substr $line, 7) if index($line, '/quote ') == 0;
    next if length($line) > 2048;
    next unless allowed_client_command($line);
    push @lines, $line;
    last if @lines >= 16;
  }

  return @lines;
}

sub run_helper {
  my ($config, $line) = @_;
  return run_helper_command(build_bridge_command($config, $line));
}

sub run_helper_command {
  my ($command) = @_;
  my $output = '';
  my $status = -1;

  local $SIG{ALRM} = sub { die "helper timed out\n" };
  my $ok = eval {
    alarm 10;
    if (open my $pipe, '-|', '(' . $command . ') 2>&1') {
      while (defined(my $chunk = <$pipe>)) {
        $output .= $chunk;
        last if length($output) > 65_536;
      }
      close $pipe;
      $status = $?;
    }
    alarm 0;
    1;
  };
  alarm 0;

  return ($output, $ok ? $status : -1);
}

1;
