package Overnet::Adapter::IRC::InputMapper;

use strictures 2;
use Moo;
use JSON ();
use Overnet::Adapter::IRC::Role::Validation;

our $VERSION = '0.001';
my $JSON = JSON->new;

with 'Overnet::Adapter::IRC::Role::Validation';

has overnet_version => (
  is       => 'ro',
  required => 1,
);
has nip29 => (
  is       => 'ro',
  required => 1,
);

no Moo;

sub map_input {
  my ($self, %args) = @_;

  my $validation_error = _validate_map_input_args(\%args);
  if (defined $validation_error) {
    return $validation_error;
  }

  my $session_config = _session_config_from_args($args{session_config});
  if (_should_map_nip29_authoritative_input(\%args, $session_config)) {
    return $self->nip29->map_input(%args, session_config => $session_config,);
  }

  return _map_standard_input($self, \%args);
}

sub _validate_map_input_args {
  my ($args) = @_;

  my $command = $args->{command};
  if (!_non_empty_scalar($command)) {
    return _error('IRC command is required');
  }
  if (!_is_supported_map_command($command)) {
    return _error("Unsupported IRC command: $command");
  }

  if (!_non_empty_scalar($args->{network})) {
    return _error('IRC network is required');
  }
  if ($command ne 'NICK' && !_non_empty_scalar($args->{target})) {
    return _error('IRC target is required');
  }
  if (!_non_empty_scalar($args->{nick})) {
    return _error('Sender nick is required');
  }
  if (!_non_negative_integer($args->{created_at})) {
    return _error('created_at must be a non-negative integer');
  }

  my $identity_error = _validate_irc_identity_args($args);
  if (defined $identity_error) {
    return $identity_error;
  }

  if ($command eq 'MODE' && exists $args->{mode_args} && !_valid_non_empty_scalar_array($args->{mode_args})) {
    return _error('MODE mode_args must be an array of non-empty strings');
  }

  return;
}

sub _is_supported_map_command {
  my ($command) = @_;
  my %supported = map { $_ => 1 } qw(PRIVMSG NOTICE TOPIC JOIN INVITE PART QUIT KICK NICK MODE DELETE UNDELETE);
  return $supported{$command} ? 1 : 0;
}

sub _validate_irc_identity_args {
  my ($args) = @_;

  for my $field (qw(account user host)) {
    next if !exists $args->{$field};
    if (!_non_empty_scalar($args->{$field})) {
      return _error("IRC $field must be a non-empty string");
    }
  }

  return;
}

sub _irc_identity_from_args {
  my ($args) = @_;
  my %irc_identity;

  for my $field (qw(account user host)) {
    if (exists $args->{$field}) {
      $irc_identity{$field} = $args->{$field};
    }
  }

  return \%irc_identity;
}

sub _should_map_nip29_authoritative_input {
  my ($args, $session_config) = @_;
  my %authoritative_commands = map { $_ => 1 } qw(KICK MODE TOPIC INVITE JOIN PART DELETE UNDELETE);

  if (($session_config->{authority_profile} || q{}) ne 'nip29') {
    return 0;
  }
  if (!_is_channel_target($args->{target})) {
    return 0;
  }

  return $authoritative_commands{$args->{command}} ? 1 : 0;
}

sub _map_standard_input {
  my ($self, $args) = @_;
  my %mapper_for = (
    NICK    => \&_map_nick_input,
    MODE    => \&_map_mode_input,
    TOPIC   => \&_map_topic_input,
    JOIN    => \&_map_membership_input,
    PART    => \&_map_membership_input,
    QUIT    => \&_map_membership_input,
    KICK    => \&_map_membership_input,
    PRIVMSG => \&_map_message_input,
    NOTICE  => \&_map_message_input,
  );

  my $mapper = $mapper_for{$args->{command}};
  if (!defined $mapper) {
    return _error("Unsupported IRC command: $args->{command}");
  }

  return $mapper->($self, $args);
}

sub _map_nick_input {
  my ($self, $args) = @_;

  if (!_non_empty_scalar($args->{new_nick})) {
    return _error('NICK new_nick is required');
  }

  return _map_input_event_result(
    $self, $args,
    {
      kind        => 7_800,
      event_type  => 'irc.nick',
      object_type => 'irc.network',
      object_id   => "irc:$args->{network}",
      origin      => $args->{network},
      body        => {
        old_nick => $args->{nick},
        new_nick => $args->{new_nick},
      },
    },
  );
}

sub _map_mode_input {
  my ($self, $args) = @_;

  if (!_is_channel_target($args->{target})) {
    return _error('MODE target must be a channel');
  }
  if (!_non_empty_scalar($args->{mode})) {
    return _error('MODE mode is required');
  }

  my $body = {mode => $args->{mode},};
  if (exists $args->{mode_args}) {
    $body->{mode_args} = [@{$args->{mode_args}}];
  }

  return _map_input_event_result(
    $self, $args,
    {
      kind        => 7_800,
      event_type  => 'irc.mode',
      object_type => 'chat.channel',
      object_id   => "irc:$args->{network}:$args->{target}",
      origin      => "$args->{network}/$args->{target}",
      body        => $body,
    },
  );
}

sub _map_topic_input {
  my ($self, $args) = @_;

  if (!_is_channel_target($args->{target})) {
    return _error('TOPIC target must be a channel');
  }
  if (!defined $args->{text}) {
    return _error('TOPIC text is required');
  }

  return _map_input_event_result(
    $self, $args,
    {
      kind        => 37_800,
      event_type  => 'chat.topic',
      object_type => 'chat.channel',
      object_id   => "irc:$args->{network}:$args->{target}",
      origin      => "$args->{network}/$args->{target}",
      body        => {topic => $args->{text},},
    },
  );
}

sub _map_membership_input {
  my ($self, $args) = @_;
  my %event_type_for = (
    JOIN => 'chat.join',
    PART => 'chat.part',
    QUIT => 'chat.quit',
    KICK => 'chat.kick',
  );
  my %target_error_for = (
    JOIN => 'JOIN target must be a channel',
    PART => 'PART target must be a channel',
    QUIT => 'QUIT target must be a channel',
    KICK => 'KICK target must be a channel',
  );
  my $command = $args->{command};

  if (!_is_channel_target($args->{target})) {
    return _error($target_error_for{$command});
  }
  if ($command eq 'KICK' && !_non_empty_scalar($args->{target_nick})) {
    return _error('KICK target_nick is required');
  }

  my $body = {};
  if ($command eq 'KICK') {
    $body->{target_nick} = $args->{target_nick};
  }
  if (defined $args->{text} && length $args->{text}) {
    $body->{reason} = $args->{text};
  }

  return _map_input_event_result(
    $self, $args,
    {
      kind        => 7_800,
      event_type  => $event_type_for{$command},
      object_type => 'chat.channel',
      object_id   => "irc:$args->{network}:$args->{target}",
      origin      => "$args->{network}/$args->{target}",
      body        => $body,
    },
  );
}

sub _map_message_input {
  my ($self, $args) = @_;

  if (!_non_empty_scalar($args->{text})) {
    return _error('Message text is required');
  }
  if (_is_channel_target($args->{target})) {
    return _map_channel_message_input($self, $args);
  }

  return _map_direct_message_input($self, $args);
}

sub _map_channel_message_input {
  my ($self, $args) = @_;
  my $event_type = $args->{command} eq 'PRIVMSG' ? 'chat.message' : 'chat.notice';

  return _map_input_event_result(
    $self, $args,
    {
      kind        => 7_800,
      event_type  => $event_type,
      object_type => 'chat.channel',
      object_id   => "irc:$args->{network}:$args->{target}",
      origin      => "$args->{network}/$args->{target}",
      body        => {text => $args->{text},},
    },
  );
}

sub _map_direct_message_input {
  my ($self, $args) = @_;
  my $event_type = $args->{command} eq 'PRIVMSG' ? 'chat.dm_message' : 'chat.dm_notice';

  return _map_input_event_result(
    $self, $args,
    {
      kind        => 7_800,
      event_type  => $event_type,
      object_type => 'chat.dm',
      object_id   => "irc:$args->{network}:dm:$args->{target}",
      origin      => "$args->{network}/$args->{target}",
      body        => {text => $args->{text},},
    },
  );
}

sub _map_input_event_result {
  my ($self, $args, $mapped) = @_;
  my $body         = $mapped->{body};
  my $irc_identity = _irc_identity_from_args($args);
  my @tags         = $self->_overnet_tags($mapped->{event_type}, $mapped->{object_type}, $mapped->{object_id});
  my @limitations  = qw(unsigned no_edit_history);

  if (!exists $irc_identity->{account}) {
    push @limitations, 'synthetic_identity';
  }
  if (keys %{$irc_identity}) {
    $body->{irc_identity} = {%{$irc_identity}};
  }

  return {
    valid => 1,
    event => {
      kind       => $mapped->{kind},
      created_at => $args->{created_at} + 0,
      tags       => \@tags,
      content    => $JSON->encode(
        {
          provenance => {
            type              => 'adapted',
            protocol          => 'irc',
            origin            => $mapped->{origin},
            external_identity => $args->{nick},
            limitations       => \@limitations,
          },
          body => $body,
        }
      ),
    },
  };
}

sub _overnet_tags {
  my ($self, $event_type, $object_type, $object_id) = @_;
  return (
    ['overnet_v',   $self->{overnet_version}],
    ['overnet_et',  $event_type],
    ['overnet_ot',  $object_type],
    ['overnet_oid', $object_id],
    ['v',           $self->{overnet_version}],
    ['t',           $event_type],
    ['o',           $object_type],
    ['d',           $object_id],
  );
}

1;

=head1 NAME

Overnet::Adapter::IRC::InputMapper - IRC input to Overnet event mapping

=head1 DESCRIPTION

This internal collaborator validates IRC input and maps standard IRC commands
to Overnet event drafts. Authoritative NIP-29 commands are delegated to the
shared NIP-29 collaborator.

=head1 SYNOPSIS

  my $mapper = Overnet::Adapter::IRC::InputMapper->new(
    overnet_version => '0.1.0',
    nip29           => $nip29,
  );
  my $result = $mapper->map_input(%irc_input);

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

=head2 map_input

Validates and maps one IRC input.

=head2 overnet_version

Returns the Overnet version used in generated event tags.

=head2 nip29

Returns the authoritative NIP-29 collaborator.

=head1 DIAGNOSTICS

Invalid input is returned as a structured adapter error.

=head1 CONFIGURATION AND ENVIRONMENT

This collaborator receives its Overnet version and NIP-29 dependency from the
adapter facade.

=head1 DEPENDENCIES

This module depends on JSON and Moo.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

Generated events are unsigned drafts.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
