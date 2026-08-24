package Overnet::Adapter::IRC;

use strictures 2;
use Moo;
use Carp qw(croak);
use JSON ();
use Overnet::Adapter::IRC::InputMapper;
use Overnet::Adapter::IRC::NIP29;
use Overnet::Adapter::IRC::Presence;

our $VERSION = '0.001';

has overnet_version => (is => 'ro');
has session_state   => (is => 'ro');
has _nip29 => (
  is      => 'ro',
  lazy    => 1,
  default => sub { Overnet::Adapter::IRC::NIP29->new },
  handles => [
    qw(
      derive_authoritative_channel_state
      derive_authoritative_ban_list_view
      derive_authoritative_list_entry_view
      derive_authoritative_join_admission
      derive_authoritative_speak_permission
      derive_authoritative_topic_permission
      derive_authoritative_mode_write_permission
      derive_authoritative_channel_action_permission
      derive_authoritative_channel_view
    )
  ],
);
has _input_mapper => (
  is      => 'ro',
  lazy    => 1,
  default => sub {
    my ($self) = @_;
    return Overnet::Adapter::IRC::InputMapper->new(
      overnet_version => $self->overnet_version,
      nip29           => $self->_nip29,
    );
  },
  handles => ['map_input'],
);
has _presence => (
  is      => 'ro',
  lazy    => 1,
  default => sub {
    my ($self) = @_;
    return Overnet::Adapter::IRC::Presence->new(overnet_version => $self->overnet_version,);
  },
  handles => {derive_channel_presence => 'derive'},
);

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);
  $args{overnet_version} //= '0.1.0';
  $args{session_state} ||= {};
  return \%args;
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub supported_secret_slots {
  return ['server_password', 'nickserv_password', 'sasl_password',];
}

sub open_session {
  my ($self, %args) = @_;
  my $adapter_session_id = $args{adapter_session_id};
  my $session_config     = $args{session_config} || {};
  my $secret_values      = $args{secret_values}  || {};
  my %supported          = map { $_ => 1 } @{supported_secret_slots()};

  if (!(defined($adapter_session_id) && !ref($adapter_session_id) && length($adapter_session_id))) {
    croak "adapter_session_id is required\n";
  }
  if (ref($session_config) ne 'HASH') {
    croak "session_config must be an object\n";
  }
  if (ref($secret_values) ne 'HASH') {
    croak "secret_values must be an object\n";
  }

  for my $slot (sort keys %{$secret_values}) {
    if (!$supported{$slot}) {
      croak "Unsupported IRC secret slot: $slot\n";
    }
    if (!defined($secret_values->{$slot}) || ref($secret_values->{$slot})) {
      croak "IRC secret slot $slot must be a string\n";
    }
  }

  $self->{session_state}{$adapter_session_id} = {secret_slots => {map { $_ => 1 } sort keys %{$secret_values}},};
  return {accepted => JSON::true,};
}

sub close_session {
  my ($self, %args) = @_;
  my $adapter_session_id = $args{adapter_session_id};

  if (!(defined($adapter_session_id) && !ref($adapter_session_id) && length($adapter_session_id))) {
    croak "adapter_session_id is required\n";
  }

  delete $self->{session_state}{$adapter_session_id};
  return 1;
}

sub map_message {
  my ($self, %args) = @_;
  return $self->map_input(%args);
}

sub derive {
  my ($self, %args) = @_;
  my $operation = $args{operation};
  my $input     = $args{input} || {};

  if (!(defined($operation) && !ref($operation) && length($operation))) {
    return {valid => 0, reason => 'derive operation is required',};
  }
  if (ref($input) ne 'HASH') {
    return {valid => 0, reason => 'derive input must be an object',};
  }

  my %method_for = (
    channel_presence                        => 'derive_channel_presence',
    authoritative_channel_view              => 'derive_authoritative_channel_view',
    authoritative_join_admission            => 'derive_authoritative_join_admission',
    authoritative_speak_permission          => 'derive_authoritative_speak_permission',
    authoritative_topic_permission          => 'derive_authoritative_topic_permission',
    authoritative_mode_write_permission     => 'derive_authoritative_mode_write_permission',
    authoritative_channel_action_permission => 'derive_authoritative_channel_action_permission',
    authoritative_ban_list_view             => 'derive_authoritative_ban_list_view',
    authoritative_list_entry_view           => 'derive_authoritative_list_entry_view',
    authoritative_channel_state             => 'derive_authoritative_channel_state',
  );
  my $method = $method_for{$operation};
  if (!defined $method) {
    return {valid => 0, reason => "Unsupported derive operation: $operation",};
  }

  return $self->$method(%{$input}, session_config => $args{session_config},);
}

1;

=head1 NAME

Overnet::Adapter::IRC - Overnet IRC adapter

=head1 SYNOPSIS

  use Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  my $result = $adapter->map_message(
    command    => 'PRIVMSG',
    network    => 'irc.libera.chat',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'Hello from IRC!',
    created_at => 1744300860,
  );

=head1 DESCRIPTION

This module is the starting point for an Overnet IRC adapter implementation.

Adapter behavior is defined by the Overnet core specification and the IRC adapter
specification.

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a new adapter instance.

=head2 supported_secret_slots

Returns the supported IRC secret slot names.

=head2 open_session

Opens an adapter session and records the provided secret slots.

=head2 close_session

Closes an adapter session.

=head2 map_message

Maps a supported IRC message input into an unsigned Overnet event draft.

The current implementation supports channel and direct-message C<PRIVMSG>,
channel and direct-message C<NOTICE>, channel C<TOPIC>, and channel-context
C<JOIN>, C<PART>, C<QUIT>, C<KICK>, network-scoped C<NICK>, and channel
C<MODE>.

=head2 map_input

Maps a supported IRC input into an unsigned Overnet event draft.

=head2 derive

Dispatches a derived adapter operation.

=head2 derive_channel_presence

Derives an adapted channel presence event from observed IRC membership events.

=head2 derive_authoritative_channel_state

Derives the authoritative channel state view.

=head2 derive_authoritative_ban_list_view

Derives the authoritative ban list view.

=head2 derive_authoritative_list_entry_view

Derives the authoritative channel list entry view.

=head2 derive_authoritative_join_admission

Derives authoritative join admission for a prospective actor.

=head2 derive_authoritative_speak_permission

Derives authoritative speak permission for an actor.

=head2 derive_authoritative_topic_permission

Derives authoritative topic-edit permission for an actor.

=head2 derive_authoritative_mode_write_permission

Derives authoritative mode-write permission for an actor.

=head2 derive_authoritative_channel_action_permission

Derives authoritative channel action permission for an actor.

=head2 derive_authoritative_channel_view

Derives an authoritative NIP-29 channel view.

=head1 DIAGNOSTICS

Methods return structured invalid results for rejected adapter inputs. Session
management methods croak for invalid API usage.

=head1 CONFIGURATION AND ENVIRONMENT

NIP-29 authoritative channel behavior is enabled through the supplied session
configuration.

=head1 DEPENDENCIES

This module depends on JSON, Net::Nostr, and Overnet authority helpers.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

Events produced by this adapter are unsigned drafts unless delegated authority
metadata is supplied.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
