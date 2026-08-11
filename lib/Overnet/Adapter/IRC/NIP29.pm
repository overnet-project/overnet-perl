package Overnet::Adapter::IRC::NIP29;

use strictures 2;
use Moo;
use Carp    qw(croak);
use English qw(-no_match_vars);
use JSON    ();
use Net::Nostr::Event;
use Net::Nostr::Group;
use Overnet::Adapter::IRC::Role::Validation;
use Overnet::Authority::HostedChannel ();

our $VERSION = '0.001';

with 'Overnet::Adapter::IRC::Role::Validation';

no Moo;

sub map_input {
  my ($self, %args) = @_;
  return $self->_map_nip29_authoritative_input(%args);
}

sub derive_authoritative_channel_state {
  my ($self, %args) = @_;

  my $view_result = $self->derive_authoritative_channel_view(%args);
  if (!$view_result->{valid}) {
    return $view_result;
  }

  my $view = $view_result->{view}[0];
  return {
    valid => 1,
    state => [
      {
        operation         => 'authoritative_channel_state',
        authority_profile => $view->{authority_profile},
        object_type       => $view->{object_type},
        object_id         => $view->{object_id},
        group_host        => $view->{group_host},
        group_id          => $view->{group_id},
        group_ref         => $view->{group_ref},
        channel_modes     => $view->{channel_modes},
        (ref($view->{ban_masks}) eq 'ARRAY' && @{$view->{ban_masks}} ? (ban_masks => [@{$view->{ban_masks}}]) : ()),
        (
          ref($view->{exception_masks}) eq 'ARRAY'
            && @{$view->{exception_masks}} ? (exception_masks => [@{$view->{exception_masks}}]) : ()
        ),
        (
          ref($view->{invite_exception_masks}) eq 'ARRAY' && @{$view->{invite_exception_masks}}
          ? (invite_exception_masks => [@{$view->{invite_exception_masks}}])
          : ()
        ),
        (defined($view->{channel_key})      ? (channel_key        => $view->{channel_key})        : ()),
        (defined($view->{user_limit})       ? (user_limit         => $view->{user_limit})         : ()),
        (exists $view->{topic}              ? (topic              => $view->{topic})              : ()),
        (exists $view->{topic_actor_pubkey} ? (topic_actor_pubkey => $view->{topic_actor_pubkey}) : ()),
        ($view->{tombstoned}                ? (tombstoned         => JSON::true)                  : ()),
        supported_roles => [@{$view->{supported_roles} || []}],
        members         => [
          map {
            +{
              pubkey                => $_->{pubkey},
              roles                 => [@{$_->{roles} || []}],
              presentational_prefix => $_->{presentational_prefix},
            }
          } @{$view->{members} || []}
        ],
        (
          ref($view->{retained_members}) eq 'ARRAY'
          ? (
            retained_members => [
              map {
                +{
                  pubkey                => $_->{pubkey},
                  roles                 => [@{$_->{roles} || []}],
                  presentational_prefix => $_->{presentational_prefix},
                }
              } @{$view->{retained_members}}
            ],
            )
          : ()
        ),
      },
    ],
  };
}

sub derive_authoritative_ban_list_view {
  my ($self, %args) = @_;

  my $view_result = $self->derive_authoritative_channel_view(%args);
  if (!$view_result->{valid}) {
    return $view_result;
  }

  my $view = $view_result->{view}[0];
  return {
    valid => 1,
    view  => [
      {
        operation         => 'authoritative_ban_list_view',
        authority_profile => $view->{authority_profile},
        object_type       => $view->{object_type},
        object_id         => $view->{object_id},
        group_host        => $view->{group_host},
        group_id          => $view->{group_id},
        group_ref         => $view->{group_ref},
        ban_masks         => [@{_normalized_ban_masks($view->{ban_masks})}],
      },
    ],
  };
}

sub derive_authoritative_list_entry_view {
  my ($self, %args) = @_;

  my $view_result = $self->derive_authoritative_channel_view(%args);
  if (!$view_result->{valid}) {
    return $view_result;
  }

  my $view    = $view_result->{view}[0];
  my $channel = $args{target};

  my %entry = (
    operation         => 'authoritative_list_entry_view',
    authority_profile => $view->{authority_profile},
    object_type       => $view->{object_type},
    object_id         => $view->{object_id},
    group_host        => $view->{group_host},
    group_id          => $view->{group_id},
    group_ref         => $view->{group_ref},
    channel           => $channel,
  );

  my $actor_pubkey = $args{actor_pubkey};
  my $actor_member =
    defined($actor_pubkey)
    ? (_member_for_pubkey($view->{members}, $actor_pubkey)
      || _member_for_pubkey($view->{retained_members}, $actor_pubkey))
    : undef;
  my $private    = $view->{private}    ? 1 : 0;
  my $hidden     = $view->{hidden}     ? 1 : 0;
  my $restricted = $view->{restricted} ? 1 : 0;

  if ($view->{tombstoned}) {
    $entry{visible_in_list} = JSON::false;
    $entry{reason}          = 'deleted';
  } elsif ($hidden && !defined($actor_member)) {
    $entry{visible_in_list} = JSON::false;
    $entry{reason}          = 'hidden';
  } else {
    $entry{visible_in_list} = JSON::true;
    if ($private) {
      $entry{private} = JSON::true;
    }
    if ($hidden) {
      $entry{hidden} = JSON::true;
    }
    if ($restricted) {
      $entry{restricted} = JSON::true;
    }
    $entry{channel_modes} = $view->{channel_modes};
    if ($private && !defined($actor_member)) {
      $entry{visible_users} = 0;
      $entry{topic}         = q{};
    } else {
      $entry{visible_users} = scalar @{$view->{present_members} || []};
      $entry{topic}         = defined($view->{topic}) ? $view->{topic} : q{};
    }
  }

  return {
    valid => 1,
    view  => [\%entry],
  };
}

sub derive_authoritative_join_admission {
  my ($self, %args) = @_;

  my ($context, $context_error) = _authoritative_channel_context(
    \%args,
    {
      operation       => 'authoritative_join_admission',
      events_required => 'array',
    },
  );
  if (defined $context_error) {
    return _error($context_error);
  }

  my %admission = _new_join_admission($context);
  if (!@{$context->{authoritative_events}}) {
    _apply_empty_authoritative_admission(\%admission, $args{actor_pubkey});
    return _admission_result(\%admission);
  }

  my $view_result = $self->derive_authoritative_channel_view(%args);
  if (!$view_result->{valid}) {
    return $view_result;
  }
  my $view = $view_result->{view}[0];
  _apply_view_authoritative_admission(\%admission, $view, \%args);

  return _admission_result(\%admission);
}

sub _authoritative_channel_context {
  my ($args, $options) = @_;
  my $operation      = $options->{operation};
  my $session_config = _session_config_from_args($args->{session_config});

  if (($session_config->{authority_profile} || q{}) ne 'nip29') {
    return (undef, "$operation requires session_config.authority_profile = nip29");
  }
  if (!_non_empty_scalar($args->{network})) {
    return (undef, 'IRC network is required');
  }
  if (!_non_empty_scalar($args->{target})) {
    return (undef, 'IRC target is required');
  }
  if (!_is_channel_target($args->{target})) {
    return (undef, "$operation target must be a channel");
  }

  my ($group_host, $group_id, $binding_error) = _resolve_nip29_group_binding(
    network        => $args->{network},
    session_config => $session_config,
    target         => $args->{target},
  );
  if (defined $binding_error) {
    return (undef, $binding_error);
  }

  my $events = $args->{authoritative_events};
  if (ref($events) ne 'ARRAY') {
    return (undef, _authoritative_events_error($options->{events_required}));
  }
  if ($options->{events_required} eq 'non_empty_array' && !@{$events}) {
    return (undef, _authoritative_events_error($options->{events_required}));
  }

  my $actor_error = _optional_authoritative_actor_error($args);
  if (defined $actor_error) {
    return (undef, $actor_error);
  }

  my $group_ref = _nip29_group_ref(
    group_id             => $group_id,
    session_config       => $session_config,
    authoritative_events => $events,
    actor_pubkey         => $args->{actor_pubkey},
  );

  return (
    {
      session_config       => $session_config,
      network              => $args->{network},
      target               => $args->{target},
      group_host           => $group_host,
      group_id             => $group_id,
      group_ref            => $group_ref,
      authoritative_events => $events,
    },
    undef,
  );
}

sub _authoritative_events_error {
  my ($events_required) = @_;

  if ($events_required eq 'non_empty_array') {
    return 'authoritative_events must be a non-empty array';
  }

  return 'authoritative_events must be an array';
}

sub _nip29_group_ref {
  my (%args) = @_;
  my $pubkey = _nip29_group_ref_pubkey(%args);
  if (!defined $pubkey) {
    return;
  }

  return Net::Nostr::Group->format_id(
    pubkey   => $pubkey,
    group_id => $args{group_id},
  );
}

sub _nip29_group_ref_pubkey {
  my (%args) = @_;
  my $session_config = $args{session_config} || {};

  if (_valid_hex_pubkey($session_config->{group_pubkey})) {
    return $session_config->{group_pubkey};
  }

  if (ref($args{authoritative_events}) eq 'ARRAY') {
    for my $event (@{$args{authoritative_events}}) {
      if (my $pubkey = _nip29_group_ref_pubkey_from_event($event, $args{group_id})) {
        return $pubkey;
      }
    }
  }

  if (_valid_hex_pubkey($args{actor_pubkey})) {
    return $args{actor_pubkey};
  }

  return;
}

sub _nip29_group_ref_pubkey_from_event {
  my ($event, $group_id) = @_;
  if (!(ref($event) eq 'HASH')) {
    return;
  }
  if (
    !(
      defined($event->{kind}) && ($event->{kind} == 39_000
        || $event->{kind} == 39_001
        || $event->{kind} == 39_002
        || $event->{kind} == 39_003
        || $event->{kind} == 9_002)
    )
  ) {
    return;
  }
  if (!(_valid_hex_pubkey($event->{pubkey}))) {
    return;
  }
  my $event_group_id = _event_hash_group_id($event);
  if (!(defined($event_group_id) && defined($group_id) && $event_group_id eq $group_id)) {
    return;
  }

  return $event->{pubkey};
}

sub _event_hash_group_id {
  my ($event) = @_;
  my $d_tag;
  for my $tag (@{$event->{tags} || []}) {
    if (ref($tag) ne 'ARRAY' || @{$tag} < 2) {
      next;
    }
    if (($tag->[0] || q{}) eq 'h') {
      return $tag->[1];
    }
    if (($tag->[0] || q{}) eq 'd') {
      $d_tag //= $tag->[1];
    }
  }
  return $d_tag;
}

sub _optional_authoritative_actor_error {
  my ($args) = @_;

  if (defined($args->{actor_pubkey}) && !_valid_hex_pubkey($args->{actor_pubkey})) {
    return 'actor_pubkey must be a 64-character hex pubkey when supplied';
  }
  if (defined($args->{actor_mask}) && !_non_empty_scalar($args->{actor_mask})) {
    return 'actor_mask must be a non-empty string when supplied';
  }
  if (defined($args->{join_key}) && !_non_empty_scalar($args->{join_key})) {
    return 'join_key must be a non-empty string when supplied';
  }

  return;
}

sub _new_join_admission {
  my ($context) = @_;

  return (
    operation         => 'authoritative_join_admission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => "irc:$context->{network}:$context->{target}",
    group_host        => $context->{group_host},
    group_id          => $context->{group_id},
    group_ref         => $context->{group_ref},
    allowed           => JSON::false,
    member            => JSON::false,
    present           => JSON::false,
    create_channel    => JSON::false,
    auth_required     => JSON::false,
    reason            => q{},
  );
}

sub _apply_empty_authoritative_admission {
  my ($admission, $actor_pubkey) = @_;
  my $has_actor = defined($actor_pubkey) ? 1 : 0;

  $admission->{allowed}        = $has_actor ? JSON::true  : JSON::false;
  $admission->{create_channel} = $has_actor ? JSON::true  : JSON::false;
  $admission->{auth_required}  = $has_actor ? JSON::false : JSON::true;
  $admission->{reason}         = $has_actor ? q{}         : 'auth_required';
  return;
}

sub _apply_view_authoritative_admission {
  my ($admission, $view, $args) = @_;

  if (defined($args->{actor_pubkey}) && ref($view->{admission}) eq 'HASH') {
    _copy_view_admission($admission, $view, $args->{actor_pubkey});
    return;
  }

  if ($view->{tombstoned}) {
    $admission->{deleted} = JSON::true;
    $admission->{reason}  = 'deleted';
    return;
  }

  if (_channel_has_mode($view->{channel_modes}, 'i')) {
    $admission->{allowed} = JSON::false;
    $admission->{reason}  = '+i';
    return;
  }

  $admission->{allowed} = JSON::true;
  $admission->{reason}  = q{};
  return;
}

sub _copy_view_admission {
  my ($admission, $view, $actor_pubkey) = @_;
  my $view_admission = $view->{admission};

  $admission->{allowed} = $view_admission->{allowed}                   ? JSON::true                : JSON::false;
  $admission->{member}  = $view_admission->{member}                    ? JSON::true                : JSON::false;
  $admission->{present} = _actor_present_in_view($view, $actor_pubkey) ? JSON::true                : JSON::false;
  $admission->{reason}  = defined($view_admission->{reason})           ? $view_admission->{reason} : q{};
  if (defined $view_admission->{invite_code}) {
    $admission->{invite_code} = $view_admission->{invite_code};
  }
  if ($view_admission->{deleted}) {
    $admission->{deleted} = JSON::true;
  }
  if ($view_admission->{request_join}) {
    $admission->{request_join} = JSON::true;
  }
  if ($view_admission->{pending_request}) {
    $admission->{pending_request} = JSON::true;
  }

  return;
}

sub _actor_present_in_view {
  my ($view, $actor_pubkey) = @_;

  for my $member (@{$view->{present_members} || []}) {
    next if ref($member) ne 'HASH';
    if (defined($member->{pubkey}) && $member->{pubkey} eq $actor_pubkey) {
      return 1;
    }
  }

  return 0;
}

sub _admission_result {
  my ($admission) = @_;

  return {
    valid     => 1,
    admission => [$admission],
  };
}

sub derive_authoritative_speak_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $actor_pubkey = $args{actor_pubkey};
  my $member       = _member_for_pubkey($view->{members}, $actor_pubkey);
  my @roles        = ref($member) eq 'HASH' ? @{$member->{roles} || []} : ();
  my %roles        = map { $_ => 1 } @roles;
  my $moderated    = _channel_has_mode($view->{channel_modes}, 'm');

  my %permission = (
    operation             => 'authoritative_speak_permission',
    authority_profile     => 'nip29',
    object_type           => 'chat.channel',
    object_id             => $view->{object_id},
    group_host            => $group_host,
    group_id              => $group_id,
    group_ref             => $view->{group_ref},
    allowed               => JSON::false,
    roles                 => [@roles],
    presentational_prefix => _presentational_prefix_for_roles(\@roles),
    reason                => q{},
  );

  if ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
  } elsif (!$moderated || $roles{'irc.operator'} || $roles{'irc.voice'}) {
    $permission{allowed} = JSON::true;
  } else {
    $permission{reason} = '+m';
  }

  return {
    valid      => 1,
    permission => [\%permission],
  };
}

sub derive_authoritative_topic_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $actor_pubkey     = $args{actor_pubkey};
  my $member           = _member_for_pubkey($view->{members}, $actor_pubkey);
  my @roles            = ref($member) eq 'HASH' ? @{$member->{roles} || []} : ();
  my %roles            = map { $_ => 1 } @roles;
  my $topic_restricted = _channel_has_mode($view->{channel_modes}, 't');

  my %permission = (
    operation         => 'authoritative_topic_permission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => $view->{object_id},
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => $view->{group_ref},
    allowed           => JSON::false,
    reason            => q{},
  );

  if ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
  } elsif (!$topic_restricted || $roles{'irc.operator'}) {
    $permission{allowed} = JSON::true;
  } else {
    $permission{reason} = '+t';
  }

  return {
    valid      => 1,
    permission => [\%permission],
  };
}

sub derive_authoritative_mode_write_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $mode = $args{mode};
  if (!_non_empty_scalar($mode)) {
    return _error('mode is required');
  }
  my $mode_args = $args{mode_args};
  if (ref($mode_args) ne 'ARRAY') {
    return _error('mode_args must be an array');
  }

  my $actor_pubkey = $args{actor_pubkey};
  my $member       = _member_for_pubkey($view->{members}, $actor_pubkey);
  my @roles        = ref($member) eq 'HASH' ? @{$member->{roles} || []} : ();
  my %roles        = map { $_ => 1 } @roles;

  my %permission = (
    operation         => 'authoritative_mode_write_permission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => $view->{object_id},
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => $view->{group_ref},
    allowed           => JSON::false,
    mode              => $mode,
    reason            => q{},
  );

  if ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
    return _permission_result(\%permission);
  }
  if (!$roles{'irc.operator'}) {
    $permission{reason} = 'not_operator';
    return _permission_result(\%permission);
  }

  my $mode_error = _apply_mode_write_permission(\%permission, $view, $mode, $mode_args);
  if (defined $mode_error) {
    return _error($mode_error);
  }

  return _permission_result(\%permission);
}

sub derive_authoritative_channel_action_permission {
  my ($self, %args) = @_;

  my ($group_host, $group_id, $view, $error) = _authoritative_permission_view($self, %args);
  return _error($error) if defined $error;

  my $action = $args{action};
  if (!_non_empty_scalar($action)) {
    return _error('action is required');
  }
  $action = lc $action;
  if (!_supported_authoritative_channel_action($action)) {
    return _error('unsupported authoritative channel action');
  }

  my $actor_pubkey    = $args{actor_pubkey};
  my $member          = _member_for_pubkey($view->{members},          $actor_pubkey);
  my $retained_member = _member_for_pubkey($view->{retained_members}, $actor_pubkey);
  my @roles           = ref($member) eq 'HASH'          ? @{$member->{roles}          || []} : ();
  my @retained_roles  = ref($retained_member) eq 'HASH' ? @{$retained_member->{roles} || []} : ();
  my %roles           = map { $_ => 1 } @roles;
  my %retained_roles  = map { $_ => 1 } @retained_roles;

  my %permission = (
    operation         => 'authoritative_channel_action_permission',
    authority_profile => 'nip29',
    object_type       => 'chat.channel',
    object_id         => $view->{object_id},
    group_host        => $group_host,
    group_id          => $group_id,
    group_ref         => $view->{group_ref},
    action            => $action,
    allowed           => JSON::false,
    reason            => q{},
  );

  if ($action eq 'undelete') {
    _apply_undelete_permission(\%permission, $view, \%retained_roles);
    return _permission_result(\%permission);
  }
  if ($view->{tombstoned}) {
    $permission{reason} = 'deleted';
    return _permission_result(\%permission);
  }
  if (!$roles{'irc.operator'}) {
    $permission{reason} = 'not_operator';
    return _permission_result(\%permission);
  }

  my $action_error = _apply_live_action_permission(\%permission, $view, \%args);
  if (defined $action_error) {
    return _error($action_error);
  }

  return _permission_result(\%permission);
}

sub _permission_result {
  my ($permission) = @_;

  return {
    valid      => 1,
    permission => [$permission],
  };
}

sub _apply_mode_write_permission {
  my ($permission, $view, $mode, $mode_args) = @_;

  my $role_error = _apply_role_mode_write_permission($permission, $view, $mode, $mode_args);
  if (defined $role_error || $permission->{allowed}) {
    return $role_error;
  }

  my $list_error = _apply_list_mode_write_permission($permission, $view, $mode, $mode_args);
  if (defined $list_error || $permission->{allowed}) {
    return $list_error;
  }

  my $state_error = _apply_state_mode_write_permission($permission, $view, $mode, $mode_args);
  if (defined $state_error || $permission->{allowed}) {
    return $state_error;
  }

  return 'unsupported authoritative channel mode write';
}

sub _apply_role_mode_write_permission {
  my ($permission, $view, $mode, $mode_args) = @_;

  if ($mode !~ /\A[+-][ov]\z/msx) {
    return;
  }
  if (!_valid_hex_pubkey($mode_args->[0])) {
    return 'mode_args[0] target pubkey is required for channel role mode writes';
  }

  my $target_pubkey = $mode_args->[0];
  my $target_member = _member_for_pubkey($view->{members}, $target_pubkey);
  $permission->{allowed}       = JSON::true;
  $permission->{target_pubkey} = $target_pubkey;
  $permission->{current_roles} = ref($target_member) eq 'HASH' ? [@{$target_member->{roles} || []}] : [];
  return;
}

sub _apply_list_mode_write_permission {
  my ($permission, $view, $mode, $mode_args) = @_;
  my %field_for = (
    b => ['normalized_ban_mask',       'mode_args[0] ban mask is required for channel ban mode writes'],
    e => ['normalized_exception_mask', 'mode_args[0] exception mask is required for channel exception mode writes'],
    I => [
      'normalized_invite_exception_mask',
      'mode_args[0] invite exception mask is required for channel invite exception mode writes'
    ],
  );

  if ($mode !~ /\A[+-][beI]\z/msx) {
    return;
  }

  my $mode_letter = substr $mode, 1, 1;
  my ($permission_field, $error_message) = @{$field_for{$mode_letter}};
  if (!_non_empty_scalar($mode_args->[0])) {
    return $error_message;
  }

  $permission->{allowed}           = JSON::true;
  $permission->{$permission_field} = $mode_args->[0];
  $permission->{group_metadata}    = _group_metadata_from_authoritative_view($view);
  return;
}

sub _apply_state_mode_write_permission {
  my ($permission, $view, $mode, $mode_args) = @_;

  if ($mode !~ /\A[+-][klimt]\z/msx) {
    return;
  }

  my $argument_error = _apply_state_mode_argument($permission, $mode, $mode_args);
  if (defined $argument_error) {
    return $argument_error;
  }

  $permission->{allowed}        = JSON::true;
  $permission->{group_metadata} = _group_metadata_from_authoritative_view($view);
  return;
}

sub _apply_state_mode_argument {
  my ($permission, $mode, $mode_args) = @_;

  if ($mode eq q{+k}) {
    if (!_non_empty_scalar($mode_args->[0])) {
      return 'mode_args[0] channel key is required for +k';
    }
    $permission->{channel_key} = $mode_args->[0];
    return;
  }
  if ($mode eq q{+l}) {
    if (!_positive_integer_string($mode_args->[0])) {
      return 'mode_args[0] user limit is required for +l';
    }
    $permission->{user_limit} = 0 + $mode_args->[0];
    return;
  }

  return;
}

sub _supported_authoritative_channel_action {
  my ($action) = @_;
  my %supported = map { $_ => 1 } qw(kick invite delete undelete);
  return $supported{$action} ? 1 : 0;
}

sub _apply_undelete_permission {
  my ($permission, $view, $retained_roles) = @_;

  if (!$view->{tombstoned}) {
    $permission->{reason} = 'not_deleted';
    return;
  }
  if (!$retained_roles->{'irc.operator'}) {
    $permission->{reason} = 'not_operator';
    return;
  }

  $permission->{allowed}        = JSON::true;
  $permission->{group_metadata} = _group_metadata_from_authoritative_view($view);
  return;
}

sub _apply_live_action_permission {
  my ($permission, $view, $args) = @_;
  my $action = $permission->{action};

  $permission->{allowed} = JSON::true;
  if ($action eq 'kick' || $action eq 'invite') {
    if (!_valid_hex_pubkey($args->{target_pubkey})) {
      return 'target_pubkey is required for authoritative channel action';
    }
    $permission->{target_pubkey} = $args->{target_pubkey};
  }
  if ($action eq 'delete') {
    $permission->{group_metadata} = _group_metadata_from_authoritative_view($view);
  }

  return;
}

sub derive_authoritative_channel_view {
  my ($self, %args) = @_;

  my ($context, $context_error) = _authoritative_channel_context(
    \%args,
    {
      operation       => 'authoritative_channel_view',
      events_required => 'non_empty_array',
    },
  );
  if (defined $context_error) {
    return _error($context_error);
  }

  my ($state, $state_error) = _authoritative_channel_state_from_events($context);
  if (defined $state_error) {
    return _error($state_error);
  }

  my %view = _authoritative_channel_view_from_state($context, $state, \%args);

  return {
    valid => 1,
    view  => [\%view],
  };
}

sub _authoritative_channel_state_from_events {
  my ($context) = @_;
  my $state = _new_authoritative_channel_state();
  my @sorted_events;

  my $sort_ok = eval {
    @sorted_events = _sorted_authoritative_group_events(@{$context->{authoritative_events}});
    1;
  };
  if (!$sort_ok) {
    my $sort_error = $EVAL_ERROR;
    chomp $sort_error;
    return (undef, $sort_error);
  }

  for my $event (@sorted_events) {
    my $event_error = _apply_authoritative_channel_event($state, $event, $context->{group_id});
    if (defined $event_error) {
      return (undef, $event_error);
    }
  }

  return ($state, undef);
}

sub _new_authoritative_channel_state {
  return {
    members               => {},
    present_members       => {},
    metadata              => _new_authoritative_metadata(),
    pending_invites       => {},
    pending_join_requests => {},
    supported_roles       => [],
  };
}

sub _new_authoritative_metadata {
  return {
    closed                 => 0,
    moderated              => 0,
    topic_restricted       => 0,
    private                => 0,
    restricted             => 0,
    hidden                 => 0,
    ban_masks              => [],
    exception_masks        => [],
    invite_exception_masks => [],
    channel_key            => undef,
    user_limit             => undef,
    topic                  => undef,
    topic_actor_pubkey     => undef,
    tombstoned             => 0,
  };
}

sub _apply_authoritative_channel_event {
  my ($state, $event, $group_id) = @_;
  my $event_group_id = Net::Nostr::Group->group_id_from_event($event);
  my %handler_for    = (
    39_000 => \&_apply_authoritative_metadata_event,
    39_001 => \&_apply_authoritative_admins_event,
    39_002 => \&_apply_authoritative_members_event,
    39_003 => \&_apply_authoritative_roles_event,
    9_000  => \&_apply_authoritative_put_user_event,
    9_001  => \&_apply_authoritative_remove_user_event,
    9_002  => \&_apply_authoritative_metadata_event,
    9_009  => \&_apply_authoritative_create_invite_event,
    9_021  => \&_apply_authoritative_join_request_event,
    9_022  => \&_apply_authoritative_leave_request_event,
  );

  if (defined($event_group_id) && $event_group_id ne $group_id) {
    return 'authoritative event group mismatch';
  }

  my $handler = $handler_for{$event->kind};
  if (!defined $handler) {
    return;
  }

  return $handler->($state, $event);
}

sub _apply_authoritative_metadata_event {
  my ($state, $event) = @_;
  my $metadata = $state->{metadata};
  %{$metadata} = (%{$metadata}, %{_metadata_from_group_event($event)},);

  if ($metadata->{tombstoned}) {
    %{$state->{present_members}}       = ();
    %{$state->{pending_invites}}       = ();
    %{$state->{pending_join_requests}} = ();
  }

  return;
}

sub _apply_authoritative_admins_event {
  my ($state, $event) = @_;
  my $admins = Net::Nostr::Group->admins_from_event($event);

  for my $admin (@{$admins->{admins} || []}) {
    my @roles = _sorted_roles(@{$admin->{roles} || []});
    $state->{members}{$admin->{pubkey}} = {
      pubkey => $admin->{pubkey},
      roles  => \@roles,
    };
  }

  return;
}

sub _apply_authoritative_members_event {
  my ($state, $event) = @_;
  my $member_info = Net::Nostr::Group->members_from_event($event);

  for my $pubkey (@{$member_info->{members} || []}) {
    if (!exists $state->{members}{$pubkey}) {
      $state->{members}{$pubkey} = {
        pubkey => $pubkey,
        roles  => [],
      };
    }
  }

  return;
}

sub _apply_authoritative_roles_event {
  my ($state, $event) = @_;
  my $role_info = Net::Nostr::Group->roles_from_event($event);
  my @supported_roles;

  for my $role (@{$role_info->{roles} || []}) {
    push @supported_roles, $role->{name};
  }
  $state->{supported_roles} = \@supported_roles;
  return;
}

sub _apply_authoritative_put_user_event {
  my ($state,         $event) = @_;
  my ($target_pubkey, @roles) = _target_and_roles_from_group_member_event($event);

  if (!defined $target_pubkey) {
    return 'put-user event must include one p tag target';
  }

  $state->{members}{$target_pubkey} = {
    pubkey => $target_pubkey,
    roles  => [_sorted_roles(@roles)],
  };
  delete $state->{pending_join_requests}{$target_pubkey};
  return;
}

sub _apply_authoritative_remove_user_event {
  my ($state, $event) = @_;
  my ($target_pubkey) = _target_and_roles_from_group_member_event($event);

  if (!defined $target_pubkey) {
    return 'remove-user event must include one p tag target';
  }

  delete $state->{members}{$target_pubkey};
  delete $state->{present_members}{$target_pubkey};
  delete $state->{pending_join_requests}{$target_pubkey};
  return;
}

sub _apply_authoritative_create_invite_event {
  my ($state,       $event)         = @_;
  my ($invite_code, $target_pubkey) = _invite_code_and_target_from_group_invite_event($event);

  if (!defined $invite_code) {
    return 'create-invite event must include one code tag';
  }

  $state->{pending_invites}{$invite_code} = {code => $invite_code,};
  if (defined $target_pubkey) {
    $state->{pending_invites}{$invite_code}{target_pubkey} = $target_pubkey;
    delete $state->{pending_join_requests}{$target_pubkey};
  }

  return;
}

sub _apply_authoritative_join_request_event {
  my ($state, $event) = @_;
  my $invite_code   = _invite_code_from_group_join_request_event($event);
  my $joiner_pubkey = _effective_actor_pubkey_from_group_event($event);
  my $joiner_mask   = _irc_mask_from_group_event($event);

  if (!_non_empty_scalar($joiner_pubkey)) {
    return;
  }
  if (_join_request_existing_member($state, $joiner_pubkey)) {
    return;
  }
  if (defined($invite_code) && exists $state->{pending_invites}{$invite_code}) {
    _join_request_with_invite($state, $joiner_pubkey, $invite_code);
    return;
  }
  if (!$state->{metadata}{closed}) {
    _mark_authoritative_member_present($state, $joiner_pubkey);
    return;
  }
  if ($state->{metadata}{restricted} && !defined($invite_code)) {
    _record_pending_join_request($state, $joiner_pubkey, $joiner_mask);
  }

  return;
}

sub _join_request_existing_member {
  my ($state, $joiner_pubkey) = @_;

  if (!exists $state->{members}{$joiner_pubkey}) {
    return 0;
  }

  _mark_authoritative_member_present($state, $joiner_pubkey);
  return 1;
}

sub _join_request_with_invite {
  my ($state, $joiner_pubkey, $invite_code) = @_;
  my $invite = $state->{pending_invites}{$invite_code};

  if (defined($invite->{target_pubkey}) && $invite->{target_pubkey} ne $joiner_pubkey) {
    return;
  }

  delete $state->{pending_invites}{$invite_code};
  _mark_authoritative_member_present($state, $joiner_pubkey);
  return;
}

sub _mark_authoritative_member_present {
  my ($state, $pubkey) = @_;

  if (!exists $state->{members}{$pubkey}) {
    $state->{members}{$pubkey} = {
      pubkey => $pubkey,
      roles  => [],
    };
  }
  delete $state->{pending_join_requests}{$pubkey};
  $state->{present_members}{$pubkey} = 1;
  return;
}

sub _record_pending_join_request {
  my ($state, $joiner_pubkey, $joiner_mask) = @_;

  $state->{pending_join_requests}{$joiner_pubkey} = {pubkey => $joiner_pubkey,};
  if (defined $joiner_mask) {
    $state->{pending_join_requests}{$joiner_pubkey}{actor_mask} = $joiner_mask;
  }
  return;
}

sub _apply_authoritative_leave_request_event {
  my ($state, $event) = @_;
  my $leaver_pubkey = _effective_actor_pubkey_from_group_event($event);

  if (!_non_empty_scalar($leaver_pubkey)) {
    return;
  }

  delete $state->{members}{$leaver_pubkey};
  delete $state->{present_members}{$leaver_pubkey};
  delete $state->{pending_join_requests}{$leaver_pubkey};
  return;
}

sub _authoritative_channel_view_from_state {
  my ($context, $state, $args) = @_;
  my $metadata              = $state->{metadata};
  my @derived_members       = _member_views($state->{members});
  my @retained_members      = @derived_members;
  my @present_members       = _member_views($state->{members}, $state->{present_members});
  my @pending_invites       = _copied_hash_values($state->{pending_invites});
  my @pending_join_requests = _copied_hash_values($state->{pending_join_requests});

  if ($metadata->{tombstoned}) {
    @derived_members       = ();
    @present_members       = ();
    @pending_invites       = ();
    @pending_join_requests = ();
  }

  my %view = (
    operation             => 'authoritative_channel_view',
    authority_profile     => 'nip29',
    object_type           => 'chat.channel',
    object_id             => "irc:$context->{network}:$context->{target}",
    group_host            => $context->{group_host},
    group_id              => $context->{group_id},
    group_ref             => $context->{group_ref},
    channel_modes         => _channel_modes_from_metadata($metadata),
    supported_roles       => [@{$state->{supported_roles}}],
    members               => \@derived_members,
    present_members       => \@present_members,
    pending_invites       => \@pending_invites,
    pending_join_requests => \@pending_join_requests,
  );

  _add_metadata_fields_to_view(\%view, $metadata);
  if ($metadata->{tombstoned}) {
    $view{retained_members} = \@retained_members;
    $view{tombstoned}       = JSON::true;
  }
  if (defined $args->{actor_pubkey}) {
    $view{admission} = _authoritative_view_admission(\%view, $state, $args, \@present_members);
  }

  return %view;
}

sub _member_views {
  my ($members, $present_members) = @_;
  my @views;

  for my $pubkey (sort keys %{$members}) {
    if (defined($present_members) && !$present_members->{$pubkey}) {
      next;
    }
    push @views, _member_view($members->{$pubkey});
  }

  return @views;
}

sub _member_view {
  my ($member) = @_;

  return {
    pubkey                => $member->{pubkey},
    roles                 => [@{$member->{roles} || []}],
    presentational_prefix => _presentational_prefix_for_roles($member->{roles}),
  };
}

sub _copied_hash_values {
  my ($values_by_key) = @_;
  my @values;

  for my $key (sort keys %{$values_by_key}) {
    my %value = %{$values_by_key->{$key}};
    push @values, \%value;
  }

  return @values;
}

sub _channel_modes_from_metadata {
  my ($metadata) = @_;
  my $modes = q{+};

  if ($metadata->{closed}) {
    $modes .= 'i';
  }
  if (defined($metadata->{channel_key}) && length($metadata->{channel_key})) {
    $modes .= 'k';
  }
  if (defined $metadata->{user_limit}) {
    $modes .= 'l';
  }
  if ($metadata->{moderated}) {
    $modes .= 'm';
  }
  $modes .= 'n';
  if ($metadata->{topic_restricted}) {
    $modes .= 't';
  }

  return $modes;
}

sub _add_metadata_fields_to_view {
  my ($view, $metadata) = @_;

  _add_non_empty_array_field($view, $metadata, 'ban_masks');
  _add_non_empty_array_field($view, $metadata, 'exception_masks');
  _add_non_empty_array_field($view, $metadata, 'invite_exception_masks');
  _add_defined_field($view, $metadata, 'channel_key');
  _add_defined_field($view, $metadata, 'user_limit');
  _add_defined_field($view, $metadata, 'topic');
  _add_defined_field($view, $metadata, 'topic_actor_pubkey');
  if ($metadata->{private}) {
    $view->{private} = JSON::true;
  }
  if ($metadata->{restricted}) {
    $view->{restricted} = JSON::true;
  }
  if ($metadata->{hidden}) {
    $view->{hidden} = JSON::true;
  }

  return;
}

sub _add_non_empty_array_field {
  my ($target, $source, $field) = @_;

  if (ref($source->{$field}) eq 'ARRAY' && @{$source->{$field}}) {
    $target->{$field} = [@{$source->{$field}}];
  }
  return;
}

sub _add_defined_field {
  my ($target, $source, $field) = @_;

  if (defined $source->{$field}) {
    $target->{$field} = $source->{$field};
  }
  return;
}

sub _authoritative_view_admission {
  my ($view, $state, $args, $present_members) = @_;
  my $checks    = _authoritative_admission_checks($state, $args, $present_members);
  my %admission = (
    allowed => _authoritative_admission_allowed($state->{metadata}, $checks),
    member  => _authoritative_admission_member($state->{metadata}, $checks),
    reason  => _authoritative_admission_reason($state->{metadata}, $checks),
  );

  _add_authoritative_admission_optional_fields(\%admission, $state->{metadata}, $checks);
  return \%admission;
}

sub _authoritative_admission_checks {
  my ($state, $args, $present_members) = @_;
  my $metadata        = $state->{metadata};
  my $actor_pubkey    = $args->{actor_pubkey};
  my $actor_mask      = $args->{actor_mask};
  my $member          = $state->{members}{$actor_pubkey};
  my $invite          = _pending_invite_for_pubkey($state->{pending_invites}, $actor_pubkey);
  my $excepted        = 0;
  my $invite_excepted = 0;
  my $banned          = 0;
  my $bad_key         = 0;
  my $channel_full    = 0;

  if (defined $actor_mask) {
    $excepted        = _actor_mask_matches_masks($metadata->{exception_masks},        $actor_mask);
    $invite_excepted = _actor_mask_matches_masks($metadata->{invite_exception_masks}, $actor_mask);
  }
  if (!$member && defined($actor_mask)) {
    $banned = _actor_mask_matches_masks($metadata->{ban_masks}, $actor_mask) && !$excepted ? 1 : 0;
  }
  if (!$member && defined($metadata->{channel_key})) {
    $bad_key = !defined($args->{join_key}) || $args->{join_key} ne $metadata->{channel_key} ? 1 : 0;
  }
  if (!$member && defined($metadata->{user_limit}) && @{$present_members} >= $metadata->{user_limit}) {
    $channel_full = 1;
  }

  return {
    member          => $member,
    invite          => $invite,
    invite_excepted => $invite_excepted,
    pending_request => $state->{pending_join_requests}{$actor_pubkey},
    banned          => $banned,
    bad_key         => $bad_key,
    channel_full    => $channel_full,
  };
}

sub _authoritative_admission_allowed {
  my ($metadata, $checks) = @_;

  if ($metadata->{tombstoned} || $checks->{banned} || $checks->{bad_key} || $checks->{channel_full}) {
    return JSON::false;
  }
  if ($checks->{member} || $checks->{invite} || $checks->{invite_excepted} || !$metadata->{closed}) {
    return JSON::true;
  }

  return JSON::false;
}

sub _authoritative_admission_member {
  my ($metadata, $checks) = @_;

  if ($metadata->{tombstoned}) {
    return JSON::false;
  }

  return $checks->{member} ? JSON::true : JSON::false;
}

sub _authoritative_admission_reason {
  my ($metadata, $checks) = @_;

  if ($metadata->{tombstoned}) {
    return 'deleted';
  }
  if ($checks->{banned}) {
    return '+b';
  }
  if ($checks->{bad_key}) {
    return '+k';
  }
  if ($checks->{channel_full}) {
    return '+l';
  }
  if ($checks->{member} || $checks->{invite} || $checks->{invite_excepted} || !$metadata->{closed}) {
    return q{};
  }
  if ($metadata->{restricted}) {
    return defined($checks->{pending_request}) ? 'join_request_pending' : 'join_request';
  }

  return '+i';
}

sub _add_authoritative_admission_optional_fields {
  my ($admission, $metadata, $checks) = @_;

  if ($metadata->{tombstoned}) {
    $admission->{deleted} = JSON::true;
    return;
  }
  if (_should_include_invite_code($checks)) {
    $admission->{invite_code} = $checks->{invite}{code};
  }
  if (_should_request_join($metadata, $checks)) {
    $admission->{request_join} = JSON::true;
  }
  if (defined $checks->{pending_request}) {
    $admission->{pending_request} = JSON::true;
  }

  return;
}

sub _should_include_invite_code {
  my ($checks) = @_;

  if (!$checks->{banned} && !$checks->{bad_key} && !$checks->{channel_full} && defined($checks->{invite})) {
    return 1;
  }

  return 0;
}

sub _should_request_join {
  my ($metadata, $checks) = @_;

  if ($checks->{banned} || $checks->{bad_key} || $checks->{channel_full}) {
    return 0;
  }
  if ($checks->{member} || $checks->{invite} || $checks->{invite_excepted}) {
    return 0;
  }
  if ($metadata->{closed} && $metadata->{restricted} && !defined($checks->{pending_request})) {
    return 1;
  }

  return 0;
}

sub _authoritative_permission_view {
  my ($self, %args) = @_;

  my $session_config = _session_config_from_args($args{session_config});
  if (($session_config->{authority_profile} || q{}) ne 'nip29') {
    return (undef, undef, undef,
      'authoritative permission derivation requires session_config.authority_profile = nip29');
  }

  my $network = $args{network};
  if (!_non_empty_scalar($network)) {
    return (undef, undef, undef, 'IRC network is required');
  }

  my $target = $args{target};
  if (!_non_empty_scalar($target)) {
    return (undef, undef, undef, 'IRC target is required');
  }
  if (!_is_channel_target($target)) {
    return (undef, undef, undef, 'authoritative permission target must be a channel');
  }

  my ($group_host, $group_id, $error) = _resolve_nip29_group_binding(
    network        => $network,
    session_config => $session_config,
    target         => $target,
  );
  if (defined $error) {
    return (undef, undef, undef, $error);
  }

  my $authoritative_events = $args{authoritative_events};
  if (ref($authoritative_events) ne 'ARRAY') {
    return (undef, undef, undef, 'authoritative_events must be an array');
  }
  if (!_valid_hex_pubkey($args{actor_pubkey})) {
    return (undef, undef, undef, 'actor_pubkey is required');
  }
  if (!@{$authoritative_events}) {
    return (undef, undef, undef, 'authoritative state unavailable');
  }

  my $view_result = $self->derive_authoritative_channel_view(%args);
  if (!$view_result->{valid}) {
    return (undef, undef, undef, $view_result->{reason});
  }
  my $view = $view_result->{view}[0];
  if (ref($view) ne 'HASH') {
    return (undef, undef, undef, 'authoritative channel view is required');
  }

  return ($group_host, $group_id, $view, undef);
}

sub _group_metadata_from_authoritative_view {
  my ($view) = @_;
  my %metadata = (
    closed           => _channel_has_mode($view->{channel_modes}, 'i'),
    moderated        => _channel_has_mode($view->{channel_modes}, 'm'),
    topic_restricted => _channel_has_mode($view->{channel_modes}, 't'),
    private          => $view->{private}                   ? 1                       : 0,
    restricted       => $view->{restricted}                ? 1                       : 0,
    hidden           => $view->{hidden}                    ? 1                       : 0,
    ban_masks        => ref($view->{ban_masks}) eq 'ARRAY' ? [@{$view->{ban_masks}}] : [],
    tombstoned       => $view->{tombstoned}                ? 1                       : 0,
  );

  _copy_optional_array_field(\%metadata, $view, 'exception_masks');
  _copy_optional_array_field(\%metadata, $view, 'invite_exception_masks');
  _copy_optional_defined_field(\%metadata, $view, 'channel_key');
  _copy_optional_defined_field(\%metadata, $view, 'user_limit');
  if (exists $view->{topic}) {
    $metadata{topic} = $view->{topic};
  }

  return \%metadata;
}

sub _copy_optional_array_field {
  my ($target, $source, $field) = @_;

  if (ref($source->{$field}) eq 'ARRAY' && @{$source->{$field}}) {
    $target->{$field} = [@{$source->{$field}}];
  }
  return;
}

sub _copy_optional_defined_field {
  my ($target, $source, $field) = @_;

  if (defined $source->{$field}) {
    $target->{$field} = $source->{$field};
  }
  return;
}

sub _member_for_pubkey {
  my ($members, $pubkey) = @_;
  if (ref($members) ne 'ARRAY') {
    return;
  }
  if (!_non_empty_scalar($pubkey)) {
    return;
  }

  for my $member (@{$members}) {
    if (ref($member) ne 'HASH') {
      next;
    }
    if (!defined($member->{pubkey}) || $member->{pubkey} ne $pubkey) {
      next;
    }
    return $member;
  }

  return;
}

sub _map_nip29_authoritative_input {
  my ($self,    %args)          = @_;
  my ($context, $context_error) = _nip29_authoritative_input_context(\%args);
  if (defined $context_error) {
    return _error($context_error);
  }

  my %mapper_for = (
    KICK     => \&_map_nip29_kick_input,
    INVITE   => \&_map_nip29_invite_input,
    JOIN     => \&_map_nip29_join_input,
    PART     => \&_map_nip29_part_input,
    TOPIC    => \&_map_nip29_topic_input,
    DELETE   => \&_map_nip29_delete_input,
    UNDELETE => \&_map_nip29_undelete_input,
    MODE     => \&_map_nip29_mode_input,
  );

  my $mapper = $mapper_for{$context->{command}};
  if (!defined $mapper) {
    return _error('Unsupported authoritative IRC command');
  }

  return $mapper->(\%args, $context);
}

sub _nip29_authoritative_input_context {
  my ($args) = @_;
  my $session_config = _session_config_from_args($args->{session_config});

  if (!_non_negative_integer($args->{created_at})) {
    return (undef, 'created_at must be a non-negative integer');
  }

  my ($group_host, $group_id, $binding_error) = _resolve_nip29_group_binding(
    network        => $args->{network},
    session_config => $session_config,
    target         => $args->{target},
  );
  if (defined $binding_error) {
    return (undef, $binding_error);
  }

  my $actor_pubkey = $args->{actor_pubkey};
  if (!_valid_hex_pubkey($actor_pubkey)) {
    return (undef, 'authoritative NIP-29 mapping requires actor_pubkey');
  }

  my $delegation_error = _delegated_authority_error($args);
  if (defined $delegation_error) {
    return (undef, $delegation_error);
  }

  my $event_pubkey = defined $args->{signing_pubkey} ? $args->{signing_pubkey} : $actor_pubkey;
  return (
    {
      command            => $args->{command} || q{},
      target             => $args->{target},
      created_at         => $args->{created_at},
      group_host         => $group_host,
      group_id           => $group_id,
      actor_pubkey       => $actor_pubkey,
      event_pubkey       => $event_pubkey,
      signing_pubkey     => $args->{signing_pubkey},
      authority_event_id => $args->{authority_event_id},
      authority_sequence => $args->{authority_sequence},
    },
    undef,
  );
}

sub _delegated_authority_error {
  my ($args) = @_;

  if ( !defined($args->{signing_pubkey})
    && !defined($args->{authority_event_id})
    && !defined($args->{authority_sequence})) {
    return;
  }
  if (!_valid_hex_pubkey($args->{signing_pubkey})) {
    return 'authoritative NIP-29 delegated signing requires signing_pubkey';
  }
  if (!_valid_hex_pubkey($args->{authority_event_id})) {
    return 'authoritative NIP-29 delegated signing requires authority_event_id';
  }
  if (!_positive_integer_string($args->{authority_sequence})) {
    return 'authoritative NIP-29 delegated signing requires authority_sequence';
  }

  return;
}

sub _map_nip29_kick_input {
  my ($args, $context) = @_;

  if (!_valid_hex_pubkey($args->{target_pubkey})) {
    return _error('authoritative NIP-29 KICK requires target_pubkey');
  }

  my $event = Net::Nostr::Group->remove_user(
    pubkey     => $context->{event_pubkey},
    group_id   => $context->{group_id},
    target     => $args->{target_pubkey},
    created_at => $context->{created_at} + 0,
    reason     => defined $args->{text} ? $args->{text} : q{},
  );
  return _nip29_event_result($event->to_hash, $context);
}

sub _map_nip29_invite_input {
  my ($args, $context) = @_;

  if (!_valid_hex_pubkey($args->{target_pubkey})) {
    return _error('authoritative NIP-29 INVITE requires target_pubkey');
  }
  if (!_non_empty_scalar($args->{invite_code})) {
    return _error('authoritative NIP-29 INVITE requires invite_code');
  }

  my $event = Net::Nostr::Group->create_invite(
    pubkey     => $context->{event_pubkey},
    group_id   => $context->{group_id},
    code       => $args->{invite_code},
    created_at => $context->{created_at} + 0,
    reason     => defined $args->{text} ? $args->{text} : q{},
  );
  my $event_hash = $event->to_hash;
  push @{$event_hash->{tags}}, ['p', $args->{target_pubkey}];
  return _nip29_event_result($event_hash, $context);
}

sub _map_nip29_join_input {
  my ($args, $context) = @_;
  my $invite_code = $args->{invite_code};

  if (defined($invite_code) && !_non_empty_scalar($invite_code)) {
    return _error('authoritative NIP-29 JOIN invite_code must be a non-empty string when supplied');
  }

  my @events = _initial_join_events($args, $context);
  my $event  = Net::Nostr::Group->join_request(
    pubkey     => $context->{event_pubkey},
    group_id   => $context->{group_id},
    created_at => $context->{created_at} + 0,
    (defined $invite_code ? (code => $invite_code) : ()),
    reason => defined $args->{text} ? $args->{text} : q{},
  );
  my $event_hash = $event->to_hash;
  if (defined $args->{actor_mask}) {
    push @{$event_hash->{tags}}, ['overnet_irc_mask', $args->{actor_mask}];
  }
  _apply_delegated_authority_tags_for_context($event_hash, $context);
  push @events, $event_hash;

  return {
    valid => 1,
    (@events == 1 ? (event => $events[0]) : (events => \@events)),
  };
}

sub _initial_join_events {
  my ($args, $context) = @_;
  my @events;

  if (!$args->{create_channel}) {
    return @events;
  }

  my $group_metadata = ref($args->{group_metadata}) eq 'HASH' ? $args->{group_metadata} : {};
  my %metadata       = %{$group_metadata};
  if (!_non_empty_scalar($metadata{name})) {
    $metadata{name} = $context->{target};
  }

  push @events,
    _build_group_metadata_event_hash(
    event_pubkey       => $context->{event_pubkey},
    group_id           => $context->{group_id},
    created_at         => $context->{created_at} + 0,
    metadata           => \%metadata,
    actor_pubkey       => $context->{actor_pubkey},
    signing_pubkey     => $context->{signing_pubkey},
    authority_event_id => $context->{authority_event_id},
    authority_sequence => $context->{authority_sequence},
    ),
    _build_group_put_user_event_hash(
    event_pubkey       => $context->{event_pubkey},
    group_id           => $context->{group_id},
    created_at         => $context->{created_at} + 0,
    target_pubkey      => $context->{actor_pubkey},
    roles              => ['irc.operator'],
    actor_pubkey       => $context->{actor_pubkey},
    signing_pubkey     => $context->{signing_pubkey},
    authority_event_id => $context->{authority_event_id},
    authority_sequence => $context->{authority_sequence},
    );

  return @events;
}

sub _map_nip29_part_input {
  my ($args, $context) = @_;

  my $event = Net::Nostr::Group->leave_request(
    pubkey     => $context->{event_pubkey},
    group_id   => $context->{group_id},
    created_at => $context->{created_at} + 0,
    reason     => defined $args->{text} ? $args->{text} : q{},
  );
  return _nip29_event_result($event->to_hash, $context);
}

sub _map_nip29_topic_input {
  my ($args, $context) = @_;

  if (!defined $args->{text}) {
    return _error('TOPIC text is required');
  }

  my ($metadata, $metadata_error) = _metadata_arg_hash($args);
  if (defined $metadata_error) {
    return _error($metadata_error);
  }
  $metadata->{topic} = $args->{text};

  return _metadata_edit_event_result($metadata, $context);
}

sub _map_nip29_delete_input {
  my ($args, $context) = @_;

  my ($metadata, $metadata_error) = _metadata_arg_hash($args);
  if (defined $metadata_error) {
    return _error($metadata_error);
  }
  $metadata->{tombstoned} = 1;

  return _metadata_edit_event_result($metadata, $context);
}

sub _map_nip29_undelete_input {
  my ($args, $context) = @_;

  my ($metadata, $metadata_error) = _metadata_arg_hash($args);
  if (defined $metadata_error) {
    return _error($metadata_error);
  }
  delete $metadata->{tombstoned};

  return _metadata_edit_event_result($metadata, $context);
}

sub _map_nip29_mode_input {
  my ($args, $context) = @_;
  my $mode = $args->{mode};

  if (!_non_empty_scalar($mode)) {
    return _error('MODE mode is required');
  }
  if ($mode =~ /\A[+-][ov]\z/msx) {
    return _map_nip29_role_mode_input($args, $context, $mode);
  }
  if ($mode =~ /\A[+-][beIklimt]\z/msx) {
    return _map_nip29_metadata_mode_input($args, $context, $mode);
  }

  return _error("Unsupported authoritative NIP-29 MODE: $mode");
}

sub _map_nip29_role_mode_input {
  my ($args, $context, $mode) = @_;
  my $direction   = substr $mode, 0, 1;
  my $mode_letter = substr $mode, 1, 1;

  if (!_valid_hex_pubkey($args->{target_pubkey})) {
    return _error("authoritative NIP-29 MODE $mode requires target_pubkey");
  }
  if (ref($args->{current_roles}) ne 'ARRAY') {
    return _error("authoritative NIP-29 MODE $mode requires current_roles");
  }
  if (!_valid_non_empty_scalar_array($args->{current_roles})) {
    return _error('current_roles must be an array of non-empty strings');
  }

  my $role_name = $mode_letter eq 'o' ? 'irc.operator' : 'irc.voice';
  my %roles     = map { $_ => 1 } @{$args->{current_roles}};
  if ($direction eq q{+}) {
    $roles{$role_name} = 1;
  } else {
    delete $roles{$role_name};
  }

  my $event = Net::Nostr::Group->put_user(
    pubkey     => $context->{event_pubkey},
    group_id   => $context->{group_id},
    target     => $args->{target_pubkey},
    created_at => $context->{created_at} + 0,
    roles      => [_sorted_roles(keys %roles)],
  );
  return _nip29_event_result($event->to_hash, $context);
}

sub _map_nip29_metadata_mode_input {
  my ($args, $context, $mode) = @_;
  my $direction   = substr $mode, 0, 1;
  my $mode_letter = substr $mode, 1, 1;
  my ($metadata, $metadata_error) = _metadata_arg_hash($args);

  if (defined $metadata_error) {
    return _error($metadata_error);
  }

  my $mode_error = _apply_nip29_metadata_mode($metadata, $args, $mode, $direction, $mode_letter);
  if (defined $mode_error) {
    return _error($mode_error);
  }

  return _metadata_edit_event_result($metadata, $context);
}

sub _apply_nip29_metadata_mode {
  my ($metadata, $args, $mode, $direction, $mode_letter) = @_;
  my %applier_for = (
    b => \&_apply_nip29_ban_mode,
    e => \&_apply_nip29_exception_mode,
    I => \&_apply_nip29_invite_exception_mode,
    k => \&_apply_nip29_key_mode,
    l => \&_apply_nip29_limit_mode,
    i => \&_apply_nip29_closed_mode,
    m => \&_apply_nip29_moderated_mode,
    t => \&_apply_nip29_topic_restricted_mode,
  );
  my $applier = $applier_for{$mode_letter};

  return $applier->($metadata, $args, $mode, $direction);
}

sub _apply_nip29_ban_mode {
  my ($metadata, $args, $mode, $direction) = @_;

  if (!_non_empty_scalar($args->{ban_mask})) {
    return "authoritative NIP-29 MODE $mode requires ban_mask";
  }

  _set_mask_value($metadata, 'ban_masks', $args->{ban_mask}, $direction, \&_normalized_ban_masks);
  return;
}

sub _apply_nip29_exception_mode {
  my ($metadata, $args, $mode, $direction) = @_;

  if (!_non_empty_scalar($args->{exception_mask})) {
    return "authoritative NIP-29 MODE $mode requires exception_mask";
  }

  _set_mask_value($metadata, 'exception_masks', $args->{exception_mask}, $direction, \&_normalized_mask_list);
  return;
}

sub _apply_nip29_invite_exception_mode {
  my ($metadata, $args, $mode, $direction) = @_;

  if (!_non_empty_scalar($args->{invite_exception_mask})) {
    return "authoritative NIP-29 MODE $mode requires invite_exception_mask";
  }

  _set_mask_value($metadata, 'invite_exception_masks', $args->{invite_exception_mask},
    $direction, \&_normalized_mask_list,);
  return;
}

sub _apply_nip29_key_mode {
  my ($metadata, $args, $mode, $direction) = @_;

  if ($direction eq q{+}) {
    if (!_non_empty_scalar($args->{channel_key})) {
      return "authoritative NIP-29 MODE $mode requires channel_key";
    }
    $metadata->{channel_key} = $args->{channel_key};
    return;
  }

  delete $metadata->{channel_key};
  return;
}

sub _apply_nip29_limit_mode {
  my ($metadata, $args, $mode, $direction) = @_;

  if ($direction eq q{+}) {
    if (!_positive_integer_string($args->{user_limit})) {
      return "authoritative NIP-29 MODE $mode requires user_limit";
    }
    $metadata->{user_limit} = 0 + $args->{user_limit};
    return;
  }

  delete $metadata->{user_limit};
  return;
}

sub _apply_nip29_closed_mode {
  my ($metadata, $args, $mode, $direction) = @_;
  $metadata->{closed} = $direction eq q{+} ? 1 : 0;
  return;
}

sub _apply_nip29_moderated_mode {
  my ($metadata, $args, $mode, $direction) = @_;
  $metadata->{moderated} = $direction eq q{+} ? 1 : 0;
  return;
}

sub _apply_nip29_topic_restricted_mode {
  my ($metadata, $args, $mode, $direction) = @_;
  $metadata->{topic_restricted} = $direction eq q{+} ? 1 : 0;
  return;
}

sub _set_mask_value {
  my ($metadata, $field, $mask, $direction, $normalizer) = @_;
  my %masks = map { $_ => 1 } @{$normalizer->($metadata->{$field})};

  if ($direction eq q{+}) {
    $masks{$mask} = 1;
  } else {
    delete $masks{$mask};
  }

  $metadata->{$field} = [sort keys %masks];
  return;
}

sub _metadata_arg_hash {
  my ($args) = @_;
  my $group_metadata = $args->{group_metadata} || {};

  if (ref($group_metadata) ne 'HASH') {
    return (undef, 'group_metadata must be an object');
  }

  my %metadata = %{$group_metadata};
  return (\%metadata, undef);
}

sub _metadata_edit_event_result {
  my ($metadata, $context) = @_;

  return {
    valid => 1,
    event => _build_group_metadata_edit_event_hash(
      event_pubkey       => $context->{event_pubkey},
      group_id           => $context->{group_id},
      created_at         => $context->{created_at} + 0,
      metadata           => $metadata,
      actor_pubkey       => $context->{actor_pubkey},
      signing_pubkey     => $context->{signing_pubkey},
      authority_event_id => $context->{authority_event_id},
      authority_sequence => $context->{authority_sequence},
    ),
  };
}

sub _nip29_event_result {
  my ($event_hash, $context) = @_;
  _apply_delegated_authority_tags_for_context($event_hash, $context);

  return {
    valid => 1,
    event => $event_hash,
  };
}

sub _apply_delegated_authority_tags_for_context {
  my ($event_hash, $context) = @_;

  _apply_delegated_authority_tags(
    event_hash         => $event_hash,
    actor_pubkey       => $context->{actor_pubkey},
    signing_pubkey     => $context->{signing_pubkey},
    authority_event_id => $context->{authority_event_id},
    authority_sequence => $context->{authority_sequence},
  );
  return;
}

sub _resolve_nip29_group_binding {
  my (%args) = @_;
  return Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => $args{network},
    session_config => $args{session_config},
    target         => $args{target},
  );
}

sub _build_group_metadata_event_hash {
  my (%args) = @_;
  my $metadata = $args{metadata} || {};

  my $event = Net::Nostr::Group->metadata(
    pubkey     => $args{event_pubkey},
    group_id   => $args{group_id},
    created_at => $args{created_at} + 0,
    (defined $metadata->{name}    ? (name       => $metadata->{name})    : ()),
    (defined $metadata->{picture} ? (picture    => $metadata->{picture}) : ()),
    (defined $metadata->{about}   ? (about      => $metadata->{about})   : ()),
    ($metadata->{private}         ? (private    => 1)                    : ()),
    ($metadata->{closed}          ? (closed     => 1)                    : ()),
    ($metadata->{restricted}      ? (restricted => 1)                    : ()),
    ($metadata->{hidden}          ? (hidden     => 1)                    : ()),
  );

  my $event_hash = $event->to_hash;
  _append_group_metadata_tags($event_hash, $metadata, 1);

  _apply_delegated_authority_tags(
    event_hash         => $event_hash,
    actor_pubkey       => $args{actor_pubkey},
    signing_pubkey     => $args{signing_pubkey},
    authority_event_id => $args{authority_event_id},
    authority_sequence => $args{authority_sequence},
  );

  return $event_hash;
}

sub _append_group_metadata_tags {
  my ($event_hash, $metadata, $include_undefined_topic) = @_;

  if ($metadata->{moderated}) {
    push @{$event_hash->{tags}}, ['mode', 'moderated'];
  }
  if ($metadata->{topic_restricted}) {
    push @{$event_hash->{tags}}, ['mode', 'topic-restricted'];
  }
  for my $ban_mask (@{_normalized_ban_masks($metadata->{ban_masks})}) {
    push @{$event_hash->{tags}}, ['ban', $ban_mask];
  }
  for my $exception_mask (@{_normalized_mask_list($metadata->{exception_masks})}) {
    push @{$event_hash->{tags}}, ['except', $exception_mask];
  }
  for my $invite_exception_mask (@{_normalized_mask_list($metadata->{invite_exception_masks})}) {
    push @{$event_hash->{tags}}, ['invite-except', $invite_exception_mask];
  }
  if (defined($metadata->{channel_key}) && length($metadata->{channel_key})) {
    push @{$event_hash->{tags}}, ['key', $metadata->{channel_key}];
  }
  if (defined $metadata->{user_limit}) {
    push @{$event_hash->{tags}}, ['limit', 0 + $metadata->{user_limit}];
  }
  if (exists($metadata->{topic}) && ($include_undefined_topic || defined($metadata->{topic}))) {
    push @{$event_hash->{tags}}, ['topic', $metadata->{topic}];
  }
  if ($metadata->{tombstoned}) {
    push @{$event_hash->{tags}}, ['status', 'tombstoned'];
  }

  return;
}

sub _build_group_put_user_event_hash {
  my (%args) = @_;

  my $event = Net::Nostr::Group->put_user(
    pubkey     => $args{event_pubkey},
    group_id   => $args{group_id},
    target     => $args{target_pubkey},
    created_at => $args{created_at} + 0,
    roles      => [_sorted_roles(@{$args{roles} || []})],
  );
  my $event_hash = $event->to_hash;
  _apply_delegated_authority_tags(
    event_hash         => $event_hash,
    actor_pubkey       => $args{actor_pubkey},
    signing_pubkey     => $args{signing_pubkey},
    authority_event_id => $args{authority_event_id},
    authority_sequence => $args{authority_sequence},
  );

  return $event_hash;
}

sub _metadata_from_group_event {
  my ($event)  = @_;
  my $metadata = _new_group_event_metadata();
  my $parsed   = _parsed_group_metadata($event);

  _apply_parsed_group_metadata($metadata, $parsed);
  for my $tag (@{$event->tags || []}) {
    _apply_group_metadata_tag($metadata, $event, $tag);
  }

  $metadata->{ban_masks}              = _normalized_ban_masks($metadata->{ban_masks});
  $metadata->{exception_masks}        = _normalized_mask_list($metadata->{exception_masks});
  $metadata->{invite_exception_masks} = _normalized_mask_list($metadata->{invite_exception_masks});
  return $metadata;
}

sub _new_group_event_metadata {
  return {
    closed                 => 0,
    moderated              => 0,
    topic_restricted       => 0,
    ban_masks              => [],
    exception_masks        => [],
    invite_exception_masks => [],
    channel_key            => undef,
    user_limit             => undef,
    topic                  => undef,
    topic_actor_pubkey     => undef,
    tombstoned             => 0,
  };
}

sub _parsed_group_metadata {
  my ($event) = @_;
  my $parsed = {};

  if ($event->kind != 39_000) {
    return $parsed;
  }

  my $parse_ok = eval {
    $parsed = Net::Nostr::Group->metadata_from_event($event);
    1;
  };
  if (!$parse_ok || ref($parsed) ne 'HASH') {
    $parsed = {};
  }

  return $parsed;
}

sub _apply_parsed_group_metadata {
  my ($metadata, $parsed) = @_;

  for my $field (qw(name picture about)) {
    if (defined $parsed->{$field}) {
      $metadata->{$field} = $parsed->{$field};
    }
  }
  for my $field (qw(private restricted hidden closed)) {
    if (exists $parsed->{$field}) {
      $metadata->{$field} = $parsed->{$field} ? 1 : 0;
    }
  }

  return;
}

sub _apply_group_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (ref($tag) ne 'ARRAY' || !@{$tag}) {
    return;
  }

  my %handler_for = (
    closed          => \&_apply_closed_metadata_tag,
    topic           => \&_apply_topic_metadata_tag,
    ban             => \&_apply_ban_metadata_tag,
    except          => \&_apply_except_metadata_tag,
    'invite-except' => \&_apply_invite_except_metadata_tag,
    key             => \&_apply_key_metadata_tag,
    limit           => \&_apply_limit_metadata_tag,
    status          => \&_apply_status_metadata_tag,
    mode            => \&_apply_mode_metadata_tag,
  );
  my $handler = $handler_for{$tag->[0]};
  if (!defined $handler) {
    return;
  }

  $handler->($metadata, $event, $tag);
  return;
}

sub _apply_closed_metadata_tag {
  my ($metadata, $event, $tag) = @_;
  $metadata->{closed} = 1;
  return;
}

sub _apply_topic_metadata_tag {
  my ($metadata, $event, $tag) = @_;
  $metadata->{topic}              = _tag_value_or_empty($tag);
  $metadata->{topic_actor_pubkey} = _effective_actor_pubkey_from_group_event($event);
  return;
}

sub _apply_ban_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (_tag_has_value($tag)) {
    push @{$metadata->{ban_masks}}, $tag->[1];
  }
  return;
}

sub _apply_except_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (_tag_has_value($tag)) {
    push @{$metadata->{exception_masks}}, $tag->[1];
  }
  return;
}

sub _apply_invite_except_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (_tag_has_value($tag)) {
    push @{$metadata->{invite_exception_masks}}, $tag->[1];
  }
  return;
}

sub _apply_key_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (_tag_has_value($tag)) {
    $metadata->{channel_key} = $tag->[1];
  }
  return;
}

sub _apply_limit_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (_tag_has_value($tag) && _positive_integer_string($tag->[1])) {
    $metadata->{user_limit} = 0 + $tag->[1];
  }
  return;
}

sub _apply_status_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (_tag_has_value($tag) && $tag->[1] eq 'tombstoned') {
    $metadata->{tombstoned} = 1;
  }
  return;
}

sub _apply_mode_metadata_tag {
  my ($metadata, $event, $tag) = @_;

  if (!_tag_has_value($tag)) {
    return;
  }
  if ($tag->[1] eq 'moderated') {
    $metadata->{moderated} = 1;
  }
  if ($tag->[1] eq 'topic-restricted') {
    $metadata->{topic_restricted} = 1;
  }
  return;
}

sub _tag_has_value {
  my ($tag) = @_;

  if (ref($tag) eq 'ARRAY' && @{$tag} >= 2) {
    return 1;
  }

  return 0;
}

sub _tag_value_or_empty {
  my ($tag) = @_;

  if (_tag_has_value($tag)) {
    return $tag->[1];
  }

  return q{};
}

sub _build_group_metadata_edit_event_hash {
  my (%args) = @_;
  my $metadata = $args{metadata} || {};

  my $event = Net::Nostr::Group->edit_metadata(
    pubkey     => $args{event_pubkey},
    group_id   => $args{group_id},
    created_at => $args{created_at} + 0,
    (defined $metadata->{name}    ? (name       => $metadata->{name})    : ()),
    (defined $metadata->{picture} ? (picture    => $metadata->{picture}) : ()),
    (defined $metadata->{about}   ? (about      => $metadata->{about})   : ()),
    ($metadata->{private}         ? (private    => 1)                    : ()),
    ($metadata->{closed}          ? (closed     => 1)                    : ()),
    ($metadata->{restricted}      ? (restricted => 1)                    : ()),
    ($metadata->{hidden}          ? (hidden     => 1)                    : ()),
  );

  my $event_hash = $event->to_hash;
  _append_group_metadata_tags($event_hash, $metadata, 0);
  _apply_delegated_authority_tags(
    event_hash         => $event_hash,
    actor_pubkey       => $args{actor_pubkey},
    signing_pubkey     => $args{signing_pubkey},
    authority_event_id => $args{authority_event_id},
    authority_sequence => $args{authority_sequence},
  );

  return $event_hash;
}

sub _target_and_roles_from_group_member_event {
  my ($event) = @_;

  for my $tag (@{$event->tags || []}) {
    if (!_tag_has_value($tag)) {
      next;
    }
    if ($tag->[0] ne 'p') {
      next;
    }
    my $last_index = scalar(@{$tag}) - 1;
    my @roles      = @{$tag}[2 .. $last_index];
    return ($tag->[1], @roles);
  }

  return;
}

sub _invite_code_and_target_from_group_invite_event {
  my ($event) = @_;
  my $invite_code;
  my $target_pubkey;

  for my $tag (@{$event->tags || []}) {
    if (!_tag_has_value($tag)) {
      next;
    }
    if (!defined($invite_code) && $tag->[0] eq 'code') {
      $invite_code = $tag->[1];
    }
    if (!defined($target_pubkey) && $tag->[0] eq 'p') {
      $target_pubkey = $tag->[1];
    }
  }

  return ($invite_code, $target_pubkey);
}

sub _invite_code_from_group_join_request_event {
  my ($event) = @_;

  for my $tag (@{$event->tags || []}) {
    if (!_tag_has_value($tag)) {
      next;
    }
    if ($tag->[0] eq 'code') {
      return $tag->[1];
    }
  }

  return;
}

sub _pending_invite_for_pubkey {
  my ($pending_invites, $pubkey) = @_;
  if (ref($pending_invites) ne 'HASH') {
    return;
  }
  if (!_non_empty_scalar($pubkey)) {
    return;
  }

  for my $code (sort keys %{$pending_invites}) {
    my $invite = $pending_invites->{$code};
    if (ref($invite) ne 'HASH') {
      next;
    }
    if (defined($invite->{target_pubkey}) && $invite->{target_pubkey} ne $pubkey) {
      next;
    }
    return $invite;
  }

  return;
}

sub _effective_actor_pubkey_from_group_event {
  my ($event) = @_;

  for my $tag (@{$event->tags || []}) {
    if (!_tag_has_value($tag)) {
      next;
    }
    if ($tag->[0] ne 'overnet_actor') {
      next;
    }
    if (_valid_hex_pubkey($tag->[1])) {
      return $tag->[1];
    }
  }

  return $event->pubkey;
}

sub _irc_mask_from_group_event {
  my ($event) = @_;

  for my $tag (@{$event->tags || []}) {
    if (!_tag_has_value($tag)) {
      next;
    }
    if ($tag->[0] ne 'overnet_irc_mask') {
      next;
    }
    if (_non_empty_scalar($tag->[1])) {
      return $tag->[1];
    }
  }

  return;
}

sub _sorted_authoritative_group_events {
  my @raw_events = @_;
  my @decorated;

  for my $raw_event (@raw_events) {
    if (ref($raw_event) ne 'HASH') {
      croak "authoritative events must be objects\n";
    }

    my $event = eval { Net::Nostr::Event->new(%{$raw_event}) };
    if (!$event) {
      croak "authoritative events must be valid Nostr events\n";
    }

    my ($authority, $sequence) = _authority_ordering_from_event($event);
    push @decorated,
      [
      $event->created_at + 0,
      _authoritative_semantic_phase_for_event($event),
      $authority, $sequence, lc($event->id || q{}), $event,
      ];
  }

  return map { $_->[5] } sort {
    $a->[0] <=> $b->[0]
      || (
         length($a->[2])
      && length($b->[2])
      && $a->[2] eq $b->[2] && $a->[3] > 0 && $b->[3] > 0
      ? ($a->[3] <=> $b->[3])
      : 0
      )
      || $a->[1] <=> $b->[1]
      || $a->[4] cmp $b->[4]
  } @decorated;
}

sub _authoritative_semantic_phase_for_event {
  my ($event) = @_;
  my $kind = $event->kind;

  if ($kind == 9_000 || $kind == 9_002 || $kind == 9_009) {
    return 0;
  }
  if ($kind == 9_021) {
    return 1;
  }
  if ($kind == 9_001 || $kind == 9_022) {
    return 2;
  }
  if ($kind == 39_000 || $kind == 39_001 || $kind == 39_002 || $kind == 39_003) {
    return 3;
  }
  return 4;
}

sub _authority_ordering_from_event {
  my ($event)   = @_;
  my $authority = q{};
  my $sequence  = 0;

  for my $tag (@{$event->tags || []}) {
    if (!_tag_has_value($tag)) {
      next;
    }
    if (($tag->[0] || q{}) eq 'overnet_authority' && !length($authority)) {
      $authority = defined($tag->[1]) && !ref($tag->[1]) ? $tag->[1] : q{};
      next;
    }
    if (($tag->[0] || q{}) eq 'overnet_sequence' && !$sequence) {
      $sequence =
        (defined($tag->[1]) && !ref($tag->[1]) && $tag->[1] =~ /\A\d+\z/msx)
        ? 0 + $tag->[1]
        : 0;
    }
  }

  return ($authority, $sequence);
}

sub _apply_delegated_authority_tags {
  my (%args)         = @_;
  my $event_hash     = $args{event_hash};
  my $signing_pubkey = $args{signing_pubkey};
  if (!defined $signing_pubkey) {
    return;
  }

  push @{$event_hash->{tags}},
    ['overnet_actor',     $args{actor_pubkey}],
    ['overnet_authority', $args{authority_event_id}],
    ['overnet_sequence',  0 + $args{authority_sequence}];
  return;
}

sub _sorted_roles {
  my @roles = @_;
  my %seen;
  my @unique_roles;
  for my $role (@roles) {
    if (!_non_empty_scalar($role)) {
      next;
    }
    if ($seen{$role}) {
      next;
    }
    $seen{$role} = 1;
    push @unique_roles, $role;
  }
  my @sorted_roles = sort { _role_sort_rank($a) <=> _role_sort_rank($b) || $a cmp $b } @unique_roles;
  return @sorted_roles;
}

sub _role_sort_rank {
  my ($role) = @_;

  if ($role eq 'irc.operator') {
    return 0;
  }
  if ($role eq 'irc.voice') {
    return 1;
  }

  return 2;
}

sub _presentational_prefix_for_roles {
  my ($roles) = @_;
  $roles ||= [];
  my %roles = map { $_ => 1 } @{$roles};
  if ($roles{'irc.operator'}) {
    return q{@};
  }
  if ($roles{'irc.voice'}) {
    return q{+};
  }
  return q{};
}

sub _normalized_mask_list {
  my ($masks) = @_;
  if (ref($masks) ne 'ARRAY') {
    return [];
  }

  my %seen;
  my @normalized_masks;
  for my $mask (@{$masks}) {
    if (!_non_empty_scalar($mask)) {
      next;
    }
    if ($seen{$mask}) {
      next;
    }
    $seen{$mask} = 1;
    push @normalized_masks, $mask;
  }

  return [sort @normalized_masks];
}

sub _normalized_ban_masks {
  my ($ban_masks) = @_;
  return _normalized_mask_list($ban_masks);
}

sub _actor_mask_matches_masks {
  my ($masks, $actor_mask) = @_;
  if (!_non_empty_scalar($actor_mask)) {
    return 0;
  }

  for my $mask (@{_normalized_mask_list($masks)}) {
    if (
      Overnet::Authority::HostedChannel::irc_mask_matches(
        mask  => $mask,
        value => $actor_mask,
      )
    ) {
      return 1;
    }
  }

  return 0;
}

1;

=head1 NAME

Overnet::Adapter::IRC::NIP29 - Authoritative IRC channel mapping and derivation

=head1 DESCRIPTION

This internal collaborator owns the NIP-29-specific conversion between IRC
channel operations and authoritative Nostr group events, views, admission, and
permissions.

=head1 SYNOPSIS

  my $nip29 = Overnet::Adapter::IRC::NIP29->new;
  my $result = $nip29->derive_authoritative_channel_view(%input);

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

=head2 map_input

Maps one validated authoritative IRC command to NIP-29 event drafts.

=head2 derive_authoritative_channel_state

Projects the IRC-facing authoritative channel state.

=head2 derive_authoritative_ban_list_view

Projects the authoritative ban list.

=head2 derive_authoritative_list_entry_view

Projects an authoritative IRC LIST entry.

=head2 derive_authoritative_join_admission

Derives join admission for a prospective actor.

=head2 derive_authoritative_speak_permission

Derives permission to send channel messages.

=head2 derive_authoritative_topic_permission

Derives permission to edit a channel topic.

=head2 derive_authoritative_mode_write_permission

Derives permission and context for a mode write.

=head2 derive_authoritative_channel_action_permission

Derives permission for an authoritative channel action.

=head2 derive_authoritative_channel_view

Reconstructs a normalized authoritative channel view from NIP-29 events.

=head1 DIAGNOSTICS

Invalid input is returned as a structured adapter error. Malformed raw Nostr
events are rejected during authoritative ordering and reconstruction.

=head1 CONFIGURATION AND ENVIRONMENT

Group bindings and authority behavior come from the adapter session
configuration supplied with each operation.

=head1 DEPENDENCIES

This module depends on Moo, Net::Nostr, and Overnet authority helpers.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

Mapped events remain unsigned unless delegated authority metadata is supplied.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
