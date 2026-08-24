package Overnet::Test::SpecConformance::IRCServerHarness;

use strictures 2;

use JSON                              ();
use Overnet::Authority::HostedChannel ();
use parent -norequire, 'Overnet::Program::IRC::Server';

our $VERSION = '0.001';

sub _supported_capabilities {
  my ($self) = @_;
  if ($self->{config}{use_server_capabilities}) {
    return $self->SUPER::_supported_capabilities();
  }
  return @{$self->{config}{supported_capabilities} || []};
}

sub _send_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id};
  if (ref($client) eq 'HASH') {
    $line = $self->_decorate_outbound_line_for_client($client, $line);
  }
  push @{$self->{_spec_lines}{$client_id}}, $line;
  return 1;
}

sub _send_message                  { return 1; }
sub _log                           { return 1; }
sub _health                        { return 1; }
sub _ensure_client_dm_subscription { return 1; }
sub _ensure_channel_subscription   { return 1; }
sub _close_channel_subscription    { return 1; }
sub _close_client_dm_subscription  { return 1; }

sub _refresh_authoritative_discovery_cache {
  my ($self, %args) = @_;
  if (!($self->_authority_relay_enabled)) {
    return 1;
  }
  return $self->SUPER::_refresh_authoritative_discovery_cache(%args);
}

sub _ensure_authoritative_channel_subscription {
  my ($self, $channel) = @_;
  if (!($self->_authority_relay_enabled)) {
    return 1;
  }
  return $self->SUPER::_ensure_authoritative_channel_subscription($channel);
}

sub _sign_candidate_event {
  my ($self, $candidate) = @_;
  return {
    %{$candidate},
    id     => ('0' x 64),
    pubkey => ('1' x 64),
    sig    => ('2' x 128),
  };
}

sub _request {
  my ($self, %args) = @_;
  my $method   = $args{method};
  my $params   = $args{params} || {};
  my %dispatch = (
    'adapters.map_input'               => sub { return $self->_request_map_input($params); },
    'adapters.derive'                  => sub { return $self->_request_derive($params); },
    'overnet.emit_event'               => sub { return $self->_request_emit_event($method, $params); },
    'overnet.emit_state'               => sub { return $self->_request_emit($method, $params); },
    'overnet.emit_private_message'     => sub { return $self->_request_emit($method, $params); },
    'overnet.emit_capabilities'        => sub { return $self->_request_emit($method, $params); },
    'subscriptions.open'               => sub { return {}; },
    'subscriptions.close'              => sub { return {}; },
    'nostr.open_subscription'          => sub { return $self->_request_open_nostr_subscription($params); },
    'nostr.close_subscription'         => sub { return $self->_request_close_nostr_subscription($params); },
    'nostr.read_subscription_snapshot' => sub { return $self->_request_nostr_subscription_snapshot($params); },
    'nostr.query_events'               => sub { return $self->_request_query_nostr_events($params); },
    'nostr.publish_event'              => sub { return $self->_request_publish_nostr_event($params); },
  );
  return $dispatch{$method} ? $dispatch{$method}->() : {};
}

sub _request_map_input {
  my ($self, $params) = @_;
  my $result =
    $self->{_spec_adapter}->map_input(%{$params->{input} || {}}, session_config => $self->{config}{adapter_config},);
  my $normalized = _normalize_adapter_result_for_harness($result);
  $self->{_spec_last_map_result} = $normalized;
  return $normalized;
}

sub _request_derive {
  my ($self, $params) = @_;
  return _normalize_adapter_result_for_harness(
    $self->{_spec_adapter}->derive(
      operation      => $params->{operation},
      session_config => $self->{config}{adapter_config},
      input          => $params->{input},
    )
  );
}

sub _request_emit_event {
  my ($self, $method, $params) = @_;
  $self->{_spec_last_emitted_event} = $params->{event};
  return $self->_request_emit($method, $params);
}

sub _request_emit {
  my ($self, $method, $params) = @_;
  push @{$self->{_spec_emits}}, {method => $method, params => $params};
  return                        {};
}

sub _request_open_nostr_subscription {
  my ($self, $params) = @_;
  $self->{_spec_nostr_subscriptions}{$params->{subscription_id}} =
    {filters => Overnet::Test::SpecConformance::plain_data_for_harness($params->{filters} || []),};
  return {
    subscription_id => $params->{subscription_id},
    events          => _spec_nostr_events_for_subscription($self, $params->{subscription_id},),
  };
}

sub _request_close_nostr_subscription {
  my ($self, $params) = @_;
  delete $self->{_spec_nostr_subscriptions}{$params->{subscription_id}};
  return {closed => JSON::true};
}

sub _request_nostr_subscription_snapshot {
  my ($self, $params) = @_;
  return {events => _spec_nostr_events_for_subscription($self, $params->{subscription_id})};
}

sub _request_query_nostr_events {
  my ($self, $params) = @_;
  return {events => _spec_nostr_events_for_filters($self, $params->{filters})};
}

sub _request_publish_nostr_event {
  my ($self, $params) = @_;
  my $event = $params->{event};
  _store_published_event($self, $event);
  my $event_id = ref($event) eq 'HASH' ? $event->{id} : undef;
  return {
    accepted => JSON::true,
    (defined($event_id) ? (event_id => $event_id) : ()),
  };
}

sub _store_published_event {
  my ($self, $event) = @_;
  if (!(ref($event) eq 'HASH')) {
    return;
  }
  my $channel = Overnet::Authority::HostedChannel::channel_name_from_group_event(
    network => $self->{config}{network},
    event   => $event,
  );
  if (!(defined $channel)) {
    return;
  }
  my $canonical = $self->_canonical_channel_name($channel);
  $self->{_spec_authoritative_channels}{$canonical} ||= {};
  my $events = $self->{_spec_authoritative_channels}{$canonical}{events} ||= [];
  if (!_event_id_seen($event, $events)) {
    push @{$events}, $event;
  }
  return;
}

sub _event_id_seen {
  my ($event, $events) = @_;
  if (!(defined $event->{id})) {
    return 0;
  }
  for my $stored (@{$events}) {
    if (ref($stored) eq 'HASH' && defined($stored->{id}) && $stored->{id} eq $event->{id}) {
      return 1;
    }
  }
  return 0;
}

sub _normalize_adapter_result_for_harness {
  my ($result) = @_;
  if (!(ref($result) eq 'HASH')) {
    return {};
  }
  if ( exists $result->{events}
    || exists $result->{state}
    || exists $result->{view}
    || exists $result->{admission}
    || exists $result->{permission}
    || exists $result->{capabilities}) {
    return $result;
  }

  my %normalized;
  if (exists $result->{event}) {
    if (($result->{event}{kind} || 0) == 37_800) {
      $normalized{state} = [$result->{event}];
    } else {
      $normalized{events} = [$result->{event}];
    }
  }
  return {%{$result}, %normalized,};
}

sub _read_authoritative_nip29_events {
  my ($self, $channel, %args) = @_;
  if ($self->_authority_relay_enabled) {
    return $self->SUPER::_read_authoritative_nip29_events($channel, %args);
  }
  my $canonical = $self->_canonical_channel_name($channel);
  my $entry     = $self->{_spec_authoritative_channels}{$canonical} || {};
  return [@{$entry->{events} || []}];
}

sub _refresh_authoritative_nip29_channel_cache {
  my ($self, $channel, %args) = @_;
  if ($self->_authority_relay_enabled) {
    return $self->SUPER::_refresh_authoritative_nip29_channel_cache($channel, %args);
  }
  my $canonical = $self->_canonical_channel_name($channel);
  my $events    = $self->_read_authoritative_nip29_events($canonical, %args);
  my $view      = $self->_derive_authoritative_channel_view_from_events($canonical, $events);
  $self->{authoritative_channel_cache}{$canonical} = {
    events => $events,
    view   => $view,
  };
  return $events;
}

sub _ensure_authoritative_discovery_subscription {
  my ($self) = @_;
  if (!($self->_authority_relay_enabled)) {
    return 1;
  }
  return $self->SUPER::_ensure_authoritative_discovery_subscription();
}

sub _spec_nostr_events_for_subscription {
  my ($self, $subscription_id) = @_;
  my $subscription =
    $self->{_spec_nostr_subscriptions}{$subscription_id} || {};
  return _spec_nostr_events_for_filters($self, $subscription->{filters});
}

sub _spec_nostr_events_for_filters {
  my ($self, $filters) = @_;
  if (!(ref($filters) eq 'ARRAY' && @{$filters})) {
    return [];
  }

  my @events;
  my %seen_ids;
  for my $entry (values %{$self->{_spec_authoritative_channels} || {}}) {
    for my $event (@{ref($entry) eq 'HASH' ? ($entry->{events} || []) : []}) {
      if (!(ref($event) eq 'HASH')) {
        next;
      }
      if (!(_spec_event_matches_any_filter($event, $filters))) {
        next;
      }
      my $event_id =
           defined($event->{id})
        && !ref($event->{id})
        && length($event->{id})
        ? $event->{id}
        : undef;
      if (defined($event_id) && $seen_ids{$event_id}++) {
        next;
      }
      push @events, $event;
    }
  }

  return $self->_sort_authoritative_events(\@events);
}

sub _spec_event_matches_any_filter {
  my ($event, $filters) = @_;
  for my $filter (@{$filters || []}) {
    if (!(ref($filter) eq 'HASH')) {
      next;
    }
    if (_spec_event_matches_filter($event, $filter)) {
      return 1;
    }
  }
  return 0;
}

sub _spec_event_matches_filter {
  my ($event, $filter) = @_;
  if (!(ref($event) eq 'HASH')) {
    return 0;
  }
  if (!(ref($filter) eq 'HASH')) {
    return 0;
  }

  if (ref($filter->{kinds}) eq 'ARRAY' && @{$filter->{kinds}}) {
    if (!_kind_filter_matches($event, $filter->{kinds})) {
      return 0;
    }
  }

  for my $key (keys %{$filter}) {
    my ($tag_name) = $key =~ /\A\#(.+)\z/mxs;
    if (!(defined $tag_name)) {
      next;
    }
    my %allowed = map { $_ => 1 } @{$filter->{$key} || []};
    my $matched = 0;
    for my $tag (@{$event->{tags} || []}) {
      if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
        next;
      }
      if (!(($tag->[0] || q{}) eq $tag_name)) {
        next;
      }
      if ($allowed{$tag->[1]}) {
        $matched = 1;
        last;
      }
    }
    if (!($matched)) {
      return 0;
    }
  }

  return 1;
}

sub _kind_filter_matches {
  my ($event, $kinds) = @_;
  for my $kind (@{$kinds}) {
    if (($kind || 0) == ($event->{kind} || 0)) {
      return 1;
    }
  }
  return 0;
}

1;

=head1 NAME

Overnet::Test::SpecConformance::IRCServerHarness - IRC server harness for Overnet spec conformance tests

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Test::SpecConformance::IRCServerHarness;

=head1 DESCRIPTION

This module provides the IRC server harness used by Overnet spec conformance tests.

=head1 SUBROUTINES/METHODS

=head2 _supported_capabilities

Internal harness method.

=head2 _send_client_line

Internal harness method.

=head2 _request

Internal harness method.

=head1 DIAGNOSTICS

This module reports errors through normal Perl exceptions or structured return values.

=head1 CONFIGURATION AND ENVIRONMENT

No module-specific environment configuration is required.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

No known bugs are documented.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
