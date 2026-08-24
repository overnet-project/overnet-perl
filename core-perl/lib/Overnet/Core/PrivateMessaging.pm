package Overnet::Core::PrivateMessaging;

use strictures 2;
use English qw(-no_match_vars);

use JSON ();
use Net::Nostr::GiftWrap;

our $VERSION = '0.001';

my %VALID_PRIVATE_TYPES = map { $_ => 1 } qw(chat.dm_message chat.dm_notice);
my $JSON                = JSON->new->utf8->canonical;

sub validate_transport {
  my ($input) = @_;

  if (ref($input) ne 'HASH') {
    return _result(errors => ['Private messaging input must be a hash object']);
  }

  if ($input->{relay_carried_private_intent}
    && ref($input->{event}) eq 'HASH') {
    return _validate_relay_carried_private_intent_event($input);
  }

  my @errors;
  my $transport = _transport_hash($input, \@errors);
  if (!(defined $transport)) {
    return _result(errors => \@errors);
  }

  my $visible_kind = _validate_visible_kind($transport, \@errors);
  my $details =
    ref($transport->{decrypted_rumor}) eq 'HASH'
    ? _validate_decrypted_rumor_transport($input, $transport)
    : _validate_opaque_transport($input, $transport);
  push @errors, @{$details->{errors}};

  return _result(
    errors          => \@errors,
    visible_kind    => $visible_kind,
    decrypted_rumor => $details->{decrypted_rumor},
    private_type    => $details->{private_type},
    object_type     => $details->{object_type},
    object_id       => $details->{object_id},
    sender_identity => $details->{sender_identity},
  );
}

sub _transport_hash {
  my ($input, $errors) = @_;
  my $transport = $input->{transport};
  if (ref($transport) ne 'HASH') {
    push @{$errors}, 'Private messaging transport must be a hash object';
    return;
  }
  return $transport;
}

sub _validate_visible_kind {
  my ($transport, $errors) = @_;
  my $visible_kind = $transport->{kind};
  if (!defined $visible_kind || ref($visible_kind) || $visible_kind !~ /\A\d+\z/mxs) {
    push @{$errors}, 'Private messaging transport kind must be an integer';
  } elsif ($visible_kind != 1059) {
    push @{$errors}, 'Relay-carried private direct messages must use kind 1059 gift wrap events';
  }
  return $visible_kind;
}

sub _validate_decrypted_rumor_transport {
  my ($input, $transport) = @_;
  my @errors;
  my $rumor_data = $transport->{decrypted_rumor};
  my ($payload, $payload_error) = _normalize_payload($rumor_data->{content});
  if (defined $payload_error) {
    push @errors, $payload_error;
  }

  my $rumor_event = @errors ? undef : _create_rumor_event($rumor_data, $payload, \@errors);
  if ($rumor_event) {
    push @errors, _validate_rumor_event($rumor_event);
  }

  my $details          = _payload_details($payload);
  my $normalized_rumor = _normalized_rumor($rumor_event, $payload, \@errors);
  if (defined $payload) {
    push @errors, _validate_payload($payload);
    push @errors, _validate_decrypted_source_binding($input, $payload);
  }

  return {
    %{$details},
    errors          => \@errors,
    decrypted_rumor => $normalized_rumor,
  };
}

sub _create_rumor_event {
  my ($rumor_data, $payload, $errors) = @_;
  my %rumor_args = (
    pubkey     => $rumor_data->{pubkey},
    created_at => $rumor_data->{created_at},
    kind       => $rumor_data->{kind},
    tags       => $rumor_data->{tags},
    content    => $JSON->encode($payload),
  );

  my $rumor_event;
  my $rumor_ok = eval {
    $rumor_event = Net::Nostr::GiftWrap->create_rumor(%rumor_args);
    1;
  };
  my $rumor_error = $EVAL_ERROR;
  if (!$rumor_ok) {
    (my $err = $rumor_error) =~ s/\ at\ .+\ line\ \d+.*//smx;
    push @{$errors}, "Invalid NIP-17 rumor: $err";
  }

  return $rumor_event;
}

sub _validate_rumor_event {
  my ($rumor_event) = @_;
  my @errors;
  if (!($rumor_event->kind == 14)) {
    push @errors, 'Relay-carried private direct messages must use kind 14 rumors';
  }

  my @recipient_tags =
    grep { ref eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p' } @{$rumor_event->tags};
  if (!(@recipient_tags == 1)) {
    push @errors, 'Relay-carried one-to-one private direct messages require exactly one rumor p tag';
  }

  return @errors;
}

sub _payload_details {
  my ($payload) = @_;
  if (!(defined $payload)) {
    return {};
  }
  return {
    private_type    => $payload->{private_type},
    object_type     => $payload->{object_type},
    object_id       => $payload->{object_id},
    sender_identity => _payload_sender_identity($payload),
  };
}

sub _payload_sender_identity {
  my ($payload) = @_;
  return ref($payload->{provenance}) eq 'HASH'
    ? $payload->{provenance}{external_identity}
    : undef;
}

sub _validate_decrypted_source_binding {
  my ($input, $payload) = @_;
  if (!(ref($input->{source}) eq 'HASH' && ($input->{source}{protocol} // q{}) eq 'irc')) {
    return;
  }
  return _validate_irc_decrypted_binding(
    source  => $input->{source},
    payload => $payload,
  );
}

sub _normalized_rumor {
  my ($rumor_event, $payload, $errors) = @_;
  if (!($rumor_event && !@{$errors})) {
    return;
  }
  return {
    id         => $rumor_event->id,
    pubkey     => $rumor_event->pubkey,
    created_at => $rumor_event->created_at,
    kind       => $rumor_event->kind,
    tags       => $rumor_event->tags,
    content    => $payload,
  };
}

sub _validate_opaque_transport {
  my ($input, $transport) = @_;
  my @errors;
  if (!(_has_opaque_metadata($input))) {
    return {errors => ['Opaque private-message transport requires private_type, object_type, and object_id metadata'],};
  }

  my $details = {
    private_type    => $input->{private_type},
    object_type     => $input->{object_type},
    object_id       => $input->{object_id},
    sender_identity => $input->{sender_identity},
  };

  push @errors, _validate_opaque_metadata(%{$details});
  push @errors, _validate_opaque_recipients($transport);
  push @errors, _validate_opaque_source_binding($input, $details);

  return {%{$details}, errors => \@errors};
}

sub _has_opaque_metadata {
  my ($input) = @_;
  return
       defined $input->{private_type}
    && defined $input->{object_type}
    && defined $input->{object_id} ? 1 : 0;
}

sub _validate_opaque_recipients {
  my ($transport) = @_;
  my @recipient_tags =
    grep { ref eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p' } @{$transport->{tags} || []};
  return @recipient_tags == 1 ? () : ('Opaque private direct messages require exactly one visible transport p tag');
}

sub _validate_opaque_source_binding {
  my ($input, $details) = @_;
  if (!(ref($input->{source}) eq 'HASH' && ($input->{source}{protocol} // q{}) eq 'irc')) {
    return;
  }
  return _validate_irc_opaque_binding(
    source          => $input->{source},
    private_type    => $details->{private_type},
    object_type     => $details->{object_type},
    object_id       => $details->{object_id},
    sender_identity => $details->{sender_identity},
  );
}

sub _validate_relay_carried_private_intent_event {
  my ($input) = @_;
  my @errors;
  my $event = $input->{event};
  my $kind  = $event->{kind};

  if ( defined $kind
    && !ref($kind)
    && $kind =~ /\A\d+\z/mxs
    && $kind == 7_800) {
    my %tag_values;
    for my $tag (@{$event->{tags} || []}) {
      if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
        next;
      }
      $tag_values{$tag->[0]} = $tag->[1];
    }

    if (
      ($tag_values{overnet_ot} // q{}) eq 'chat.dm'
      && ( ($tag_values{overnet_et} // q{}) eq 'chat.dm_message'
        || ($tag_values{overnet_et} // q{}) eq 'chat.dm_notice')
    ) {
      push @errors, 'Relay-carried private direct messages must use NIP-17 rather than public Overnet core events';
    }
  }

  if (!(@errors)) {
    push @errors, 'Relay-carried private direct messages must use NIP-17 rather than public Overnet core events';
  }

  return _result(errors => \@errors);
}

sub _normalize_payload {
  my ($content) = @_;

  if (ref($content) eq 'HASH') {
    return ($content, undef);
  }

  if (!defined $content || ref($content)) {
    return (undef, 'Decrypted rumor content must be a JSON object or JSON object string');
  }

  my $decoded;
  my $decode_ok = eval { $decoded = $JSON->decode($content); 1 };
  if (!$decode_ok || ref($decoded) ne 'HASH') {
    return (undef, 'Decrypted rumor content must decode to a JSON object');
  }

  return ($decoded, undef);
}

sub _validate_payload {
  my ($payload) = @_;
  my @errors;

  if (!_is_non_empty_string($payload->{overnet_v})) {
    push @errors, 'Private-message payload overnet_v must be a non-empty string';
  }

  if ( !defined $payload->{private_type}
    || !$VALID_PRIVATE_TYPES{$payload->{private_type}}) {
    push @errors, 'Private-message payload private_type must be chat.dm_message or chat.dm_notice';
  }

  if (($payload->{object_type} // q{}) ne 'chat.dm') {
    push @errors, 'Private-message payload object_type must be chat.dm';
  }

  if (!_is_non_empty_string($payload->{object_id})) {
    push @errors, 'Private-message payload object_id must be a non-empty string';
  }

  push @errors, _validate_provenance($payload->{provenance});

  if (ref($payload->{body}) ne 'HASH') {
    push @errors, 'Private-message payload body must be an object';
  } elsif (!exists $payload->{body}{text}
    || !defined $payload->{body}{text}
    || ref($payload->{body}{text})) {
    push @errors, 'Private-message payload body.text must be a string';
  }

  return @errors;
}

sub _validate_irc_decrypted_binding {
  my (%args)  = @_;
  my $source  = $args{source};
  my $payload = $args{payload};
  my @errors;

  my $network = $source->{network};
  if (!(_is_non_empty_string($network))) {
    push @errors, 'IRC private-message binding requires a non-empty source.network string';
  }

  my $line = $source->{line};
  if (!_is_non_empty_string($line)) {
    push @errors, 'IRC private-message binding requires a non-empty source.line string';
    return @errors;
  }

  my $parsed = _parse_irc_direct_message_line($line);
  if (!$parsed) {
    push @errors, 'IRC private-message binding source.line must contain a direct-message PRIVMSG or NOTICE';
    return @errors;
  }
  my $command = $parsed->{command};
  my $target  = $parsed->{target};

  if ($target =~ /\A[#&+!]/mxs) {
    push @errors, 'IRC private-message binding source.line must target a nick, not a channel';
    return @errors;
  }

  if ($command eq 'PRIVMSG') {
    if (!(($payload->{private_type} // q{}) eq 'chat.dm_message')) {
      push @errors, 'IRC private-message binding must use private_type chat.dm_message for PRIVMSG';
    }
  } elsif ($command eq 'NOTICE') {
    if (!(($payload->{private_type} // q{}) eq 'chat.dm_notice')) {
      push @errors, 'IRC private-message binding must use private_type chat.dm_notice for NOTICE';
    }
  } else {
    push @errors, 'IRC private-message binding source.line must use PRIVMSG or NOTICE';
  }

  my $expected_object_id = "irc:$network:dm:$target";
  if (!(($payload->{object_id} // q{}) eq $expected_object_id)) {
    push @errors, "IRC private-message binding object_id must be $expected_object_id";
  }

  if (ref($payload->{provenance}) ne 'HASH'
    || ($payload->{provenance}{protocol} // q{}) ne 'irc') {
    push @errors, 'IRC private-message binding provenance.protocol must be irc';
  } elsif (defined($payload->{provenance}{external_identity})
    && ($payload->{provenance}{external_identity} // q{}) ne ($parsed->{sender} // q{})) {
    push @errors, 'IRC private-message binding provenance.external_identity must match the IRC sender nick';
  }

  return @errors;
}

sub _validate_irc_opaque_binding {
  my (%args) = @_;
  my $source = $args{source};
  my @errors;

  my $network = $source->{network};
  if (!(_is_non_empty_string($network))) {
    push @errors, 'IRC private-message binding requires a non-empty source.network string';
  }

  my $line = $source->{line};
  if (!_is_non_empty_string($line)) {
    push @errors, 'IRC private-message binding requires a non-empty source.line string';
    return @errors;
  }

  my $parsed = _parse_irc_direct_message_line($line);
  if (!$parsed) {
    push @errors, 'IRC private-message binding source.line must contain a direct-message PRIVMSG or NOTICE';
    return @errors;
  }

  if ($parsed->{target} =~ /\A[#&+!]/mxs) {
    push @errors, 'IRC private-message binding source.line must target a nick, not a channel';
    return @errors;
  }

  if (!($line =~ /\s:\+overnet-e2ee-v1\s+\S/mxs)) {
    push @errors, 'Opaque IRC private-message binding source.line must carry an overnet-e2ee-v1 transport body';
  }

  if ($parsed->{command} eq 'PRIVMSG') {
    if (!(($args{private_type} // q{}) eq 'chat.dm_message')) {
      push @errors, 'IRC private-message binding must use private_type chat.dm_message for PRIVMSG';
    }
  } elsif ($parsed->{command} eq 'NOTICE') {
    if (!(($args{private_type} // q{}) eq 'chat.dm_notice')) {
      push @errors, 'IRC private-message binding must use private_type chat.dm_notice for NOTICE';
    }
  } else {
    push @errors, 'IRC private-message binding source.line must use PRIVMSG or NOTICE';
  }

  if (!(($args{object_type} // q{}) eq 'chat.dm')) {
    push @errors, 'Opaque private-message binding object_type must be chat.dm';
  }

  my $expected_object_id = "irc:$network:dm:$parsed->{target}";
  if (!(($args{object_id} // q{}) eq $expected_object_id)) {
    push @errors, "IRC private-message binding object_id must be $expected_object_id";
  }

  if (!(_is_non_empty_string($args{sender_identity}))) {
    push @errors, 'Opaque IRC private-message binding requires sender_identity';
  }
  if (_is_non_empty_string($args{sender_identity})
    && ($args{sender_identity} // q{}) ne ($parsed->{sender} // q{})) {
    push @errors, 'Opaque IRC private-message binding sender_identity must match the IRC sender nick';
  }

  return @errors;
}

sub _validate_opaque_metadata {
  my (%args) = @_;
  my @errors;

  if ( !defined $args{private_type}
    || !$VALID_PRIVATE_TYPES{$args{private_type}}) {
    push @errors, 'Opaque private-message private_type must be chat.dm_message or chat.dm_notice';
  }

  if (($args{object_type} // q{}) ne 'chat.dm') {
    push @errors, 'Opaque private-message object_type must be chat.dm';
  }

  if (!_is_non_empty_string($args{object_id})) {
    push @errors, 'Opaque private-message object_id must be a non-empty string';
  }

  if ( exists $args{sender_identity}
    && defined $args{sender_identity}
    && !_is_non_empty_string($args{sender_identity})) {
    push @errors, 'Opaque private-message sender_identity must be a non-empty string when present';
  }

  return @errors;
}

sub _parse_irc_direct_message_line {
  my ($line) = @_;
  if (!(_is_non_empty_string($line))) {
    return;
  }

  my ($sender, $command, $target) = $line =~ /\A:([^\s!]+)(?:![^\s]+)?\s+([A-Z]+)\s+([^\s]+)\s+:/mxs;
  if (!(defined $sender && defined $command && defined $target)) {
    return;
  }

  return {
    sender  => $sender,
    command => $command,
    target  => $target,
  };
}

sub _validate_provenance {
  my ($provenance) = @_;
  my @errors;

  if (ref($provenance) ne 'HASH') {
    push @errors, 'Private-message payload provenance must be an object';
    return @errors;
  }

  my $ptype = $provenance->{type};
  if (!defined $ptype || ($ptype ne 'native' && $ptype ne 'adapted')) {
    push @errors, "Private-message payload provenance type must be 'native' or 'adapted'";
    return @errors;
  }

  if ($ptype eq 'adapted') {
    if (!_is_non_empty_string($provenance->{protocol})) {
      push @errors, 'Adapted private-message provenance protocol must be a non-empty string';
    }

    if (!_is_non_empty_string($provenance->{origin})) {
      push @errors, 'Adapted private-message provenance origin must be a non-empty string';
    }

    if (!_is_string_array($provenance->{limitations})) {
      push @errors, 'Adapted private-message provenance limitations must be an array of strings';
    }

    my $has_identity = _is_non_empty_string($provenance->{external_identity});
    my $has_scope    = _is_non_empty_string($provenance->{external_scope});
    if (!($has_identity || $has_scope)) {
      push @errors, 'Adapted private-message provenance must include external_identity or external_scope';
    }
  }

  return @errors;
}

sub _is_non_empty_string {
  my ($value) = @_;
  return defined $value && !ref($value) && length $value;
}

sub _is_string_array {
  my ($value) = @_;
  if (!(ref($value) eq 'ARRAY')) {
    return 0;
  }
  for my $item (@{$value}) {
    if (!defined $item || ref($item)) {
      return 0;
    }
  }
  return 1;
}

sub _result {
  my (%args) = @_;
  my $errors = $args{errors} || [];

  return @{$errors}
    ? {
    valid  => 0,
    errors => $errors,
    reason => $errors->[0],
    }
    : {
    valid           => 1,
    errors          => [],
    visible_kind    => $args{visible_kind},
    decrypted_rumor => $args{decrypted_rumor},
    private_type    => $args{private_type},
    object_type     => $args{object_type},
    object_id       => $args{object_id},
    sender_identity => $args{sender_identity},
    };
}

1;

=head1 NAME

Overnet::Core::PrivateMessaging - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Core::PrivateMessaging;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 validate_transport

Public API entry point.

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
