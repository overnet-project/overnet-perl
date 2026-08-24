package Overnet::Authority::Delegation;

use strictures 2;
use Carp        qw(croak);
use Time::HiRes qw(time);
use Overnet::Core::Nostr;

our $VERSION = '0.001';

sub create_auth_event {
  my ($class, %args) = @_;
  my $key       = _require_key($args{key});
  my $challenge = $args{challenge};
  my $scope     = $args{scope};
  my $created_at =
    exists $args{created_at} ? $args{created_at} : int(time());

  if (!(defined $challenge && !ref($challenge) && length($challenge))) {
    return _invalid('challenge is required');
  }
  if (!(defined $scope && !ref($scope) && length($scope))) {
    return _invalid('scope is required');
  }
  if (!(defined $created_at && !ref($created_at))) {
    return _invalid('created_at is required');
  }

  return $key->create_event_hash(
    kind       => 22_242,
    created_at => $created_at + 0,
    content    => q{},
    tags       => [['relay', $scope], ['challenge', $challenge],],
  );
}

sub verify_auth_event {
  my ($class, %args) = @_;
  my $challenge  = $args{challenge};
  my $scope      = $args{scope};
  my $event_hash = $args{event};

  if (!(defined $challenge && !ref($challenge) && length($challenge))) {
    return _invalid('challenge is required');
  }
  if (!(defined $scope && !ref($scope) && length($scope))) {
    return _invalid('scope is required');
  }

  my ($event, $event_error) = _coerce_signed_event($event_hash);
  if (!($event)) {
    return _invalid($event_error);
  }

  if (!($event->kind == 22_242)) {
    return _invalid('auth event requires kind 22242');
  }

  my %tags = _first_tag_values($event->tags);
  if (!(defined $tags{challenge} && $tags{challenge} eq $challenge)) {
    return _invalid('auth event challenge does not match');
  }
  if (!(defined $tags{relay} && $tags{relay} eq $scope)) {
    return _invalid('auth event relay scope does not match');
  }

  return {
    valid    => 1,
    pubkey   => $event->pubkey,
    event_id => $event->id,
    event    => $event->to_hash,
  };
}

sub create_delegation_grant_event {
  my ($class, %args) = @_;
  my $key             = _require_key($args{key});
  my $relay_url       = $args{relay_url};
  my $scope           = $args{scope};
  my $delegate_pubkey = $args{delegate_pubkey};
  my $session_id      = $args{session_id};
  my $expires_at      = $args{expires_at};
  my $kind            = exists $args{kind} ? $args{kind} : 14_142;
  my $nick            = $args{nick};
  my $created_at =
    exists $args{created_at} ? $args{created_at} : int(time());

  my $error = _validate_grant_creation(
    relay_url       => $relay_url,
    scope           => $scope,
    delegate_pubkey => $delegate_pubkey,
    session_id      => $session_id,
    expires_at      => $expires_at,
    kind            => $kind,
    created_at      => $created_at,
    nick            => $nick,
  );

  if (defined $error) {
    return _invalid($error);
  }

  return $key->create_event_hash(
    kind       => 0 + $kind,
    created_at => $created_at + 0,
    content    => q{},
    tags       => [
      ['relay',      $relay_url],
      ['server',     $scope],
      ['delegate',   $delegate_pubkey],
      ['session',    $session_id],
      ['expires_at', "$expires_at"],
      (defined $nick ? (['nick', $nick]) : ()),
    ],
  );
}

sub verify_delegation_grant {
  my ($class, %args) = @_;
  my $authority_pubkey = $args{authority_pubkey};
  my $relay_url        = $args{relay_url};
  my $scope            = $args{scope};
  my $delegate_pubkey  = $args{delegate_pubkey};
  my $session_id       = $args{session_id};
  my $expires_at       = $args{expires_at};
  my $kind             = exists $args{kind} ? $args{kind} : 14_142;
  my $event_hash       = $args{event};

  my $error = _validate_grant_verification(
    authority_pubkey => $authority_pubkey,
    relay_url        => $relay_url,
    scope            => $scope,
    delegate_pubkey  => $delegate_pubkey,
    session_id       => $session_id,
    expires_at       => $expires_at,
    kind             => $kind,
  );

  if (defined $error) {
    return _invalid($error);
  }

  my ($event, $event_error) = _coerce_signed_event($event_hash);
  if (!($event)) {
    return _invalid($event_error);
  }

  $error = _verify_grant_event(
    event            => $event,
    authority_pubkey => $authority_pubkey,
    relay_url        => $relay_url,
    scope            => $scope,
    delegate_pubkey  => $delegate_pubkey,
    session_id       => $session_id,
    expires_at       => $expires_at,
    kind             => $kind,
  );
  if (defined $error) {
    return _invalid($error);
  }

  return {
    valid    => 1,
    pubkey   => $event->pubkey,
    event_id => $event->id,
    event    => $event->to_hash,
  };
}

sub _validate_grant_creation {
  my (%args) = @_;
  return
       _validate_grant_common(%args)
    || _validate_created_at($args{created_at})
    || _validate_optional_nick($args{nick});
}

sub _validate_grant_verification {
  my (%args) = @_;
  return _validate_hex_pubkey(authority_pubkey => $args{authority_pubkey})
    || _validate_grant_common(%args);
}

sub _validate_grant_common {
  my (%args) = @_;
  for my $check (
    [non_empty_string => relay_url       => $args{relay_url}],
    [non_empty_string => scope           => $args{scope}],
    [hex_pubkey       => delegate_pubkey => $args{delegate_pubkey}],
    [non_empty_string => session_id      => $args{session_id}],
    [digits           => expires_at      => $args{expires_at}],
    [positive_integer => kind            => $args{kind}],
  ) {
    my ($type, $name, $value) = @{$check};
    my $error = _validate_grant_field($type, $name, $value);
    if (defined $error) {
      return $error;
    }
  }
  return;
}

sub _validate_grant_field {
  my ($type, $name, $value) = @_;
  if ($type eq 'non_empty_string') {
    return _validate_non_empty_string($name, $value);
  }
  if ($type eq 'hex_pubkey') {
    return _validate_hex_pubkey($name, $value);
  }
  if ($type eq 'digits') {
    return _validate_digits($name, $value);
  }
  if ($type eq 'positive_integer') {
    return _validate_positive_integer($name, $value);
  }
  croak "Unknown delegation grant field validator: $type\n";
}

sub _validate_non_empty_string {
  my ($name, $value) = @_;
  return defined $value && !ref($value) && length($value) ? undef : "$name is required";
}

sub _validate_hex_pubkey {
  my ($name, $value) = @_;
  return defined $value && !ref($value) && $value =~ /\A[0-9a-f]{64}\z/mxs ? undef : "$name is required";
}

sub _validate_digits {
  my ($name, $value) = @_;
  return defined $value && !ref($value) && $value =~ /\A\d+\z/mxs ? undef : "$name is required";
}

sub _validate_positive_integer {
  my ($name, $value) = @_;
  return defined $value && !ref($value) && $value =~ /\A[1-9]\d*\z/mxs ? undef : "$name must be a positive integer";
}

sub _validate_created_at {
  my ($created_at) = @_;
  return defined $created_at && !ref($created_at) ? undef : 'created_at is required';
}

sub _validate_optional_nick {
  my ($nick) = @_;
  return !(defined $nick && (ref($nick) || !length($nick))) ? undef : 'nick must be a non-empty string';
}

sub _verify_grant_event {
  my (%args) = @_;
  return _verify_grant_identity(%args) || _verify_grant_tags(%args);
}

sub _verify_grant_identity {
  my (%args) = @_;
  my $event = $args{event};
  if (!($event->kind == $args{kind})) {
    return 'delegation event uses the wrong event kind';
  }
  if (!($event->pubkey eq $args{authority_pubkey})) {
    return 'delegation event pubkey does not match the authenticated user';
  }
  return;
}

sub _verify_grant_tags {
  my (%args) = @_;
  my %tags = _first_tag_values($args{event}->tags);
  for my $check (
    [relay    => $args{relay_url}       => 'delegation event relay does not match'],
    [server   => $args{scope}           => 'delegation event server scope does not match'],
    [delegate => $args{delegate_pubkey} => 'delegation event delegate pubkey does not match'],
    [session  => $args{session_id}      => 'delegation event session does not match'],
  ) {
    my ($tag, $expected, $error) = @{$check};
    if (!(defined $tags{$tag} && $tags{$tag} eq $expected)) {
      return $error;
    }
  }
  return _verify_expiration_tag($tags{expires_at}, $args{expires_at});
}

sub _verify_expiration_tag {
  my ($tag_value, $expires_at) = @_;
  if (!(defined $tag_value && $tag_value =~ /\A\d+\z/mxs && $tag_value == $expires_at)) {
    return 'delegation event expiration does not match';
  }
  return;
}

sub _coerce_signed_event {
  my ($event_hash) = @_;
  if (!(ref($event_hash) eq 'HASH')) {
    return (undef, 'event must be an object');
  }

  my $event = Overnet::Core::Nostr->event_from_wire($event_hash);
  if (!($event && eval { $event->validate; 1 })) {
    return (undef, 'event must be a valid signed Nostr event');
  }

  return ($event, undef);
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    if (exists $values{$tag->[0]}) {
      next;
    }
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _invalid {
  my ($reason) = @_;
  return {
    valid  => 0,
    reason => $reason,
  };
}

sub _require_key {
  my ($key) = @_;
  if (ref($key) && ref($key) eq 'Overnet::Core::Nostr::Key') {
    return $key;
  }
  croak "key must be an Overnet::Core::Nostr::Key instance\n";
}

1;

=head1 NAME

Overnet::Authority::Delegation - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Authority::Delegation;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 create_auth_event

Public API entry point.

=head2 verify_auth_event

Public API entry point.

=head2 create_delegation_grant_event

Public API entry point.

=head2 verify_delegation_grant

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
