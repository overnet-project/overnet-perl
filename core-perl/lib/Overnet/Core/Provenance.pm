package Overnet::Core::Provenance;

use strictures 2;
use JSON ();

our $VERSION = '0.001';

my $JSON              = JSON->new->utf8;
my $DEFAULT_SEPARATOR = q{/};

sub verify_event {
  my ($event, $trusted_records, $options) = @_;
  $trusted_records ||= [];
  $options         ||= {};
  my $separator = defined $options->{origin_separator} ? $options->{origin_separator} : $DEFAULT_SEPARATOR;

  my $provenance = _event_provenance($event);
  if (!defined $provenance || ($provenance->{type} // q{}) ne 'adapted') {
    return {outcome => 'not_applicable'};
  }

  my $protocol = $provenance->{protocol};
  my $origin   = $provenance->{origin};
  if (!_is_non_empty_string($protocol) || !_is_non_empty_string($origin)) {
    return {outcome => 'unverified'};
  }

  my $tally = _tally_records(
    $trusted_records,
    {
      protocol  => $protocol,
      origin    => $origin,
      pubkey    => $event->{pubkey},
      at        => $event->{created_at},
      separator => $separator,
    },
  );

  return {outcome => _outcome_from_tally($tally)};
}

sub _event_provenance {
  my ($event) = @_;
  if (!(ref $event eq 'HASH')) {
    return;
  }
  if (ref $event->{provenance} eq 'HASH') {
    return $event->{provenance};
  }
  my $content = _decode_content($event->{content});
  return ref $content eq 'HASH' ? $content->{provenance} : undef;
}

sub _record_body {
  my ($auth_record) = @_;
  if (!(ref $auth_record eq 'HASH')) {
    return;
  }
  if (ref $auth_record->{body} eq 'HASH') {
    return $auth_record->{body};
  }
  my $content = _decode_content($auth_record->{content});
  return ref $content eq 'HASH' ? $content->{body} : undef;
}

sub _decode_content {
  my ($content) = @_;
  if (!defined $content || ref $content) {
    return;
  }
  my $decoded;
  my $ok = eval { $decoded = $JSON->decode($content); 1 };
  return $ok ? $decoded : undef;
}

sub _tally_records {
  my ($records, $ctx) = @_;
  my %tally = (applicable => 0, in_effect => 0, lists_key => 0, excludes_key => 0);

  for my $auth_record (@{$records}) {
    my $body = _record_body($auth_record);
    if (!_record_applies($body, $ctx)) {
      next;
    }
    $tally{applicable}++;
    if (!_record_in_effect($body, $ctx)) {
      next;
    }
    $tally{in_effect}++;
    if (_body_lists_key($body, $ctx->{pubkey})) {
      $tally{lists_key}++;
    } else {
      $tally{excludes_key}++;
    }
  }

  return \%tally;
}

sub _record_applies {
  my ($body, $ctx) = @_;
  if (!(ref $body eq 'HASH')) {
    return 0;
  }
  if (!(_is_non_empty_string($body->{protocol}) && $body->{protocol} eq $ctx->{protocol})) {
    return 0;
  }
  if (!_is_non_empty_string($body->{origin})) {
    return 0;
  }
  return _origin_matches($body, $ctx->{origin}, $ctx->{separator});
}

sub _origin_matches {
  my ($body, $event_origin, $separator) = @_;
  my $record_origin = $body->{origin};
  if ($event_origin eq $record_origin) {
    return 1;
  }
  if (($body->{origin_match} // q{}) eq 'prefix') {
    return index($event_origin, $record_origin . $separator) == 0 ? 1 : 0;
  }
  return 0;
}

sub _record_in_effect {
  my ($body, $ctx) = @_;
  if (!_origin_match_well_formed($body)) {
    return 0;
  }
  if (!_pubkeys_well_formed($body->{pubkeys})) {
    return 0;
  }
  return _within_window($body, $ctx->{at});
}

sub _origin_match_well_formed {
  my ($body) = @_;
  if (!exists $body->{origin_match}) {
    return 1;
  }
  my $match = $body->{origin_match};
  return defined $match && !ref $match && ($match eq 'exact' || $match eq 'prefix') ? 1 : 0;
}

sub _pubkeys_well_formed {
  my ($pubkeys) = @_;
  if (!(ref $pubkeys eq 'ARRAY')) {
    return 0;
  }
  for my $pubkey (@{$pubkeys}) {
    if (ref $pubkey || !defined $pubkey || $pubkey !~ /\A[0-9a-f]{64}\z/mxs) {
      return 0;
    }
  }
  return 1;
}

sub _within_window {
  my ($body, $at) = @_;

  # A declared window bound must be a well-formed integer timestamp. A malformed
  # bound means the record is not well-formed and cannot be shown to be in
  # effect, so it is not silently ignored (it tends toward unresolvable).
  if (exists $body->{not_before} && !_is_integer($body->{not_before})) {
    return 0;
  }
  if (exists $body->{not_after} && !_is_integer($body->{not_after})) {
    return 0;
  }

  # A record without a window is in effect regardless of the event's time. A
  # record that declares a window can only be shown to be in effect when the
  # event carries a usable timestamp to compare against it.
  if (!(exists $body->{not_before} || exists $body->{not_after})) {
    return 1;
  }
  if (!_is_integer($at)) {
    return 0;
  }

  if (exists $body->{not_before} && $at < $body->{not_before}) {
    return 0;
  }
  if (exists $body->{not_after} && $at > $body->{not_after}) {
    return 0;
  }
  return 1;
}

sub _body_lists_key {
  my ($body, $pubkey) = @_;
  if (!(defined $pubkey && ref $body->{pubkeys} eq 'ARRAY')) {
    return 0;
  }
  for my $candidate (@{$body->{pubkeys}}) {
    if (defined $candidate && !ref $candidate && $candidate eq $pubkey) {
      return 1;
    }
  }
  return 0;
}

sub _outcome_from_tally {
  my ($tally) = @_;
  if ($tally->{applicable} == 0) {
    return 'unverified';
  }
  if ($tally->{in_effect} == 0) {
    return 'unresolvable';
  }
  if ($tally->{lists_key} && $tally->{excludes_key}) {
    return 'unresolvable';
  }
  return $tally->{lists_key} ? 'authoritative' : 'forged';
}

sub _is_non_empty_string {
  my ($value) = @_;
  return defined $value && !ref($value) && length($value) ? 1 : 0;
}

sub _is_integer {
  my ($value) = @_;
  return defined $value && !ref($value) && $value =~ /\A\d+\z/mxs ? 1 : 0;
}

1;

=head1 NAME

Overnet::Core::Provenance - reference provenance verification for adapted events

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Core::Provenance;

  my $result = Overnet::Core::Provenance::verify_event($event, \@trusted_records);
  # $result->{outcome} is one of:
  #   authoritative, forged, unverified, unresolvable, not_applicable

=head1 DESCRIPTION

This module is the Overnet reference implementation of the consumer-side
provenance verification operation defined in Overnet core specification
section 7.9. Given an adapted event and the consumer's set of trusted
adapter authority records (section 6.15), it decides whether the signing
identity of the event is authoritative for the external origin the event
claims.

Verification does not admit, store, or reject events. It decides whether
adapted data may be presented as carrying authoritative external
attribution.

=head1 SUBROUTINES/METHODS

=head2 verify_event

  my $result = Overnet::Core::Provenance::verify_event($event, $records, \%options);

C<$event> is a wire-style Overnet event hash (with C<pubkey>, C<content>,
and C<created_at>) or a hash carrying a decoded C<provenance>. C<$records>
is an array reference of the consumer's trusted authority records, each a
wire-style event hash (with C<content>) or a hash carrying a decoded
C<body>. The caller is responsible for having already decided which records
to trust; this operation treats every supplied record as trusted.

The optional C<origin_separator> controls prefix matching of authority
record origins and defaults to C<"/">. Companion adapter specifications
define the separator for their origin space (the IRC adapter uses C<"/">).

The returned outcome is one of C<authoritative>, C<forged>, C<unverified>,
C<unresolvable>, or C<not_applicable> (returned for native data, which is
not subject to this operation).

=head1 DIAGNOSTICS

This module reports results through structured return values rather than
exceptions. Malformed trusted records are treated as unresolvable rather
than fatal.

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
