package Overnet::Core::Validator;

use strictures 2;
use English qw(-no_match_vars);
use B       ();
use JSON    ();
use Net::Nostr::Event;

our $VERSION = '0.001';

my %VALID_KINDS = (7_800 => 1, 37_800 => 1, 7_801 => 1);
my %SINGULAR_TAGS =
  map { $_ => 1 } qw(overnet_v overnet_et overnet_ot overnet_oid overnet_delegate v t o d);
my %MIRROR_TAG = (
  overnet_v   => 'v',
  overnet_et  => 't',
  overnet_ot  => 'o',
  overnet_oid => 'd',
);
my $JSON = JSON->new->utf8;

sub validate {
  my ($input, $context) = @_;
  my @errors;

  my ($event, $event_error) = _parse_event($input, 'Invalid Nostr event');
  if (!($event)) {
    return _result(errors => [$event_error],);
  }

  my $kind = $event->kind;
  my ($tag_values, $tag_counts) = _tag_info($event->tags);

  push @errors, _validate_kind($kind);
  push @errors, _validate_common_tags($tag_values, $tag_counts);
  push @errors, _validate_kind_tags($event, $kind, $tag_values, $tag_counts, $context);
  push @errors, _validate_event_content($event, $kind, $tag_values, $context);
  push @errors, _validate_removal_authorization($event, $tag_values, $context);
  push @errors, _validate_nostr_crypto($event);

  return _result(
    event  => $event,
    errors => \@errors,
  );
}

sub _parse_event {
  my ($input, $prefix) = @_;
  my $event;
  my $ok    = eval { $event = Net::Nostr::Event->from_wire($input); 1 };
  my $error = $EVAL_ERROR;
  if (!$ok) {
    (my $err = $error) =~ s/\ at\ .+\ line\ \d+.*//smx;
    return (undef, "$prefix: $err");
  }
  return ($event, undef);
}

sub _tag_info {
  my ($tags) = @_;
  my %tag_values;
  my %tag_counts;
  for my $tag (@{$tags}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag})) {
      next;
    }
    $tag_counts{$tag->[0]}++;
    if (@{$tag} >= 2) {
      $tag_values{$tag->[0]} = $tag->[1];
    }
  }
  return (\%tag_values, \%tag_counts);
}

sub _validate_kind {
  my ($kind) = @_;
  return $VALID_KINDS{$kind} ? () : ("Kind $kind is not a recognized Overnet kind (must be 7800, 37800, or 7801)");
}

sub _validate_common_tags {
  my ($tag_values, $tag_counts) = @_;
  my @errors;
  for my $tag_name (sort keys %SINGULAR_TAGS) {
    if (($tag_counts->{$tag_name} // 0) > 1) {
      push @errors, "Duplicate $tag_name tag";
    }
  }
  for my $tag_name (qw(overnet_v overnet_et overnet_ot overnet_oid)) {
    if (!(defined $tag_values->{$tag_name})) {
      push @errors, "Missing required $tag_name tag";
    }
  }
  for my $tag_name (qw(overnet_et overnet_ot overnet_oid)) {
    if (defined $tag_values->{$tag_name}
      && !(!ref($tag_values->{$tag_name}) && length($tag_values->{$tag_name}))) {
      push @errors, "$tag_name tag must be a non-empty string";
    }
  }
  for my $tag_name (qw(v t o d)) {
    if (!(defined $tag_values->{$tag_name})) {
      push @errors, "Missing required $tag_name tag";
    }
  }
  push @errors, _validate_mirror_tags($tag_values);
  return @errors;
}

sub _validate_mirror_tags {
  my ($tag_values) = @_;
  my @errors;
  for my $canonical (sort keys %MIRROR_TAG) {
    my $mirror = $MIRROR_TAG{$canonical};
    if (!(defined $tag_values->{$canonical} && defined $tag_values->{$mirror})) {
      next;
    }
    if ($tag_values->{$canonical} ne $tag_values->{$mirror}) {
      push @errors, "Mirror $mirror tag must match $canonical tag";
    }
  }
  return @errors;
}

sub _validate_kind_tags {
  my ($event, $kind, $tag_values, $tag_counts, $context) = @_;
  if ($kind == 37_800) {
    return _validate_state_tags($event, $tag_values, $tag_counts);
  }
  if ($kind == 7_801) {
    return _validate_removal_tags($tag_values, $tag_counts, $context);
  }
  return;
}

sub _validate_state_tags {
  my ($event, $tag_values, $tag_counts) = @_;
  my @errors;
  my $d_tag = $event->d_tag;
  if (($tag_counts->{d} // 0) > 1) {
    push @errors, "Duplicate d tag";
  }
  if ($d_tag eq q{}) {
    push @errors, "Kind 37800 requires a d tag set to the object identifier";
  } elsif (defined $tag_values->{overnet_oid} && $d_tag ne $tag_values->{overnet_oid}) {
    push @errors, "Kind 37800 d tag must match overnet_oid";
  }
  return @errors;
}

sub _validate_removal_tags {
  my ($tag_values, $tag_counts, $context) = @_;
  my @errors;
  my $can_check = 1;
  if (defined $tag_values->{overnet_et} && $tag_values->{overnet_et} ne 'core.removal') {
    push @errors, "Kind 7801 must use overnet_et value core.removal";
    $can_check = 0;
  }
  for my $check (
    [e                => "Duplicate e tag", "Kind 7801 requires an e tag identifying the event being tombstoned"],
    [overnet_delegate => "Duplicate overnet_delegate tag", undef],
  ) {
    my ($tag, $duplicate_error, $missing_error) = @{$check};
    ($can_check) = _validate_removal_tag_count($tag_values, $tag_counts, \@errors, $can_check, $tag, $duplicate_error,
      $missing_error);
  }
  _set_removal_authorization_flag($context, $can_check);
  return @errors;
}

sub _validate_removal_tag_count {
  my ($tag_values, $tag_counts, $errors, $can_check, $tag, $duplicate_error, $missing_error) = @_;
  if (($tag_counts->{$tag} // 0) > 1) {
    push @{$errors}, $duplicate_error;
    $can_check = 0;
  }
  if (defined($missing_error) && !defined $tag_values->{$tag}) {
    push @{$errors}, $missing_error;
    $can_check = 0;
  }
  return $can_check;
}

sub _set_removal_authorization_flag {
  my ($context, $can_check) = @_;
  if (ref $context eq 'HASH') {
    $context->{_can_check_removal_authorization} = $can_check;
  }
  return;
}

sub _validate_event_content {
  my ($event, $kind, $tag_values, $context) = @_;
  my ($content, $error) = _decode_content($event);
  if (defined $error) {
    return ($error);
  }
  my @errors;
  push @errors, _validate_provenance($content->{provenance});
  push @errors, _validate_body($content->{body}, $kind, $context);
  push @errors, _validate_core_delegation($content, $kind, $tag_values);
  push @errors, _validate_core_adapter_authority($content, $kind, $tag_values);
  return @errors;
}

sub _decode_content {
  my ($event) = @_;
  my $content;
  my $ok = eval { $content = $JSON->decode($event->content); 1 };
  if (!$ok || ref $content ne 'HASH') {
    return (undef, "Content must be a JSON object");
  }
  return ($content, undef);
}

sub _validate_provenance {
  my ($provenance) = @_;
  if (!defined $provenance || ref $provenance ne 'HASH') {
    return ("Missing required provenance field in content");
  }
  my $ptype = $provenance->{type};
  if (!defined $ptype || ($ptype ne 'native' && $ptype ne 'adapted')) {
    return ("Provenance type must be 'native' or 'adapted'");
  }
  return $ptype eq 'adapted' ? _validate_adapted_provenance($provenance) : ();
}

sub _validate_adapted_provenance {
  my ($provenance) = @_;
  my @errors;
  push @errors, _validate_required_non_empty($provenance, protocol => "Adapted provenance");
  push @errors, _validate_required_non_empty($provenance, origin   => "Adapted provenance");
  if (!defined $provenance->{limitations}) {
    push @errors, "Adapted provenance missing required limitations field";
  } elsif (!_is_string_array($provenance->{limitations})) {
    push @errors, "Adapted provenance limitations must be an array of strings";
  }
  push @errors, _validate_adapted_identity_scope($provenance);
  return @errors;
}

sub _validate_required_non_empty {
  my ($hash, $field, $label) = @_;
  if (!defined $hash->{$field}) {
    return ("$label missing required $field field");
  }
  return _is_non_empty_string($hash->{$field}) ? () : ("$label $field must be a non-empty string");
}

sub _validate_adapted_identity_scope {
  my ($provenance) = @_;
  my @errors;
  my $has_identity = _validate_optional_non_empty($provenance, 'external_identity', \@errors);
  my $has_scope    = _validate_optional_non_empty($provenance, 'external_scope',    \@errors);
  if (!($has_identity || $has_scope)) {
    push @errors, "Adapted provenance must include external_identity or external_scope";
  }
  return @errors;
}

sub _validate_optional_non_empty {
  my ($hash, $field, $errors) = @_;
  if (!(exists $hash->{$field})) {
    return 0;
  }
  if (_is_non_empty_string($hash->{$field})) {
    return 1;
  }
  push @{$errors}, "Adapted provenance $field must be a non-empty string";
  return 0;
}

sub _validate_body {
  my ($body, $kind, $context) = @_;
  if (!defined $body) {
    return ("Missing required body field in content");
  }
  if (ref $body ne 'HASH') {
    return ("Body field must be a JSON object");
  }
  if ($kind == 7_801 && keys %{$body}) {
    _set_removal_authorization_flag($context, 0);
    return ("Kind 7801 body must be an empty JSON object");
  }
  return;
}

sub _validate_core_delegation {
  my ($content, $kind, $tag_values) = @_;
  if (!(defined $tag_values->{overnet_et} && $tag_values->{overnet_et} eq 'core.delegation')) {
    return;
  }
  my @errors;
  push @errors, _validate_core_delegation_kind($kind);
  push @errors, _validate_core_delegation_provenance($content->{provenance});
  push @errors, _validate_core_delegation_body($content->{body});
  return @errors;
}

sub _validate_core_delegation_kind {
  my ($kind) = @_;
  return $kind == 7_800 ? () : ("Core delegation events must use kind 7800");
}

sub _validate_core_delegation_provenance {
  my ($provenance) = @_;
  return defined $provenance && ref $provenance eq 'HASH' && ($provenance->{type} // q{}) eq 'native'
    ? ()
    : ("Core delegation events must use native provenance");
}

sub _validate_core_delegation_body {
  my ($body) = @_;
  if (!defined $body || ref $body ne 'HASH') {
    return;
  }
  my @errors;
  if (!defined $body->{action} || $body->{action} ne 'remove') {
    push @errors, "Core delegation action must be remove";
  }
  if (!defined $body->{delegate_pubkey}) {
    push @errors, "Core delegation missing required delegate_pubkey field";
  } elsif ($body->{delegate_pubkey} !~ /\A[0-9a-f]{64}\z/mxs) {
    push @errors, "Core delegation delegate_pubkey must be 64-char lowercase hex";
  }
  if (defined $body->{expires_at} && (ref $body->{expires_at} || $body->{expires_at} !~ /\A\d+\z/mxs)) {
    push @errors, "Core delegation expires_at must be an integer timestamp";
  }
  return @errors;
}

sub _validate_core_adapter_authority {
  my ($content, $kind, $tag_values) = @_;
  if (!(defined $tag_values->{overnet_et} && $tag_values->{overnet_et} eq 'core.adapter_authority')) {
    return;
  }
  my @errors;
  if ($kind != 37_800) {
    push @errors, "Adapter authority record must use kind 37800";
  }
  if (!(defined $tag_values->{overnet_ot} && $tag_values->{overnet_ot} eq 'core.adapter_authority')) {
    push @errors, "Adapter authority record must use overnet_ot value core.adapter_authority";
  }
  push @errors, _validate_authority_provenance($content->{provenance});
  push @errors, _validate_authority_body($content->{body}, $tag_values);
  return @errors;
}

sub _validate_authority_provenance {
  my ($provenance) = @_;
  return defined $provenance && ref $provenance eq 'HASH' && ($provenance->{type} // q{}) eq 'native'
    ? ()
    : ("Adapter authority record must use native provenance");
}

sub _validate_authority_body {
  my ($body, $tag_values) = @_;
  if (!defined $body || ref $body ne 'HASH') {
    return;
  }
  my @errors;
  push @errors, _validate_authority_protocol_origin($body, $tag_values);
  push @errors, _validate_authority_pubkeys($body);
  push @errors, _validate_authority_origin_match($body);
  push @errors, _validate_authority_window($body);
  return @errors;
}

sub _validate_authority_protocol_origin {
  my ($body, $tag_values) = @_;
  my @errors;
  push @errors, _validate_authority_required_field($body, 'protocol');
  push @errors, _validate_authority_required_field($body, 'origin');
  if (_is_non_empty_string($body->{protocol}) && _is_non_empty_string($body->{origin})) {
    my $expected_oid = "$body->{protocol}:$body->{origin}";
    if (defined $tag_values->{overnet_oid} && $tag_values->{overnet_oid} ne $expected_oid) {
      push @errors, "Adapter authority record overnet_oid must equal protocol:origin";
    }
  }
  return @errors;
}

sub _validate_authority_required_field {
  my ($body, $field) = @_;
  if (!exists $body->{$field}) {
    return ("Adapter authority record missing required $field field");
  }
  return _is_non_empty_string($body->{$field})
    ? ()
    : ("Adapter authority record $field must be a non-empty string");
}

sub _validate_authority_pubkeys {
  my ($body) = @_;
  if (!exists $body->{pubkeys}) {
    return ("Adapter authority record missing required pubkeys field");
  }
  if (ref $body->{pubkeys} ne 'ARRAY') {
    return ("Adapter authority record pubkeys must be an array");
  }
  for my $pubkey (@{$body->{pubkeys}}) {
    if (ref $pubkey || !defined $pubkey || $pubkey !~ /\A[0-9a-f]{64}\z/mxs) {
      return ("Adapter authority record pubkeys must contain only 64-char lowercase hex strings");
    }
  }
  return;
}

sub _validate_authority_origin_match {
  my ($body) = @_;
  if (!exists $body->{origin_match}) {
    return;
  }
  my $match = $body->{origin_match};
  return (defined $match && !ref $match && ($match eq 'exact' || $match eq 'prefix'))
    ? ()
    : ("Adapter authority record origin_match must be exact or prefix");
}

sub _validate_authority_window {
  my ($body) = @_;
  my @errors;
  for my $field (qw(not_before not_after)) {
    if (defined $body->{$field} && (ref $body->{$field} || $body->{$field} !~ /\A\d+\z/mxs)) {
      push @errors, "Adapter authority record $field must be an integer timestamp";
    }
  }
  return @errors;
}

sub _validate_removal_authorization {
  my ($event, $tag_values, $context) = @_;
  if (!($event->kind == 7_801 && _can_check_removal_authorization($context))) {
    return;
  }
  my ($target_event, $target_error) = _removal_target_event($context);
  if (!($target_event)) {
    return ($target_error);
  }
  my @target_crypto_errors = _validate_context_event_crypto($target_event, 'Kind 7801 target event');
  if (@target_crypto_errors) {
    return @target_crypto_errors;
  }
  return _validate_removal_against_target($event, $tag_values, $context, $target_event);
}

sub _validate_context_event_crypto {
  my ($event, $label) = @_;
  my $ok    = eval { $event->validate(); 1 };
  my $error = $EVAL_ERROR;
  if (!$ok) {
    (my $err = $error) =~ s/\ at\ .+\ line\ \d+.*//smx;
    return ("$label failed Nostr validation: $err");
  }
  return;
}

sub _can_check_removal_authorization {
  my ($context) = @_;
  return !ref($context) || ref($context) ne 'HASH'
    ? 1
    : ($context->{_can_check_removal_authorization} // 1);
}

sub _removal_target_event {
  my ($context) = @_;
  my $target_input = ref($context) eq 'HASH' ? $context->{target_event} : undef;
  if (!defined $target_input) {
    return (undef, "Kind 7801 requires target event context for authorization");
  }
  return _parse_event($target_input, 'Invalid removal target event');
}

sub _validate_removal_against_target {
  my ($event, $tag_values, $context, $target_event) = @_;
  if ($tag_values->{e} ne $target_event->id) {
    return ("Kind 7801 target event context does not match e tag");
  }
  if (!defined $tag_values->{overnet_delegate}) {
    return _validate_direct_removal_author($event, $target_event);
  }
  return _validate_delegated_removal_context($event, $tag_values, $context, $target_event);
}

sub _validate_direct_removal_author {
  my ($event, $target_event) = @_;
  return $event->pubkey eq $target_event->pubkey
    ? ()
    : ("Kind 7801 removal must be authored by the same pubkey as the target event");
}

sub _validate_delegated_removal_context {
  my ($event, $tag_values, $context, $target_event) = @_;
  my $delegation_input = ref($context) eq 'HASH' ? $context->{delegation_event} : undef;
  if (!defined $delegation_input) {
    return ("Delegated removal requires delegation event context");
  }
  my ($delegation_event, $delegation_error) = _parse_event($delegation_input, 'Invalid delegation event');
  if (!($delegation_event)) {
    return ($delegation_error);
  }
  if ($tag_values->{overnet_delegate} ne $delegation_event->id) {
    return ("Delegated removal delegation context does not match overnet_delegate tag");
  }
  my @errors;
  _validate_delegated_removal(
    event            => $event,
    tag_values       => $tag_values,
    target_event     => $target_event,
    delegation_event => $delegation_event,
    errors           => \@errors,
  );
  return @errors;
}

sub _validate_nostr_crypto {
  my ($event)        = @_;
  my $validate_ok    = eval { $event->validate(); 1 };
  my $validate_error = $EVAL_ERROR;
  if (!$validate_ok) {
    (my $err = $validate_error) =~ s/\ at\ .+\ line\ \d+.*//smx;
    return ("Nostr validation failed: $err");
  }
  return;
}

sub _validate_delegated_removal {
  my %args             = @_;
  my $event            = $args{event};
  my $tag_values       = $args{tag_values};
  my $target_event     = $args{target_event};
  my $delegation_event = $args{delegation_event};
  my $errors           = $args{errors};

  my @crypto_errors = _validate_context_event_crypto($delegation_event, 'Delegated removal delegation event');
  if (@crypto_errors) {
    push @{$errors}, @crypto_errors;
    return;
  }

  if ($delegation_event->kind != 7_800) {
    push @{$errors}, "Delegated removal delegation event must use kind 7800";
    return;
  }

  my $content;
  my $content_ok = eval { $content = $JSON->decode($delegation_event->content); 1 };
  if ( !$content_ok
    || ref $content ne 'HASH'
    || ref($content->{body}) ne 'HASH') {
    push @{$errors}, "Invalid delegation event content";
    return;
  }

  my $provenance = $content->{provenance};
  if (!(defined $provenance && ref $provenance eq 'HASH' && ($provenance->{type} // q{}) eq 'native')) {
    push @{$errors}, "Delegated removal delegation event must use native provenance";
    return;
  }

  my %delegation_tags;
  for my $tag (@{$delegation_event->tags // []}) {
    if (!(ref $tag eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }
    $delegation_tags{$tag->[0]} = $tag->[1];
  }

  if (($delegation_tags{overnet_et} // q{}) ne 'core.delegation') {
    push @{$errors}, "Delegated removal requires a core.delegation event";
    return;
  }

  if ( ($delegation_tags{overnet_ot} // q{}) ne ($tag_values->{overnet_ot} // q{})
    || ($delegation_tags{overnet_oid} // q{}) ne ($tag_values->{overnet_oid} // q{})) {
    push @{$errors}, "Delegation object scope does not match removal object";
    return;
  }

  if ($delegation_event->pubkey ne $target_event->pubkey) {
    push @{$errors}, "Delegation must be authored by the same pubkey as the target event";
    return;
  }

  my $body = $content->{body};
  if (($body->{action} // q{}) ne 'remove') {
    push @{$errors}, "Delegation action must be remove";
    return;
  }

  if (($body->{delegate_pubkey} // q{}) ne $event->pubkey) {
    push @{$errors}, "Delegation delegate_pubkey does not authorize this removal pubkey";
    return;
  }

  if (defined $body->{expires_at}
    && $body->{expires_at} < $event->created_at) {
    push @{$errors}, "Delegation is expired at removal event timestamp";
  }
  return;
}

sub _result {
  my (%args) = @_;
  my $event  = $args{event};
  my $errors = $args{errors} || [];
  return @{$errors}
    ? {
    valid  => 0,
    errors => $errors,
    reason => $errors->[0],
    (defined $event ? (event => $event) : ())
    }
    : {
    valid  => 1,
    errors => [],
    (defined $event ? (event => $event) : ())
    };
}

sub _is_non_empty_string {
  my ($value) = @_;
  if (!defined $value || ref $value) {
    return 0;
  }

  # Reject a value that was decoded from JSON as a number where the spec
  # requires a string: a JSON string carries the POK flag, a JSON number does
  # not. This is checked before length(), which would coerce the value.
  if (!(B::svref_2object(\$value)->FLAGS & B::SVp_POK())) {
    return 0;
  }

  return length($value) ? 1 : 0;
}

sub _is_string_array {
  my ($value) = @_;
  if (!(ref($value) eq 'ARRAY')) {
    return 0;
  }

  for my $item (@{$value}) {
    if (!(_is_non_empty_string($item))) {
      return 0;
    }
  }

  return 1;
}

1;

=head1 NAME

Overnet::Core::Validator - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Core::Validator;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 validate

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
