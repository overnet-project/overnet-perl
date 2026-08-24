package Overnet::Core::ProfileContract;

use strictures 2;
use English qw(-no_match_vars);
use B       qw(SVp_IOK SVp_NOK SVp_POK svref_2object);
use JSON    ();
use JSON::Schema::Modern;
use Scalar::Util qw(blessed);

our $VERSION = '0.001';

my $JSON        = JSON->new->utf8;
my $JSON_SCHEMA = JSON::Schema::Modern->new(
  specification_version => 'draft2020-12',
  output_format         => 'flag',
);
my %TOP_LEVEL = map { $_ => 1 }
  qw(contract_version profile profile_version status description capabilities depends_on object_types event_types fixtures extensions);
my @REQUIRED_TOP_LEVEL =
  qw(contract_version profile profile_version status description capabilities object_types event_types fixtures extensions);
my %STATUS = map { $_ => 1 } qw(draft stable deprecated);
my %CORE_REQUIRED_TAG =
  map { $_ => 1 } qw(overnet_v overnet_et overnet_ot overnet_oid v t o d);
my %OBJECT_ID_SCHEME =
  map { $_ => 1 } qw(profile-defined uuid uri content-addressed opaque);
my %STATE_DERIVATION = map { $_ => 1 } qw(event-log latest-per-author external-authoritative profile-defined);
my %STATE_EFFECT =
  map { $_ => 1 } qw(none creates updates removes profile-defined);
my %AUTHORIZATION_MODEL = map { $_ => 1 } qw(open author-is-object-owner delegated external-authority profile-defined);
my %PRIVACY             = map { $_ => 1 } qw(public encrypted profile-defined);

my %DEPENDENCY_FIELD   = map { $_ => 1 } qw(profile version);
my %FIXTURES_FIELD     = map { $_ => 1 } qw(valid invalid);
my %OBJECT_TYPE_FIELD  = map { $_ => 1 } qw(description id state extensions);
my %OBJECT_ID_FIELD    = map { $_ => 1 } qw(scheme pattern examples);
my %OBJECT_STATE_FIELD = map { $_ => 1 } qw(derivation state_event_type);
my %EVENT_TYPE_FIELD   = map { $_ => 1 }
  qw(description kind object_type required_tags body_schema references state_effect authorization privacy extensions);
my %AUTHORIZATION_FIELD = map { $_ => 1 } qw(model description);
my %REFERENCE_FIELD =
  map { $_ => 1 } qw(name required tag target_object_type target_event_type);

sub validate_contract {
  my ($profile_contract) = @_;
  my @errors;
  if (!(ref($profile_contract) eq 'HASH')) {
    return _result(errors => ['profile_contract.document_not_object']);
  }

  push @errors, _validate_contract_top_level($profile_contract);
  push @errors, _validate_contract_metadata($profile_contract);
  _validate_capabilities($profile_contract, \@errors);
  _validate_dependencies($profile_contract, \@errors);
  _validate_fixtures($profile_contract, \@errors);
  if (exists $profile_contract->{extensions}) {
    _validate_extensions($profile_contract->{extensions}, \@errors);
  }

  my $object_types = _contract_object_types($profile_contract, \@errors);
  my $event_types  = _contract_event_types($profile_contract, \@errors);
  _validate_contract_object_types($profile_contract, $object_types, \@errors);
  _validate_contract_event_types($profile_contract, $object_types, $event_types, \@errors);
  _validate_state_event_types($object_types, $event_types, \@errors);

  return _result(errors => \@errors, contract => $profile_contract);
}

sub _validate_contract_top_level {
  my ($profile_contract) = @_;
  my @errors;
  for my $field (sort keys %{$profile_contract}) {
    if (!($TOP_LEVEL{$field})) {
      push @errors, 'profile_contract.unknown_top_level_field';
    }
  }
  for my $field (@REQUIRED_TOP_LEVEL) {
    if (!(exists $profile_contract->{$field})) {
      push @errors, $field eq 'contract_version'
        ? 'profile_contract.missing_contract_version'
        : "profile_contract.missing_$field";
    }
  }
  return @errors;
}

sub _validate_contract_metadata {
  my ($profile_contract) = @_;
  my @errors;
  if (_invalid_contract_version($profile_contract)) {
    push @errors, 'profile_contract.invalid_contract_version';
  }
  my $profile = $profile_contract->{profile};
  if (!(_is_profile_name($profile))) {
    push @errors, 'profile_contract.invalid_profile_namespace';
  }

  if (exists $profile_contract->{profile_version}
    && !_is_semver($profile_contract->{profile_version})) {
    push @errors, 'profile_contract.invalid_profile_version';
  }

  if (
    exists $profile_contract->{status}
    && ( !_is_non_empty_string($profile_contract->{status})
      || !$STATUS{$profile_contract->{status}})
  ) {
    push @errors, 'profile_contract.invalid_status';
  }

  if (exists $profile_contract->{description}
    && !_is_non_empty_string($profile_contract->{description})) {
    push @errors, 'profile_contract.invalid_description';
  }
  return @errors;
}

sub _invalid_contract_version {
  my ($profile_contract) = @_;
  return exists $profile_contract->{contract_version}
    && (!_is_json_integer($profile_contract->{contract_version})
    || $profile_contract->{contract_version} != 1) ? 1 : 0;
}

sub _contract_object_types {
  my ($profile_contract, $errors) = @_;
  my $object_types =
    ref($profile_contract->{object_types}) eq 'HASH'
    ? $profile_contract->{object_types}
    : {};
  if (
    exists $profile_contract->{object_types}
    && (ref($profile_contract->{object_types}) ne 'HASH'
      || !keys %{$object_types})
  ) {
    push @{$errors}, 'profile_contract.invalid_object_types';
  }
  return $object_types;
}

sub _contract_event_types {
  my ($profile_contract, $errors) = @_;
  my $event_types =
    ref($profile_contract->{event_types}) eq 'HASH'
    ? $profile_contract->{event_types}
    : {};
  if (
    exists $profile_contract->{event_types}
    && (ref($profile_contract->{event_types}) ne 'HASH'
      || !keys %{$event_types})
  ) {
    push @{$errors}, 'profile_contract.invalid_event_types';
  }
  return $event_types;
}

sub _validate_contract_object_types {
  my ($profile_contract, $object_types, $errors) = @_;
  my $profile = $profile_contract->{profile};
  for my $name (sort keys %{$object_types}) {
    my $object_type = $object_types->{$name};
    if (!(_is_profile_scoped_name($name) && _is_local_name($profile, $name))) {
      push @{$errors}, 'profile_contract.object_type_outside_profile_namespace';
    }

    _validate_object_type($object_type, $errors);
  }
  return;
}

sub _validate_contract_event_types {
  my ($profile_contract, $object_types, $event_types, $errors) = @_;
  my $profile = $profile_contract->{profile};
  for my $name (sort keys %{$event_types}) {
    my $event_type = $event_types->{$name};

    if (!(_is_profile_scoped_name($name) && _is_local_name($profile, $name))) {
      push @{$errors}, 'profile_contract.event_type_outside_profile_namespace';
    }

    _validate_event_type($profile_contract, $event_type, $object_types, $errors);
  }
  return;
}

sub _validate_state_event_types {
  my ($object_types, $event_types, $errors) = @_;
  for my $name (sort keys %{$object_types}) {
    my $object_type = $object_types->{$name};
    if (!(ref($object_type) eq 'HASH' && ref($object_type->{state}) eq 'HASH')) {
      next;
    }
    my $state_event_type = $object_type->{state}{state_event_type};
    if (_is_non_empty_string($state_event_type)
      && !exists $event_types->{$state_event_type}) {
      push @{$errors}, 'profile_contract.state_event_type_undefined';
    }
  }
  return;
}

sub validate_contract_set {
  my ($contracts) = @_;
  my @errors;
  if (!(ref($contracts) eq 'ARRAY')) {
    return _result(errors => ['profile_contract_set.contracts_not_array']);
  }

  my %by_profile;
  for my $profile_contract (@{$contracts}) {
    my $result = validate_contract($profile_contract);
    if (!($result->{valid})) {
      push @errors, @{$result->{errors}};
    }

    my $profile =
      ref($profile_contract) eq 'HASH'
      ? $profile_contract->{profile}
      : undef;
    if (!(defined $profile)) {
      next;
    }

    if (exists $by_profile{$profile}) {
      push @errors, 'profile_contract_set.duplicate_profile';
    } else {
      $by_profile{$profile} = $profile_contract;
    }
  }

  if (!@errors) {
    for my $profile_contract (@{$contracts}) {
      _validate_contract_dependencies_in_set($profile_contract, \%by_profile, \@errors);
    }
  }

  if (!@errors) {
    for my $profile_contract (@{$contracts}) {
      _validate_external_references_in_set($profile_contract, \%by_profile, \@errors);
    }
  }

  if (!@errors) {
    for my $profile_contract (@{$contracts}) {
      _validate_external_event_object_types_in_set($profile_contract, \%by_profile, \@errors);
    }
  }

  return _result(
    errors     => \@errors,
    contracts  => $contracts,
    by_profile => \%by_profile
  );
}

sub validate_profile_event {
  my (%args) = @_;
  my @contracts = _profile_event_contracts(%args);
  if (!(@contracts)) {
    return {valid => 1, applicable => 0, errors => []};
  }

  my $context = _profile_event_contract_context(\@contracts);
  if (!($context->{valid})) {
    return $context;
  }

  my ($kind, $tags, $content) = _event_parts($args{event});
  my ($tag_values, $tag_counts) = _event_tags($tags);
  my $event_type_name = $tag_values->{overnet_et};
  my @matches         = _matching_profile_event_types($event_type_name, \@contracts);

  if (!(@matches)) {
    return _result(
      errors     => ['profile_event.event_type_undefined'],
      applicable => 1
    );
  }

  if (@matches > 1) {
    return _result(
      errors     => ['profile_event.event_type_ambiguous'],
      applicable => 1
    );
  }

  my ($profile_contract, $event_type) = @{$matches[0]};
  my @errors = _validate_profile_event_match(
    kind       => $kind,
    tag_values => $tag_values,
    tag_counts => $tag_counts,
    content    => $content,
    event_type => $event_type,
  );

  return _result(
    errors     => \@errors,
    applicable => 1,
    contract   => $profile_contract
  );
}

sub _profile_event_contracts {
  my (%args) = @_;
  my @contracts;
  if (exists $args{contract} && defined $args{contract}) {
    push @contracts, $args{contract};
  }
  if (ref($args{contracts}) eq 'ARRAY') {
    push @contracts, @{$args{contracts}};
  }
  return @contracts;
}

sub _profile_event_contract_context {
  my ($contracts) = @_;
  return @{$contracts} == 1
    ? validate_contract($contracts->[0])
    : validate_contract_set($contracts);
}

sub _matching_profile_event_types {
  my ($event_type_name, $contracts) = @_;
  my @matches;
  for my $profile_contract (@{$contracts}) {
    if (!(ref($profile_contract) eq 'HASH' && ref($profile_contract->{event_types}) eq 'HASH')) {
      next;
    }
    if (!(defined $event_type_name && exists $profile_contract->{event_types}{$event_type_name})) {
      next;
    }
    push @matches, [$profile_contract, $profile_contract->{event_types}{$event_type_name}];
  }
  return @matches;
}

sub _validate_profile_event_match {
  my (%args) = @_;
  my @errors;
  push @errors, _validate_profile_event_kind(%args);
  push @errors, _validate_profile_event_object_type(%args);
  push @errors, _validate_profile_event_required_tags(%args);
  push @errors, _validate_profile_event_body(%args);
  push @errors, _validate_profile_event_required_references(%args);
  return @errors;
}

sub _validate_profile_event_kind {
  my (%args) = @_;
  return defined $args{kind} && $args{kind} == $args{event_type}{kind} ? () : ('profile_event.kind_mismatch');
}

sub _validate_profile_event_object_type {
  my (%args) = @_;
  return ($args{tag_values}{overnet_ot} // q{}) eq ($args{event_type}{object_type} // q{})
    ? ()
    : ('profile_event.object_type_mismatch');
}

sub _validate_profile_event_required_tags {
  my (%args) = @_;
  my @errors;
  for my $tag (@{$args{event_type}{required_tags} || []}) {
    if (!($args{tag_counts}{$tag})) {
      push @errors, 'profile_event.required_tag_missing';
    }
  }
  return @errors;
}

sub _validate_profile_event_body {
  my (%args) = @_;
  my $body = _event_body($args{content});
  return ref($body) eq 'HASH' && _json_schema_valid($body, $args{event_type}{body_schema})
    ? ()
    : ('profile_event.body_schema_mismatch');
}

sub _validate_profile_event_required_references {
  my (%args) = @_;
  my @errors;
  for my $reference (@{$args{event_type}{references} || []}) {
    if (!(_profile_event_reference_missing($reference, $args{tag_counts}))) {
      next;
    }
    push @errors, 'profile_event.required_reference_tag_missing';
  }
  return @errors;
}

sub _profile_event_reference_missing {
  my ($reference, $tag_counts) = @_;
  if (!(ref($reference) eq 'HASH' && $reference->{required})) {
    return 0;
  }
  my $tag = $reference->{tag};
  return defined $tag && !$tag_counts->{$tag} ? 1 : 0;
}

sub _validate_capabilities {
  my ($profile_contract, $errors) = @_;
  if (!(exists $profile_contract->{capabilities})) {
    return;
  }
  if (!(ref($profile_contract->{capabilities}) eq 'ARRAY')) {
    return push @{$errors}, 'profile_contract.invalid_capabilities';
  }

  my %seen;
  for my $capability (@{$profile_contract->{capabilities}}) {
    if (!_is_profile_scoped_name($capability)) {
      push @{$errors}, 'profile_contract.invalid_capability';
      next;
    }

    if ($seen{$capability}++) {
      push @{$errors}, 'profile_contract.duplicate_capability';
    }
  }
  return;
}

sub _validate_fixtures {
  my ($profile_contract, $errors) = @_;
  if (!(exists $profile_contract->{fixtures})) {
    return;
  }
  if (!(ref($profile_contract->{fixtures}) eq 'HASH')) {
    return push @{$errors}, 'profile_contract.invalid_fixtures';
  }

  _validate_fields($profile_contract->{fixtures},
    \%FIXTURES_FIELD, [qw(valid invalid)], 'profile_contract.invalid_fixtures', $errors,);

  for my $field (qw(valid invalid)) {
    if (!(exists $profile_contract->{fixtures}{$field})) {
      next;
    }
    if (ref($profile_contract->{fixtures}{$field}) ne 'ARRAY') {
      push @{$errors}, 'profile_contract.invalid_fixtures';
      next;
    }

    my %seen;
    for my $path (@{$profile_contract->{fixtures}{$field}}) {
      if (!_is_relative_path($path)) {
        push @{$errors}, 'profile_contract.invalid_fixture_path';
        next;
      }

      if ($seen{$path}++) {
        push @{$errors}, 'profile_contract.duplicate_fixture_path';
      }
    }
  }
  return;
}

sub _validate_extensions {
  my ($extensions, $errors) = @_;
  if (!(ref($extensions) eq 'HASH')) {
    push @{$errors}, 'profile_contract.invalid_extensions';
  }
  return;
}

sub _validate_object_type {
  my ($object_type, $errors) = @_;
  if (!(ref($object_type) eq 'HASH')) {
    return push @{$errors}, 'profile_contract.invalid_object_type';
  }

  _validate_fields(
    $object_type, \%OBJECT_TYPE_FIELD,
    [qw(description id state extensions)],
    'profile_contract.invalid_object_type', $errors,
  );

  if (!(_is_non_empty_string($object_type->{description}))) {
    push @{$errors}, 'profile_contract.invalid_object_type_description';
  }

  _validate_object_id($object_type->{id}, $errors);
  _validate_object_state($object_type->{state}, $errors);
  if (exists $object_type->{extensions}) {
    _validate_extensions($object_type->{extensions}, $errors);
  }
  return;
}

sub _validate_object_id {
  my ($id, $errors) = @_;
  if (!(ref($id) eq 'HASH')) {
    return push @{$errors}, 'profile_contract.invalid_object_id';
  }

  _validate_fields(
    $id, \%OBJECT_ID_FIELD,
    [qw(scheme pattern examples)],
    'profile_contract.invalid_object_id', $errors,
  );

  if (!(_is_non_empty_string($id->{scheme}) && $OBJECT_ID_SCHEME{$id->{scheme}})) {
    push @{$errors}, 'profile_contract.invalid_object_id_scheme';
  }

  if (
    !(
      exists $id->{pattern} && (!defined $id->{pattern}
        || _is_non_empty_string($id->{pattern}))
    )
  ) {
    push @{$errors}, 'profile_contract.invalid_object_id_pattern';
  }

  if (ref($id->{examples}) ne 'ARRAY') {
    push @{$errors}, 'profile_contract.invalid_object_id_examples';
    return;
  }

  for my $example (@{$id->{examples}}) {
    if (!(_is_non_empty_string($example))) {
      push @{$errors}, 'profile_contract.invalid_object_id_examples';
    }
  }
  return;
}

sub _validate_object_state {
  my ($state, $errors) = @_;
  if (!(ref($state) eq 'HASH')) {
    return push @{$errors}, 'profile_contract.invalid_object_state';
  }

  _validate_fields(
    $state, \%OBJECT_STATE_FIELD,
    [qw(derivation state_event_type)],
    'profile_contract.invalid_object_state', $errors,
  );

  if (!(_is_non_empty_string($state->{derivation}) && $STATE_DERIVATION{$state->{derivation}})) {
    push @{$errors}, 'profile_contract.invalid_state_derivation';
  }

  if (
    !(
      exists $state->{state_event_type} && (!defined $state->{state_event_type}
        || _is_non_empty_string($state->{state_event_type}))
    )
  ) {
    push @{$errors}, 'profile_contract.invalid_state_event_type';
  }
  return;
}

sub _validate_event_type {
  my ($profile_contract, $event_type, $object_types, $errors) = @_;
  if (!(ref($event_type) eq 'HASH')) {
    return push @{$errors}, 'profile_contract.invalid_event_type';
  }

  _validate_fields(
    $event_type,
    \%EVENT_TYPE_FIELD,
    [
      qw(description kind object_type required_tags body_schema references state_effect authorization privacy extensions)
    ],
    'profile_contract.invalid_event_type',
    $errors,
  );

  if (!(_is_non_empty_string($event_type->{description}))) {
    push @{$errors}, 'profile_contract.invalid_event_type_description';
  }

  if (_is_json_integer($event_type->{kind})
    && $event_type->{kind} == 7_801) {
    push @{$errors}, 'profile_contract.profile_event_type_uses_core_removal_kind';
  } elsif (!_is_json_integer($event_type->{kind})
    || !_is_event_kind($event_type->{kind})) {
    push @{$errors}, 'profile_contract.invalid_event_kind';
  }

  my $event_object_type = $event_type->{object_type};
  if (!_is_profile_scoped_name($event_object_type)) {
    push @{$errors}, 'profile_contract.invalid_event_object_type';
  } elsif (_is_local_name($profile_contract->{profile}, $event_object_type)) {
    if (!(exists $object_types->{$event_object_type})) {
      push @{$errors}, 'profile_contract.event_object_type_undefined';
    }
  } elsif (!_dependency_for_target($profile_contract, $event_object_type)) {
    push @{$errors}, 'profile_contract.event_object_type_dependency_missing';
  }

  _validate_required_tags($event_type->{required_tags}, $errors);

  if ( ref($event_type->{body_schema}) ne 'HASH'
    || !_is_non_empty_string($event_type->{body_schema}{type})
    || $event_type->{body_schema}{type} ne 'object') {
    push @{$errors}, 'profile_contract.body_schema_not_object';
  }

  _validate_references($profile_contract, $event_type->{references}, $errors);

  if (!(_is_non_empty_string($event_type->{state_effect}) && $STATE_EFFECT{$event_type->{state_effect}})) {
    push @{$errors}, 'profile_contract.invalid_state_effect';
  }

  _validate_authorization($event_type->{authorization}, $errors);

  if (!(_is_non_empty_string($event_type->{privacy}) && $PRIVACY{$event_type->{privacy}})) {
    push @{$errors}, 'profile_contract.invalid_privacy';
  }

  if (exists $event_type->{extensions}) {
    _validate_extensions($event_type->{extensions}, $errors);
  }
  return;
}

sub _validate_authorization {
  my ($authorization, $errors) = @_;
  if (!(ref($authorization) eq 'HASH')) {
    return push @{$errors}, 'profile_contract.invalid_authorization';
  }

  _validate_fields($authorization, \%AUTHORIZATION_FIELD, [qw(model description)],
    'profile_contract.invalid_authorization', $errors,);

  if (!(_is_non_empty_string($authorization->{model}) && $AUTHORIZATION_MODEL{$authorization->{model}})) {
    push @{$errors}, 'profile_contract.invalid_authorization_model';
  }

  if (!(_is_non_empty_string($authorization->{description}))) {
    push @{$errors}, 'profile_contract.invalid_authorization_description';
  }
  return;
}

sub _validate_dependencies {
  my ($profile_contract, $errors) = @_;
  if (!(exists $profile_contract->{depends_on})) {
    return;
  }
  if (!(ref($profile_contract->{depends_on}) eq 'ARRAY')) {
    return push @{$errors}, 'profile_contract.invalid_dependencies';
  }

  my %seen;
  for my $dependency (@{$profile_contract->{depends_on}}) {
    if (ref($dependency) ne 'HASH') {
      push @{$errors}, 'profile_contract.invalid_dependency';
      next;
    }

    _validate_fields($dependency, \%DEPENDENCY_FIELD, [qw(profile version)], 'profile_contract.invalid_dependency',
      $errors,);

    my $profile = $dependency->{profile};

    if (!(_is_profile_name($profile))) {
      push @{$errors}, 'profile_contract.invalid_dependency_profile';
    }

    if ( defined $profile
      && defined $profile_contract->{profile}
      && $profile eq $profile_contract->{profile}) {
      push @{$errors}, 'profile_contract.self_dependency';
    }

    if (defined $profile && $seen{$profile}++) {
      push @{$errors}, 'profile_contract.duplicate_dependency_profile';
    }

    if (!(_is_version_requirement($dependency->{version}))) {
      push @{$errors}, 'profile_contract.invalid_dependency_version';
    }
  }
  return;
}

sub _validate_required_tags {
  my ($required_tags, $errors) = @_;
  if (!(ref($required_tags) eq 'ARRAY')) {
    return push @{$errors}, 'profile_contract.invalid_required_tags';
  }

  my %seen;
  for my $tag (@{$required_tags}) {
    if (!_is_tag_name($tag)) {
      push @{$errors}, 'profile_contract.invalid_required_tag';
      next;
    }

    if ($seen{$tag}++) {
      push @{$errors}, 'profile_contract.duplicate_required_tag';
    }
  }

  for my $tag (sort keys %CORE_REQUIRED_TAG) {
    if (!($seen{$tag})) {
      push @{$errors}, 'profile_contract.required_core_tag_missing';
    }
  }
  return;
}

sub _validate_references {
  my ($profile_contract, $references, $errors) = @_;
  if (!(ref($references) eq 'ARRAY')) {
    return push @{$errors}, 'profile_contract.invalid_references';
  }

  for my $reference (@{$references}) {
    _validate_reference($profile_contract, $reference, $errors);
  }
  return;
}

sub _validate_reference {
  my ($profile_contract, $reference, $errors) = @_;
  if (ref($reference) ne 'HASH') {
    push @{$errors}, 'profile_contract.invalid_reference';
    return;
  }

  _validate_reference_shape($reference, $errors);
  my ($target, $kind) = _reference_target($reference, $errors);
  if (!(defined $target)) {
    return;
  }
  _validate_reference_target_defined($profile_contract, $target, $kind, $errors);
  return;
}

sub _validate_reference_shape {
  my ($reference, $errors) = @_;
  _validate_fields(
    $reference, \%REFERENCE_FIELD,
    [qw(name required tag target_object_type target_event_type)],
    'profile_contract.invalid_reference', $errors,
  );
  if (!(_is_non_empty_string($reference->{name}))) {
    push @{$errors}, 'profile_contract.invalid_reference_name';
  }
  if (!(JSON::is_bool($reference->{required}))) {
    push @{$errors}, 'profile_contract.invalid_reference_required';
  }
  if (exists $reference->{tag} && defined $reference->{tag} && !_is_tag_name($reference->{tag})) {
    push @{$errors}, 'profile_contract.invalid_reference_tag';
  }
  if (JSON::is_bool($reference->{required}) && $reference->{required} && !defined $reference->{tag}) {
    push @{$errors}, 'profile_contract.required_reference_tag_missing';
  }
  return;
}

sub _reference_target {
  my ($reference, $errors) = @_;
  my $target_object_type = $reference->{target_object_type};
  my $target_event_type  = $reference->{target_event_type};
  my $has_object         = defined $target_object_type;
  my $has_event          = defined $target_event_type;

  _validate_reference_target_names($target_object_type, $target_event_type, $errors);
  if ($has_object && $has_event) {
    push @{$errors}, 'profile_contract.reference_target_ambiguous';
    return;
  }
  if (!$has_object && !$has_event) {
    push @{$errors}, 'profile_contract.reference_target_missing';
    return;
  }
  return $has_object ? ($target_object_type, 'object') : ($target_event_type, 'event');
}

sub _validate_reference_target_names {
  my ($target_object_type, $target_event_type, $errors) = @_;
  if (defined $target_object_type && !_is_profile_scoped_name($target_object_type)) {
    push @{$errors}, 'profile_contract.invalid_reference_target_object_type';
  }
  if (defined $target_event_type && !_is_profile_scoped_name($target_event_type)) {
    push @{$errors}, 'profile_contract.invalid_reference_target_event_type';
  }
  return;
}

sub _validate_reference_target_defined {
  my ($profile_contract, $target, $kind, $errors) = @_;
  if (_is_local_name($profile_contract->{profile}, $target)) {
    _validate_local_reference_target($profile_contract, $target, $kind, $errors);
    return;
  }
  if (!_dependency_for_target($profile_contract, $target)) {
    push @{$errors}, 'profile_contract.reference_target_dependency_missing';
  }
  return;
}

sub _validate_local_reference_target {
  my ($profile_contract, $target, $kind, $errors) = @_;
  if ($kind eq 'object' && !exists $profile_contract->{object_types}{$target}) {
    push @{$errors}, 'profile_contract.reference_target_object_type_undefined';
  }
  if ($kind eq 'event' && !exists $profile_contract->{event_types}{$target}) {
    push @{$errors}, 'profile_contract.reference_target_event_type_undefined';
  }
  return;
}

sub _validate_contract_dependencies_in_set {
  my ($profile_contract, $by_profile, $errors) = @_;
  for my $dependency (@{$profile_contract->{depends_on} || []}) {
    my $profile             = $dependency->{profile};
    my $dependency_contract = $by_profile->{$profile};

    if (!$dependency_contract) {
      push @{$errors}, 'profile_contract_set.dependency_missing';
      next;
    }

    if (!(_version_satisfies($dependency_contract->{profile_version}, $dependency->{version}))) {
      push @{$errors}, 'profile_contract_set.dependency_version_unsatisfied';
    }
  }
  return;
}

sub _validate_external_references_in_set {
  my ($profile_contract, $by_profile, $errors) = @_;
  for my $event_type (values %{$profile_contract->{event_types} || {}}) {
    if (!(ref($event_type) eq 'HASH' && ref($event_type->{references}) eq 'ARRAY')) {
      next;
    }

    for my $reference (@{$event_type->{references}}) {
      if (!(ref($reference) eq 'HASH')) {
        next;
      }
      my $target =
        defined $reference->{target_object_type}
        ? $reference->{target_object_type}
        : $reference->{target_event_type};
      if (!(defined $target && !_is_local_name($profile_contract->{profile}, $target))) {
        next;
      }

      my $dependency          = _dependency_for_target($profile_contract, $target);
      my $dependency_contract = $dependency ? $by_profile->{$dependency->{profile}} : undef;
      if (!($dependency_contract)) {
        next;
      }

      if (defined $reference->{target_object_type}
        && !exists $dependency_contract->{object_types}{$target}) {
        push @{$errors}, 'profile_contract_set.reference_target_missing';
      } elsif (defined $reference->{target_event_type}
        && !exists $dependency_contract->{event_types}{$target}) {
        push @{$errors}, 'profile_contract_set.reference_target_missing';
      }
    }
  }
  return;
}

sub _validate_external_event_object_types_in_set {
  my ($profile_contract, $by_profile, $errors) = @_;
  for my $event_type (values %{$profile_contract->{event_types} || {}}) {
    if (!(ref($event_type) eq 'HASH')) {
      next;
    }
    my $target = $event_type->{object_type};
    if (!(defined $target && !_is_local_name($profile_contract->{profile}, $target))) {
      next;
    }

    my $dependency          = _dependency_for_target($profile_contract, $target);
    my $dependency_contract = $dependency ? $by_profile->{$dependency->{profile}} : undef;
    if (!($dependency_contract)) {
      next;
    }

    if (!(exists $dependency_contract->{object_types}{$target})) {
      push @{$errors}, 'profile_contract_set.event_object_type_missing';
    }
  }
  return;
}

sub _event_parts {
  my ($event) = @_;

  if (ref($event) eq 'HASH') {
    return ($event->{kind}, $event->{tags}, $event->{content});
  }

  if ( blessed($event)
    && $event->can('kind')
    && $event->can('tags')
    && $event->can('content')) {
    return ($event->kind, $event->tags, $event->content);
  }

  return;
}

sub _event_tags {
  my ($tags) = @_;
  my (%values, %counts);
  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag})) {
      next;
    }
    $counts{$tag->[0]}++;
    if (@{$tag} >= 2) {
      $values{$tag->[0]} = $tag->[1];
    }
  }

  return (\%values, \%counts);
}

sub _event_body {
  my ($content) = @_;
  my $decoded = eval { $JSON->decode($content) };
  if ($EVAL_ERROR || ref($decoded) ne 'HASH') {
    return;
  }
  return $decoded->{body};
}

sub _json_schema_valid {
  my ($value, $schema) = @_;
  if (!(ref($schema) eq 'HASH')) {
    return 0;
  }
  my $result = eval { $JSON_SCHEMA->evaluate($value, $schema) };
  if ($EVAL_ERROR || !$result) {
    return 0;
  }
  return $result->valid ? 1 : 0;
}

sub _validate_fields {
  my ($value, $allowed, $required, $reason, $errors) = @_;

  for my $field (sort keys %{$value}) {
    if (!($allowed->{$field})) {
      push @{$errors}, $reason;
    }
  }

  for my $field (@{$required}) {
    if (!(exists $value->{$field})) {
      push @{$errors}, $reason;
    }
  }
  return;
}

sub _dependency_for_target {
  my ($profile_contract, $target) = @_;
  my @matches;
  for my $dependency (@{$profile_contract->{depends_on} || []}) {
    if (!(ref($dependency) eq 'HASH')) {
      next;
    }
    my $profile = $dependency->{profile};
    if (!(defined $profile && defined $target)) {
      next;
    }
    if ($target =~ /\A\Q$profile\E\./mxs) {
      push @matches, $dependency;
    }
  }

  if (!(@matches)) {
    return;
  }
  return (sort { length($a->{profile}) <=> length($b->{profile}) } @matches)[-1];
}

sub _is_non_empty_string {
  my ($value) = @_;
  return _is_json_string($value) && length($value) > 0;
}

sub _is_json_string {
  my ($value) = @_;
  if (!(defined($value) && !ref($value))) {
    return 0;
  }
  my $flags = svref_2object(\$value)->FLAGS;
  return ($flags & SVp_POK) && !($flags & (SVp_IOK | SVp_NOK)) ? 1 : 0;
}

sub _is_json_integer {
  my ($value) = @_;
  if (!(defined($value) && !ref($value))) {
    return 0;
  }
  my $flags = svref_2object(\$value)->FLAGS;
  return ($flags & SVp_IOK) && !($flags & (SVp_NOK | SVp_POK)) ? 1 : 0;
}

sub _is_json_number {
  my ($value) = @_;
  if (!(defined($value) && !ref($value))) {
    return 0;
  }
  my $flags = svref_2object(\$value)->FLAGS;
  return ($flags & (SVp_IOK | SVp_NOK)) && !($flags & SVp_POK) ? 1 : 0;
}

sub _is_local_name {
  my ($profile, $name) = @_;
  return
       defined($profile)
    && defined($name)
    && $name =~ /\A\Q$profile\E\./mxs ? 1 : 0;
}

sub _is_profile_name {
  my ($value) = @_;
  return _is_json_string($value)
    && $value =~ /\A[a-z0-9]+(?:[._-][a-z0-9]+)*\z/mxs;
}

sub _is_profile_scoped_name {
  my ($value) = @_;
  return _is_json_string($value)
    && $value =~ /\A[a-z0-9]+(?:[._-][a-z0-9]+)+\z/mxs;
}

sub _is_semver {
  my ($value) = @_;
  return _is_json_string($value) && $value =~ /\A\d+\.\d+\.\d+\z/mxs;
}

sub _is_version_requirement {
  my ($value) = @_;
  if (!(_is_json_string($value))) {
    return 0;
  }
  if (_is_semver($value)) {
    return 1;
  }
  my $operator = qr/(?:=|>=|>|<=|<)/mxs;
  my $version  = qr/\d+\.\d+\.\d+/mxs;
  return $value =~ /\A$operator$version(?:\ $operator$version)?\z/mxs;
}

sub _is_event_kind {
  my ($value) = @_;
  return defined($value) && ($value == 7_800 || $value == 37_800);
}

sub _is_tag_name {
  my ($value) = @_;
  return _is_json_string($value) && $value =~ /\A[A-Za-z0-9_:-]+\z/mxs;
}

sub _is_relative_path {
  my ($value) = @_;
  return
       _is_json_string($value)
    && length($value) > 0
    && $value !~ m{\A/}mxs
    && $value !~ m{(?:\A|/)\.\.(?:/|\z)}mxs;
}

sub _version_satisfies {
  my ($version, $requirement) = @_;
  if (!(_is_semver($version) && _is_version_requirement($requirement))) {
    return 0;
  }
  if (_is_semver($requirement)) {
    return _compare_versions($version, $requirement) == 0;
  }

  for my $term (split /\ /mxs, $requirement) {
    $term =~ /\A(=|>=|>|<=|<)(\d+\.\d+\.\d+)\z/mxs or return 0;
    my ($op, $required) = ($1, $2);
    my $cmp = _compare_versions($version, $required);
    if ($op eq q{=} && $cmp != 0) {
      return 0;
    }
    if ($op eq '>' && $cmp <= 0) {
      return 0;
    }
    if ($op eq '>=' && $cmp < 0) {
      return 0;
    }
    if ($op eq '<' && $cmp >= 0) {
      return 0;
    }
    if ($op eq '<=' && $cmp > 0) {
      return 0;
    }
  }

  return 1;
}

sub _compare_versions {
  my ($version_a, $version_b) = @_;
  my @version_a = split /\./mxs, $version_a;
  my @version_b = split /\./mxs, $version_b;
  for my $i (0 .. 2) {
    if ($version_a[$i] < $version_b[$i]) {
      return -1;
    }
    if ($version_a[$i] > $version_b[$i]) {
      return 1;
    }
  }

  return 0;
}

sub _result {
  my (%args) = @_;
  my $errors = $args{errors} || [];
  my %result = map { $_ => $args{$_} }
    grep { exists $args{$_} } qw(contract contracts by_profile applicable);
  return @{$errors}
    ? {%result, valid => 0, errors => $errors, reason => $errors->[0]}
    : {%result, valid => 1, errors => []};
}

1;

=head1 NAME

Overnet::Core::ProfileContract - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Core::ProfileContract;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 validate_contract

Public API entry point.

=head2 validate_contract_set

Public API entry point.

=head2 validate_profile_event

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
