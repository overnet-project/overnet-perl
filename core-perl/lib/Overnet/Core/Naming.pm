package Overnet::Core::Naming;

use strictures 2;
use B ();
use Crypt::PK::ECC;
use Encode           qw(encode decode FB_CROAK LEAVE_SRC);
use JSON             ();
use Cpanel::JSON::XS ();
use List::Util       qw(any);
use Socket           qw(AF_INET6 inet_pton);
use URI;
use Overnet::Core::Validator;

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;
$JSON->max_depth(64);
my $PARSER = Cpanel::JSON::XS->new->utf8;
$PARSER->allow_dupkeys(0);
$PARSER->max_depth(64);
my $MAX_INTEGER = 9_007_199_254_740_991;
my $MAX_BYTES   = 1_048_576;
my $MAX_HISTORY = 1024;
my %FIELDS      = (
  'naming.change' => [
    qw(version namespace_id name revision previous expires_at object_type object_id profile status controllers authority read_relays profile_data)
  ],
  'naming.binding'    => [qw(version request object_id)],
  'naming.resolution' => [qw(version namespace_id name nonce head revision expires_at)],
);

sub validate_namespace {
  my ($class, $config) = @_;
  return _config($config);
}

sub normalize_name {
  my ($class, %args) = @_;
  my $rule = $args{normalization};
  if (!_string($rule) || ($rule ne 'exact-utf8-v1' && $rule ne 'irc-rfc1459-v1')) {
    return _failure('unsupported', 'Unknown normalization rule');
  }
  my $name = $args{name};
  if (!_string($name)) {
    return _failure('invalid', 'Name must be a string');
  }
  my $bytes;
  my $ok = eval {
    $bytes = utf8::is_utf8($name) ? encode('utf8', $name, FB_CROAK | LEAVE_SRC) : $name;
    $name  = decode('utf8', $bytes, FB_CROAK | LEAVE_SRC);
    1;
  };
  if (!$ok || $name =~ /[^\x{0}-\x{d7ff}\x{e000}-\x{10ffff}]/mxs) {
    return _failure('invalid', 'Name must contain valid UTF-8 scalar values');
  }
  if ($rule eq 'exact-utf8-v1') {
    if (!length($bytes) || length($bytes) > 255 || $name =~ /[\x00-\x1f\x7f]/mxs) {
      return _failure('invalid', 'Name is outside exact-utf8-v1 limits');
    }
  } else {
    if (length($bytes) < 2 || length($bytes) > 50 || $name !~ /\A\#[\x21-\x7e]+\z/mxs || $name =~ /[,:]/mxs) {
      return _failure('invalid', 'Name is outside irc-rfc1459-v1 limits');
    }
    $name =~ tr/A-Z[]\\^/a-z{}|~/;
  }
  return {valid => 1, name => $name};
}

sub binding_id {
  my ($class, %args) = @_;
  if (!_namespace_id($args{namespace_id})) {
    return _failure('untrusted', 'A pinned namespace ID is required');
  }
  my $result = $class->normalize_name(%args);
  if (!$result->{valid}) {
    return $result;
  }
  my $key   = substr($args{namespace_id}, 3);
  my $bytes = encode('utf8', $result->{name}, FB_CROAK | LEAVE_SRC);
  return {%{$result}, binding_id => 'urn:overnet:name:' . $key . q{:} . unpack('H*', $bytes)};
}

sub verify_record {
  my ($class, %args) = @_;
  my $config = _config($args{namespace});
  if (!$config->{valid}) {
    return $config;
  }
  my $wire = _wire($args{event});
  if (!$wire->{valid}) {
    return $wire;
  }
  my $event = $wire->{event};
  my $payload;
  my $ok = eval { $payload = _decode_json($event->{content}); 1; };
  if (!$ok || ref($payload) ne 'HASH' || ref($payload->{body}) ne 'HASH') {
    return _failure('invalid', 'Content must be an unambiguous JSON object with a body');
  }
  my $core = Overnet::Core::Validator::validate($event);
  if (!$core->{valid}) {
    return _failure('invalid', 'Invalid signed core event: ' . join(q{; }, @{$core->{errors}}));
  }
  my %tags = map { $_->[0] => $_->[1] } @{$event->{tags}};
  my $type = $tags{overnet_et};
  if ( !exists $FIELDS{$type}
    || $tags{overnet_v} ne '0.1.0'
    || $tags{overnet_ot} ne 'naming.binding'
    || $payload->{provenance}{type} ne 'native') {
    return _failure('invalid', 'Record requires a native naming event with core version 0.1.0');
  }
  my $body = $payload->{body};
  if (!_fields($body, @{$FIELDS{$type}}) || !_integer($body->{version}, 1) || $body->{version} != 1) {
    return _failure('invalid', 'Incorrect naming body fields or version');
  }
  my $signed = {valid => 1, event => $event, body => $body, type => $type, binding_id => $tags{overnet_oid}};
  if ($type eq 'naming.binding') {
    return _binding($signed, $args{namespace});
  }
  my $identity = _identity($signed, $args{namespace});
  if (!$identity->{valid}) {
    return $identity;
  }
  if ($type eq 'naming.change') {
    return _change($signed, $args{namespace});
  }
  return _proof($signed, $args{namespace});
}

sub verify_history {
  my ($class, %args) = @_;
  if (ref($args{history}) ne 'ARRAY' || !@{$args{history}}) {
    return _failure('unavailable', 'Complete binding history is required');
  }
  if (@{$args{history}} > $MAX_HISTORY) {
    return _failure('unavailable', 'History exceeds the verification limit');
  }
  if (!_hex($args{head}, 64)) {
    return _failure('invalid', 'A head event ID is required');
  }
  my (%records, %failures);
  for my $input (@{$args{history}}) {
    my $result = $class->verify_record(event => $input, namespace => $args{namespace});
    if ($result->{valid} && $result->{type} eq 'naming.binding') {
      $records{$result->{event}{id}} = $result;
      next;
    }
    my $wire = _wire($input);
    if ($wire->{valid}) {
      $failures{$wire->{event}{id}} =
        $result->{valid} ? _failure('invalid', 'History requires binding commits') : $result;
    } elsif (ref($input) eq 'HASH' && _hex($input->{id}, 64)) {
      $failures{$input->{id}} = $wire;
    }
  }
  my $chain = _chain($args{head}, \%records, \%failures);
  if (!$chain->{valid}) {
    return $chain;
  }
  if (defined($args{binding_id}) && $chain->{binding}{binding_id} ne $args{binding_id}) {
    return _failure('invalid', 'History belongs to a different requested binding');
  }
  return _check_branches($chain, \%records, \%failures);
}

sub _check_branches {
  my ($chain, $records, $failures) = @_;

  # Only complete, authorized branches count as conflict evidence. A signed
  # but unauthorized successor, or unrelated forged relay noise, cannot poison it.
  my %chosen      = map { $_->{event}{id}               => 1 } @{$chain->{records}};
  my %by_revision = map { $_->{request}{body}{revision} => $_ } @{$chain->{records}};
  my $highest     = $chain->{binding};
  for my $id (sort keys %{$records}) {
    if ($chosen{$id} || $records->{$id}{binding_id} ne $chain->{binding}{binding_id}) {
      next;
    }
    my $other = _chain($id, $records, $failures);
    if (!$other->{valid}) {
      next;
    }
    for my $signed (@{$other->{records}}) {
      my $same = $by_revision{$signed->{request}{body}{revision}};
      if ($same && $same->{event}{id} ne $signed->{event}{id}) {
        return _conflict('Registrar signed competing valid histories', [$same->{event}, $signed->{event}]);
      }
      $by_revision{$signed->{request}{body}{revision}} = $signed;
      if ($signed->{request}{body}{revision} > $highest->{request}{body}{revision}) {
        $highest = $signed;
      }
    }
  }
  $chain->{highest_binding} = $highest;
  return $chain;
}

sub verify_resolution {
  my ($class, %args) = @_;
  my $config = _config($args{namespace});
  if (!$config->{valid}) {
    return $config;
  }
  my $identity = $class->binding_id(%{$args{namespace}}, name => $args{name});
  if (!$identity->{valid}) {
    return $identity;
  }
  if (ref($args{conflicts}) eq 'ARRAY' && @{$args{conflicts}}) {
    return _conflict('A retained conflict requires explicit recovery', $args{conflicts});
  }
  if (!defined $args{proof}) {
    return _failure('unavailable', 'A signed current-head proof is required');
  }
  my $proof = _lookup_proof(\%args, $identity);
  if (!$proof->{valid}) {
    return $proof;
  }
  my $body       = $proof->{body};
  my $checkpoint = $args{checkpoint};
  if (defined($checkpoint) && !_checkpoint($checkpoint)) {
    return _failure('unavailable', 'Retained checkpoint is malformed');
  }
  my %common = (
    valid        => 1,
    namespace_id => $body->{namespace_id},
    name         => $body->{name},
    proof        => $proof->{event},
    expires_at   => $body->{expires_at},
  );
  if (!defined $body->{head}) {
    return _absence(\%args, $proof, \%common);
  }
  my $chain = $class->verify_history(%args, head => $body->{head}, binding_id => $identity->{binding_id});
  if (!$chain->{valid}) {
    return $chain;
  }
  my $binding = $chain->{binding};
  if ( $binding->{binding_id} ne $identity->{binding_id}
    || $chain->{checkpoint}{revision} != $body->{revision}
    || $binding->{event}{created_at} > $proof->{event}{created_at}) {
    return _failure('invalid', 'Proof does not match the verified history head');
  }
  my $highest = $chain->{highest_binding};
  if ($highest->{request}{body}{revision} > $body->{revision}) {
    return _conflict(
      'Proof predates a newer verified binding',
      [$proof->{event}, $highest->{event}],
      {revision => $highest->{request}{body}{revision}, event_id => $highest->{event}{id}}
    );
  }
  if ($checkpoint) {
    my $retained = $chain->{records}[$checkpoint->{revision} - 1];
    if (!$retained || $retained->{event}{id} ne $checkpoint->{event_id}) {
      return _conflict('Current history does not descend from the retained head',
        [$proof->{event}, $binding->{event}], $checkpoint);
    }
  }
  my $assignment = $binding->{request}{body};
  my $outcome    = $assignment->{status} eq 'active' ? 'resolved' : $assignment->{status};
  return {
    %common,
    outcome    => $outcome,
    binding    => $binding->{event},
    object_id  => $binding->{body}{object_id},
    checkpoint => $chain->{checkpoint},
    ($outcome eq 'resolved' ? (authority => $assignment->{authority}) : ()),
  };
}

sub _lookup_proof {
  my ($args, $identity) = @_;
  if (!_integer($args->{now}, 0) || !_integer($args->{epsilon}, 0) || !_hex($args->{nonce}, 64)) {
    return _failure('invalid', 'Lookup requires a nonce, current time, and clock-error bound');
  }
  my $proof = __PACKAGE__->verify_record(event => $args->{proof}, namespace => $args->{namespace});
  if (!$proof->{valid}) {
    return $proof;
  }
  if ($proof->{type} ne 'naming.resolution' || $proof->{binding_id} ne $identity->{binding_id}) {
    return _failure('invalid', 'Proof does not identify the requested binding');
  }
  if ($proof->{body}{nonce} ne $args->{nonce} || $proof->{event}{created_at} > $args->{now} + 2 * $args->{epsilon}) {
    return _failure('invalid', 'Proof nonce or creation time does not match the lookup');
  }
  if ($args->{now} + $args->{epsilon} >= $proof->{body}{expires_at}) {
    return _failure('unavailable', 'Proof has expired under the clock-error bound');
  }
  return $proof;
}

sub _absence {
  my ($args, $proof, $common) = @_;
  if ($args->{checkpoint}) {
    return _conflict('Registrar reported absence after registration', [$proof->{event}], $args->{checkpoint});
  }
  if (ref($args->{history}) ne 'ARRAY' || @{$args->{history}} > $MAX_HISTORY) {
    return _failure('unavailable', 'An absence response requires a bounded evidence array');
  }
  for my $input (@{$args->{history}}) {
    my $signed = __PACKAGE__->verify_record(namespace => $args->{namespace}, event => $input);
    if (!$signed->{valid} || $signed->{type} ne 'naming.binding' || $signed->{binding_id} ne $proof->{binding_id}) {
      next;
    }
    my $chain = __PACKAGE__->verify_history(%{$args}, head => $signed->{event}{id});
    if ($chain->{valid}) {
      return _conflict(
        'Absence contradicts a verified registration',
        [$proof->{event}, $signed->{event}],
        $chain->{checkpoint}
      );
    }
    if ($chain->{outcome} eq 'conflict') {
      return $chain;
    }
  }
  return {%{$common}, outcome => 'not_found'};
}

sub _config {
  my ($config) = @_;
  if (ref($config) ne 'HASH' || !_namespace_id($config->{namespace_id}) || !_pubkey(substr($config->{namespace_id}, 3)))
  {
    return _failure('untrusted', 'Explicit namespace configuration is required');
  }
  my $normal = __PACKAGE__->normalize_name(normalization => $config->{normalization}, name => '#validation');
  if (!$normal->{valid}) {
    return $normal;
  }
  if (!_url($config->{registrar_url}, $config, 'registrar')) {
    return _failure('invalid', 'Registrar URL must be explicitly configured and canonical');
  }
  return {valid => 1};
}

sub _wire {
  my ($input) = @_;
  my $event;
  my $ok = eval {
    my $json = ref($input) eq 'HASH' ? $JSON->encode($input) : $input;
    $event = _decode_json($json);
    1;
  };
  if (!$ok || !_fields($event, qw(id pubkey created_at kind tags content sig))) {
    return _failure('invalid', 'Event must be a bounded JSON object with exactly the signed wire fields');
  }
  if ( !_hex($event->{id}, 64)
    || !_hex($event->{pubkey}, 64)
    || !_hex($event->{sig},    128)
    || !_integer($event->{created_at}, 0)
    || !_integer($event->{kind},       0)
    || $event->{kind} != 7800
    || !_string($event->{content})
    || ref($event->{tags}) ne 'ARRAY') {
    return _failure('invalid', 'Invalid naming wire event field types');
  }
  for my $tag (@{$event->{tags}}) {
    if (ref($tag) ne 'ARRAY' || !@{$tag} || any { !_string($_) } @{$tag}) {
      return _failure('invalid', 'Tags must be nonempty arrays of strings');
    }
  }
  return {valid => 1, event => $event};
}

sub _decode_json {
  my ($text) = @_;
  if (!_string($text) || length($text) > $MAX_BYTES) {
    return;
  }
  my $bytes = utf8::is_utf8($text) ? encode('utf8', $text, FB_CROAK | LEAVE_SRC) : $text;
  if (length($bytes) > $MAX_BYTES) {
    return;
  }
  return $PARSER->decode($bytes);
}

sub _identity {
  my ($signed, $config) = @_;
  my $body = $signed->{body};
  if (!_namespace_id($body->{namespace_id}) || $body->{namespace_id} ne $config->{namespace_id}) {
    return _failure('untrusted', 'Record belongs to an unselected namespace');
  }
  my $identity = __PACKAGE__->binding_id(%{$config}, name => $body->{name});
  if (!$identity->{valid}) {
    return $identity;
  }
  if ($identity->{name} ne $body->{name} || $identity->{binding_id} ne $signed->{binding_id}) {
    return _failure('invalid', 'Signed name and binding identifier must be canonical and match');
  }
  return {valid => 1};
}

sub _change {
  my ($signed, $config) = @_;
  my $body = $signed->{body};
  if ( !_integer($body->{revision}, 1)
    || !_integer($body->{expires_at}, 0)
    || $body->{expires_at} < $signed->{event}{created_at}
    || $body->{expires_at} > $signed->{event}{created_at} + 300
    || !_string($body->{status})
    || !any { $body->{status} eq $_ } qw(active suspended retired)) {
    return _failure('invalid', 'Invalid revision, request validity interval, or status');
  }
  if (ref($body->{controllers}) ne 'ARRAY' || !@{$body->{controllers}}) {
    return _failure('invalid', 'Controllers must be a nonempty sorted set');
  }
  my $controllers = _controllers($body->{controllers});
  if (!$controllers->{valid}) {
    return $controllers;
  }
  my $authority = _authority($body, $config);
  if (!$authority->{valid}) {
    return $authority;
  }
  if ($body->{revision} == 1) {
    if ( defined $body->{previous}
      || defined $body->{object_id}
      || $body->{status} ne 'active'
      || !any { $_ eq $signed->{event}{pubkey} } @{$body->{controllers}}) {
      return _failure('invalid', 'Registration requires null predecessor/target and its requester as a controller');
    }
  } elsif (!_hex($body->{previous}, 64) || !_target($body->{object_id})) {
    return _failure('invalid', 'Updates require a predecessor and stable target identifier');
  }
  return _irc_profile($signed, $config);
}

sub _controllers {
  my ($controllers) = @_;
  my $previous_key = q{};
  for my $key (@{$controllers}) {
    if (!_pubkey($key) || $key le $previous_key) {
      return _failure('invalid', 'Controller keys must be lowercase, unique, and sorted');
    }
    $previous_key = $key;
  }
  return {valid => 1};
}

sub _authority {
  my ($body, $config) = @_;
  if ( !_fields($body->{authority}, qw(pubkey relay_url))
    || !_pubkey($body->{authority}{pubkey})
    || !_url($body->{authority}{relay_url}, $config, 'relay')
    || ref($body->{read_relays}) ne 'ARRAY') {
    return _failure('invalid', 'Invalid hosting authority or read sources');
  }
  my %seen = ($body->{authority}{relay_url} => 1);
  for my $url (@{$body->{read_relays}}) {
    if (!_url($url, $config, 'relay') || $seen{$url}++) {
      return _failure('invalid', 'Read sources must be distinct canonical relay URLs');
    }
  }
  return {valid => 1};
}

sub _irc_profile {
  my ($signed, $config) = @_;
  my $body = $signed->{body};
  if ( !_string($body->{profile})
    || !length($body->{profile})
    || !_string($body->{object_type})
    || !length($body->{object_type})
    || ref($body->{profile_data}) ne 'HASH') {
    return _failure('invalid', 'Profile, object type, and profile data are required');
  }
  if ($body->{profile} ne 'irc.naming.nip29.v1') {
    return _failure('unsupported', 'Unsupported application binding profile');
  }
  my $fields = _irc_fields($body, $config);
  if (!$fields->{valid}) {
    return $fields;
  }
  my $data = $body->{profile_data};
  my $network;
  my $ok = eval { $network = encode('utf8', $data->{network}, FB_CROAK | LEAVE_SRC); 1; };
  if (!$ok || length($network) > 255) {
    return _failure('invalid', 'IRC network exceeds UTF-8 limits');
  }
  my $group = 'irc-' . unpack('H*', $network) . q{-} . unpack('H*', $body->{name});
  if ($data->{group_id} ne $group || ($body->{revision} == 1 && $data->{bootstrap_pubkey} ne $signed->{event}{pubkey}))
  {
    return _failure('invalid', 'IRC group ID or bootstrap actor does not match registration');
  }
  return $signed;
}

sub _irc_fields {
  my ($body, $config) = @_;
  my $data = $body->{profile_data};
  if ( $config->{normalization} ne 'irc-rfc1459-v1'
    || $body->{object_type} ne 'chat.channel'
    || !_fields($data, qw(network group_id bootstrap_pubkey))
    || !_string($data->{network})
    || !_string($config->{irc_network})
    || $data->{network} ne $config->{irc_network}
    || !length($data->{network})
    || $data->{network} =~ /[\x00-\x20\x7f\/:]/mxs
    || !_pubkey($data->{bootstrap_pubkey})
    || !_string($data->{group_id})) {
    return _failure('invalid', 'Invalid IRC binding or pinned network label');
  }
  return {valid => 1};
}

sub _binding {
  my ($signed, $config) = @_;
  if ($signed->{event}{pubkey} ne substr($config->{namespace_id}, 3)) {
    return _failure('untrusted', 'Commit signer is not the pinned registrar');
  }

  # Parse the embedded request directly, never recursively accept a binding.
  my $wire = _wire($signed->{body}{request});
  if (!$wire->{valid}) {
    return $wire;
  }
  my @types = grep { $_->[0] eq 'overnet_et' } @{$wire->{event}{tags}};
  if (@types != 1 || $types[0][1] ne 'naming.change') {
    return _failure('invalid', 'Commit must embed a change request');
  }
  my $request = __PACKAGE__->verify_record(event => $wire->{event}, namespace => $config);
  if (!$request->{valid}) {
    return $request;
  }
  my $body       = $request->{body};
  my $target     = $body->{revision} == 1 ? 'urn:overnet:object:' . $request->{event}{id} : $body->{object_id};
  my @references = grep { $_->[0] eq 'e' } @{$signed->{event}{tags}};
  if ( $signed->{binding_id} ne $request->{binding_id}
    || !_target($signed->{body}{object_id})
    || $signed->{body}{object_id} ne $target
    || @references != 1
    || !defined($references[0][1])
    || $references[0][1] ne $request->{event}{id}
    || $signed->{event}{created_at} < $request->{event}{created_at}
    || $signed->{event}{created_at} > $body->{expires_at}) {
    return _failure('invalid', 'Commit does not match its request, target, reference, or validity interval');
  }
  return {%{$signed}, request => $request};
}

sub _proof {
  my ($signed, $config) = @_;
  my $body = $signed->{body};
  if ($signed->{event}{pubkey} ne substr($config->{namespace_id}, 3)) {
    return _failure('untrusted', 'Proof signer is not the pinned registrar');
  }
  if ( !_hex($body->{nonce}, 64)
    || !_integer($body->{revision},   0)
    || !_integer($body->{expires_at}, 0)
    || $body->{expires_at} <= $signed->{event}{created_at}
    || $body->{expires_at} > $signed->{event}{created_at} + 60) {
    return _failure('invalid', 'Invalid proof nonce, revision, or validity interval');
  }
  if (defined $body->{head} ? (!_hex($body->{head}, 64) || $body->{revision} == 0) : $body->{revision} != 0) {
    return _failure('invalid', 'Proof head and revision are inconsistent');
  }
  return $signed;
}

sub _chain {
  my ($head, $records, $failures) = @_;
  my (@reverse, %seen);
  my $id = $head;
  while (defined $id) {
    if ($seen{$id}++) {
      return _failure('invalid', 'Cyclic binding history');
    }
    my $signed = $records->{$id};
    if (!$signed) {
      return $failures->{$id} || _failure('unavailable', 'A required predecessor is absent');
    }
    push @reverse, $signed;
    $id = $signed->{request}{body}{previous};
  }
  my @ordered = reverse @reverse;
  my $previous;
  for my $signed (@ordered) {
    my $result = _transition($previous, $signed);
    if (!$result->{valid}) {
      return $result;
    }
    $previous = $signed;
  }
  return {
    valid      => 1,
    records    => \@ordered,
    binding    => $previous,
    checkpoint => {revision => $previous->{request}{body}{revision}, event_id => $previous->{event}{id}},
  };
}

sub _transition {
  my ($previous, $signed) = @_;
  my $body = $signed->{request}{body};
  if (!$previous) {
    return $body->{revision} == 1 ? {valid => 1} : _failure('unavailable', 'Registration is missing');
  }
  my $prior = $previous->{request}{body};
  if ( $body->{revision} != $prior->{revision} + 1
    || $body->{previous} ne $previous->{event}{id}
    || $signed->{event}{created_at} < $previous->{event}{created_at}) {
    return _failure('invalid', 'Revision, predecessor, or commit time does not follow prior history');
  }
  if (!any { $_ eq $signed->{request}{event}{pubkey} } @{$prior->{controllers}}) {
    return _failure('invalid', 'Change is not authorized by a prior controller', 'naming.unauthorized');
  }
  for my $field (qw(namespace_id name object_type profile)) {
    if ($body->{$field} ne $prior->{$field}) {
      return _failure('invalid', 'Change modifies an immutable identity field');
    }
  }
  if ( $signed->{body}{object_id} ne $previous->{body}{object_id}
    || $JSON->encode($body->{profile_data}) ne $JSON->encode($prior->{profile_data})) {
    return _failure('invalid', 'Change modifies the target or immutable IRC profile data');
  }
  if ($prior->{status} eq 'retired') {
    return _failure('invalid', 'Retirement is terminal', 'naming.transition_denied');
  }
  if (!($prior->{status} eq 'suspended' && $body->{status} eq 'active')
    && $JSON->encode($body->{authority}) ne $JSON->encode($prior->{authority})) {
    return _failure('invalid', 'Authority may change only on suspended-to-active transition',
      'naming.transition_denied');
  }
  return {valid => 1};
}

sub _url {
  my ($url, $config, $role) = @_;
  if (!_string($url) || $url =~ /[^\x21-\x7e]|[\\\#]/mxs || $url =~ /%(?![0-9a-fA-F]{2})/mxs) {
    return 0;
  }
  my $uri;
  my $ok = eval { $uri = URI->new($url); 1; };
  if (!$ok || !$uri->can('host') || !$uri->can('userinfo') || $uri->as_string ne $url) {
    return 0;
  }
  my $scheme = $uri->scheme // q{};
  my $allowed =
    $role eq 'registrar' ? ($scheme eq 'http' || $scheme eq 'https') : ($scheme eq 'ws' || $scheme eq 'wss');
  if (!$allowed || defined($uri->userinfo) || defined($uri->fragment) || !defined($uri->host) || !length($uri->host)) {
    return 0;
  }
  if (!_transport_allowed($url, $scheme, $config)) {
    return 0;
  }
  if ($role eq 'registrar' && defined($uri->query)) {
    return 0;
  }
  return _canonical_url($url, $uri);
}

sub _transport_allowed {
  my ($url, $scheme, $config) = @_;
  if (
    ($scheme eq 'http' || $scheme eq 'ws')
    && !(
      ref($config->{local_plaintext_urls}) eq 'ARRAY' && any { _string($_) && $_ eq $url }
      @{$config->{local_plaintext_urls}}
    )
  ) {
    return 0;
  }
  return 1;
}

sub _canonical_url {
  my ($url, $uri) = @_;
  my $scheme    = $uri->scheme;
  my $authority = $uri->authority;

  # URI parsing is reused, but path/query escapes are intentionally untouched.
  # The naming profile does not permit URI->canonical to rewrite those bytes.
  if ($authority ne lc($authority) || $url !~ /\A(?:https?|wss?):\/\//mxs || !length($uri->path)) {
    return 0;
  }
  if (substr($authority, 0, 1) eq '[' && !inet_pton(AF_INET6, $uri->host)) {
    return 0;
  }
  if (substr($authority, 0, 1) ne '[' && $uri->host =~ /[\[\]:]/mxs) {
    return 0;
  }
  my $default = ($scheme eq 'https' || $scheme eq 'wss') ? 443 : 80;
  if ($authority =~ /:(\d+)\z/mxs) {
    my $port = $1;
    if ($port == $default || $port < 1 || $port > 65_535 || "$port" ne q{} . (0 + $port)) {
      return 0;
    }
  } elsif ($authority =~ /:/mxs && $authority !~ /\]\z/mxs) {
    return 0;
  }
  return 1;
}

sub _pubkey {
  my ($value) = @_;
  if (!_hex($value, 64)) {
    return 0;
  }
  my $ok = eval {
    my $key = Crypt::PK::ECC->new;
    $key->import_key_raw(pack('H*', '02' . $value), 'secp256k1');
    1;
  };
  return $ok ? 1 : 0;
}

sub _fields {
  my ($hash, @fields) = @_;
  return ref($hash) eq 'HASH' && keys(%{$hash}) == @fields && !any { !exists $hash->{$_} } @fields;
}

sub _string {
  my ($value) = @_;
  return defined($value) && !ref($value) && (B::svref_2object(\$value)->FLAGS & B::SVp_POK()) ? 1 : 0;
}

sub _integer {
  my ($value, $minimum) = @_;
  return
       defined($value)
    && !ref($value)
    && (B::svref_2object(\$value)->FLAGS & B::SVp_IOK())
    && $value >= $minimum
    && $value <= $MAX_INTEGER ? 1 : 0;
}

sub _hex {
  my ($value, $length) = @_;
  return _string($value) && length($value) == $length && $value =~ /\A[0-9a-f]+\z/mxs ? 1 : 0;
}

sub _namespace_id {
  my ($value) = @_;
  return _string($value) && $value =~ /\Ans:[0-9a-f]{64}\z/mxs ? 1 : 0;
}

sub _target {
  my ($value) = @_;
  return _string($value) && $value =~ /\Aurn:overnet:object:[0-9a-f]{64}\z/mxs ? 1 : 0;
}

sub _checkpoint {
  my ($value) = @_;
  return _fields($value, qw(revision event_id)) && _integer($value->{revision}, 1) && _hex($value->{event_id}, 64);
}

sub _failure {
  my ($outcome, $message, $code) = @_;
  return {
    valid   => 0,
    outcome => $outcome,
    code    => $code // ($outcome eq 'invalid' ? 'naming.invalid_record' : "naming.$outcome"),
    errors  => [$message]
  };
}

sub _conflict {
  my ($message, $evidence, $checkpoint) = @_;
  return {
    %{_failure('conflict', $message)},
    conflicts => $evidence,
    (defined($checkpoint) ? (checkpoint => $checkpoint) : ())
  };
}

1;

=head1 NAME

Overnet::Core::Naming - Verify signed naming records and authority histories

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $result = Overnet::Core::Naming->verify_record(
    namespace => $pinned_config, event => $signed_event,
  );

=head1 DESCRIPTION

Pure verification helpers for naming v1 and its IRC binding. All wire events
and embedded requests undergo core and cryptographic verification. No peer may
supply a preverified flag. Unknown profiles return C<unsupported>.

=head1 SUBROUTINES/METHODS

=head2 validate_namespace

Accepts the pinned configuration hash. Checks the namespace, normalization,
and registrar endpoint without consulting discovery or accessing the network.

=head2 normalize_name

Accepts C<normalization> and C<name> (UTF-8 bytes or Perl characters). Returns
C<valid> and canonical C<name>, or C<outcome>, C<code>, and C<errors> on failure.

=head2 binding_id

Also accepts C<namespace_id>; adds the canonical C<binding_id> to that result.

=head2 verify_record

Accepts C<event> (a wire hash or JSON) and trusted C<namespace> configuration:
C<namespace_id>, C<normalization>, C<registrar_url>, and C<irc_network> for IRC.
C<local_plaintext_urls> explicitly allows exact local HTTP/WS endpoints.
Returns C<valid>, C<event>, C<body>, C<type>, C<binding_id>, and the verified
embedded C<request> for commits. Individual commits do not establish ancestry,
current authority, or operational provisioning.

=head2 verify_history

Accepts C<namespace>, C<history> (an evidence array), and C<head> event ID.
Reconstructs and checks the complete chain, independent of delivery order.
Returns C<records>, C<binding>, and C<checkpoint> (C<revision>, C<event_id>).
Unrelated forged evidence is ignored; required forged evidence is invalid.
Competing complete authorized branches return C<conflict> with signed evidence.

=head2 verify_resolution

Accepts C<namespace>, C<name>, C<proof>, C<history>, C<nonce>, integer Unix
C<now>, and nonnegative integer C<epsilon>. Optional C<checkpoint> and
C<conflicts> are trusted local state, never response fields. Returns the naming
semantic C<outcome>; only C<resolved> includes C<authority>. Positive results
include C<proof>, C<expires_at>, and, for registered names, C<binding>,
C<object_id>, and C<checkpoint>. Absence does not reserve a name.

This pure helper does not consume nonces or persist results. Use
L<Overnet::Core::Naming::Verifier> to enforce lookup lifetime and persistence
before exposing a result. Historical requests are checked at commit time.

=head1 DIAGNOSTICS

Untrusted evidence returns structured failures. Resource limits are one MiB
per encoded event/content, depth 64, and 1024 history entries. Exceeding limits
never establishes absence. Malformed local configuration also fails closed.

=head1 CONFIGURATION AND ENVIRONMENT

Trust and plaintext exceptions come only from explicit caller configuration.

=head1 DEPENDENCIES

Core validation, Cpanel::JSON::XS with duplicate keys forbidden, JSON, and URI.

=head1 INCOMPATIBILITIES

No automatic adoption of legacy IRC identifiers or unknown application profiles.

=head1 BUGS AND LIMITATIONS

Does not implement registrar transactions, network lookup, storage, host
provisioning, or clock monitoring. Signatures cannot prove past fencing or
destination recovery, or expose equivocation never observed by the consumer.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the repository LICENSE file.

=cut
