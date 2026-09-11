package Overnet::Core::Naming::Verifier;

use strictures 2;
use Moo;
use Carp        qw(croak);
use Crypt::PRNG qw(random_bytes);
use JSON        ();
use Overnet::Core::Naming;

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;

has namespace  => (is => 'ro');
has epsilon    => (is => 'ro');
has clock      => (is => 'ro');
has save_state => (is => 'ro');
has _state     => (is => 'ro');
has _pending   => (is => 'ro', default => sub { return {}; });

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args   = _constructor_args(@args);
  my $config = Overnet::Core::Naming->validate_namespace($args{namespace});
  if (!$config->{valid}) {
    croak join(q{; }, @{$config->{errors}});
  }
  if (!_integer($args{epsilon})) {
    croak 'epsilon must be an explicitly configured nonnegative integer';
  }
  for my $callback (qw(load_state save_state)) {
    if (ref($args{$callback}) ne 'CODE') {
      croak "$callback callback is required";
    }
  }
  my $clock = $args{clock} // sub { return time(); };
  if (ref($clock) ne 'CODE') {
    croak 'clock must be a callback';
  }
  my $state = _copy($args{load_state}->());
  _validate_state($state, $args{namespace});
  return {
    namespace  => _copy($args{namespace}),
    epsilon    => 0 + $args{epsilon},
    clock      => $clock,
    save_state => $args{save_state},
    _state     => $state,
  };
}

sub empty_state {
  my ($class, %args) = @_;
  my $config = Overnet::Core::Naming->validate_namespace($args{namespace});
  if (!$config->{valid}) {
    croak join(q{; }, @{$config->{errors}});
  }
  return {version => 1, namespace => _pin($args{namespace}), bindings => {}};
}

sub begin_lookup {
  my ($self, %args) = @_;
  my $identity = Overnet::Core::Naming->binding_id(%{$self->{namespace}}, name => $args{name});
  if (!$identity->{valid}) {
    return $identity;
  }
  my $now = _now($self);
  if (!defined $now) {
    return _failure('unavailable', 'Clock is unavailable');
  }
  for my $nonce (keys %{$self->{_pending}}) {
    if ($self->{_pending}{$nonce}{started_at} + 60 <= $now) {
      delete $self->{_pending}{$nonce};
    }
  }
  if (keys(%{$self->{_pending}}) >= 128) {
    return _failure('unavailable', 'Too many outstanding naming lookups');
  }
  my $nonce = unpack('H*', random_bytes(32));
  $self->{_pending}{$nonce} = {name => $identity->{name}, started_at => $now};
  return {valid => 1, namespace_id => $self->{namespace}{namespace_id}, name => $identity->{name}, nonce => $nonce};
}

sub verify_resolution {
  my ($self, %args) = @_;
  my $nonce = $args{nonce};
  if (!defined($nonce) || ref($nonce) || $nonce !~ /\A[0-9a-f]{64}\z/mxs) {
    return _failure('invalid', 'An outstanding lookup nonce is required');
  }

  # Consume before processing any response, including invalid responses. The
  # caller can start a fresh lookup; the same nonce can never accept twice.
  my $lookup = delete $self->{_pending}{$nonce};
  if (!$lookup) {
    return _failure('invalid', 'Unknown or consumed lookup nonce');
  }
  my $now = _now($self);
  if (!defined($now) || $now < $lookup->{started_at} || $now >= $lookup->{started_at} + 60) {
    return _failure('unavailable', 'Lookup expired or clock moved backwards');
  }
  my $state  = $self->{_state}{bindings}{$lookup->{name}} // {};
  my $result = Overnet::Core::Naming->verify_resolution(
    namespace  => $self->{namespace},
    name       => $lookup->{name},
    nonce      => $nonce,
    now        => $now,
    epsilon    => $self->{epsilon},
    proof      => $args{proof},
    history    => $args{history},
    checkpoint => $state->{checkpoint},
    conflicts  => $state->{conflicts},
  );
  if (!$result->{valid} && $result->{outcome} ne 'conflict') {
    return $result;
  }
  my $next = _copy($state);
  if ($result->{outcome} eq 'conflict') {
    $next->{conflicts} = _copy($result->{conflicts});
  }
  if ($result->{checkpoint}
    && (!$next->{checkpoint} || $result->{checkpoint}{revision} > $next->{checkpoint}{revision})) {
    $next->{checkpoint} = _copy($result->{checkpoint});
  }
  $self->{_state}{bindings}{$lookup->{name}} = $next;
  my $saved = eval { $self->{save_state}->(_copy($self->{_state})); };
  if (!$saved) {

    # Keep evidence in memory even on persistence failure, so the live
    # verifier cannot subsequently accept a rollback or forget a conflict.
    return _failure('unavailable', 'Unable to durably retain naming verification state');
  }
  return $result;
}

sub _constructor_args {
  my (@args) = @_;
  if (@args == 1 && ref($args[0]) eq 'HASH') {
    return %{$args[0]};
  }
  if (@args % 2 == 0) {
    return @args;
  }
  croak 'Constructor arguments must be a hash or hash reference';
}

sub _pin {
  my ($config) = @_;
  return {map { $_ => $config->{$_} } qw(namespace_id normalization irc_network)};
}

sub _validate_state {
  my ($state, $config) = @_;
  if ( ref($state) ne 'HASH'
    || !_integer($state->{version})
    || $state->{version} != 1
    || ref($state->{namespace}) ne 'HASH'
    || $JSON->encode($state->{namespace}) ne $JSON->encode(_pin($config))
    || ref($state->{bindings}) ne 'HASH') {
    croak 'Stored naming state is missing, malformed, or belongs to a different namespace configuration';
  }
  for my $name (keys %{$state->{bindings}}) {
    my $normal = Overnet::Core::Naming->normalize_name(normalization => $config->{normalization}, name => $name);
    my $entry  = $state->{bindings}{$name};
    if (!$normal->{valid} || $normal->{name} ne $name || ref($entry) ne 'HASH') {
      croak 'Stored naming binding is malformed';
    }
    _validate_entry($entry);
  }
  return;
}

sub _validate_entry {
  my ($entry) = @_;
  if (exists $entry->{checkpoint}) {
    my $head = $entry->{checkpoint};
    if ( ref($head) ne 'HASH'
      || !_integer($head->{revision})
      || !$head->{revision}
      || !defined($head->{event_id})
      || ref($head->{event_id})
      || $head->{event_id} !~ /\A[0-9a-f]{64}\z/mxs) {
      croak 'Stored naming checkpoint is malformed';
    }
  }
  if (exists($entry->{conflicts}) && (ref($entry->{conflicts}) ne 'ARRAY' || !@{$entry->{conflicts}})) {
    croak 'Stored naming conflict evidence is malformed';
  }
  return;
}

sub _copy {
  my ($value) = @_;
  return $JSON->decode($JSON->encode($value));
}

sub _integer {
  my ($value) = @_;
  return defined($value) && !ref($value) && $value =~ /\A(?:0|[1-9][0-9]*)\z/mxs && $value <= 9_007_199_254_740_991;
}

sub _now {
  my ($self) = @_;
  my $value = eval { $self->{clock}->(); };
  return _integer($value) ? 0 + $value : undef;
}

sub _failure {
  my ($outcome, $message) = @_;
  return {
    valid   => 0,
    outcome => $outcome,
    errors  => [$message],
    code    => $outcome eq 'invalid' ? 'naming.invalid_record' : "naming.$outcome"
  };
}

1;

=head1 NAME

Overnet::Core::Naming::Verifier - Naming verification with lookup and persistence boundaries

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $verifier = Overnet::Core::Naming::Verifier->new(
    namespace => $pinned_config, epsilon => 2,
    load_state => sub { return $store->load; },
    save_state => sub { return $store->durably_save($_[0]); },
  );
  my $lookup = $verifier->begin_lookup(name => '#Overnet');
  # The caller sends namespace_id, name, and nonce to the registrar.
  my $result = $verifier->verify_resolution(
    nonce => $lookup->{nonce}, proof => $response->{proof},
    history => $response->{history},
  );

=head1 DESCRIPTION

Generates unpredictable lookup nonces, consumes them once, and applies the
shared naming verifier against retained local state. It saves checkpoints and
conflicts before returning successful resolution or conflict results.

=head1 SUBROUTINES/METHODS

=head2 empty_state

Given C<namespace>, explicitly initializes a new store's versioned state.
Use only when provisioning a new verifier, never to hide missing/corrupt state.

=head2 begin_lookup

Given C<name>, returns C<valid>, canonical C<name>, C<namespace_id>, and a
32-byte hex C<nonce>. A lookup lasts 60 seconds. At most 128 may be pending.

=head2 verify_resolution

Given the outstanding C<nonce> and response C<proof> and C<history>, returns
the shared verifier's semantic outcome. Trust, name, clock, and retained state
come from the verifier, never from optional peer assertions. Replays and nonce
reuse fail. A failed response consumes the nonce too.

=head2 namespace

Constructor namespace configuration, copied on construction. Treat the accessor
as read-only; it is local trusted configuration.

=head2 epsilon

Explicit nonnegative integer maximum clock error in seconds.

=head2 clock

Optional constructor callback returning integer Unix time, defaulting to time.
The caller must monitor the configured clock bound and stop use if it is lost.

=head2 save_state

Required callback taking a full state snapshot. It must return true only after
durable persistence and throw or return false on failure. C<load_state> is a
required constructor callback reading that same store; missing/corrupt or
incorrectly pinned state is an error. Storage implementations must preserve all
acknowledged snapshots, reject incomplete recovery, and serialize access with
one owner for this verifier's state. An in-memory callback is suitable for tests
only. Pending nonces are deliberately not restored after restart.

=head1 DIAGNOSTICS

Invalid local construction throws. Lookup, verification, and persistence failures
return structured results without authority. Failed saves retain evidence in
memory; recovery after storage failure must not discard it silently.

=head1 CONFIGURATION AND ENVIRONMENT

No ambient trust or environment configuration is used.

=head1 DEPENDENCIES

Moo, CryptX for random nonces, JSON, and Overnet::Core::Naming.

=head1 INCOMPATIBILITIES

Local state is versioned and pinned to immutable namespace settings.

=head1 BUGS AND LIMITATIONS

This is a verification component, not a network resolver, registrar, or durable
storage backend. It advertises no naming role. Returned results must be checked
against their expiry and the clock bound whenever used; no route caching is
implemented here. It does not establish unrecorded provisioning or fencing facts.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the repository LICENSE file.

=cut
