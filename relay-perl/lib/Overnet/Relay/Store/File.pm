package Overnet::Relay::Store::File;

use strictures 2;
use Moo;

extends 'Overnet::Relay::Store';

use Carp           qw(croak);
use English        qw(-no_match_vars);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use JSON           ();
use IO::Handle     ();
use File::Temp     qw(tempfile);
use Overnet::Core::Nostr::Event;
use Net::Nostr::Event;
use Overnet::Core::JSON ();

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;

# Persistence is an append-structured log so that storing N events costs O(N)
# total instead of O(N^2): each accepted event or deletion appends one record
# rather than rewriting the whole store. The log is periodically compacted back
# to one record per live event so the file stays bounded under churn.
my $COMPACT_MIN_RECORDS = 128;
my $COMPACT_LIVE_FACTOR = 2;

has path => (is => 'rw');

around new => sub {
  my ($orig, $class, @args) = @_;
  my %args = _constructor_args_hash(@args);
  my $path = delete $args{path};

  if (!(defined $path && !ref($path) && length($path))) {
    croak 'path is required';
  }

  my $self = $class->SUPER::new(\%args);
  $self->path($path);
  $self->{_records_on_disk} = 0;
  $self->{_needs_rewrite}   = 0;
  $self->_load_from_disk;
  return $self;
};

for my $method (
  qw(store delete_by_id clear query all_events get_by_id find_addressable find_replaceable acceptance_for discarded_state discarded_removal)
) {
  around $method => sub {
    my ($orig, $self, @args) = @_;
    croak 'Relay store is unavailable after a persistence failure; reopen it' if $self->{_write_failed};
    return $self->$orig(@args);
  };
}

no Moo;

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub store {
  my ($self, $event, $accepted_at) = @_;
  return 0 if $self->get_by_id($event->id);
  $self->_persist_record([q{+}, $event->to_hash, $accepted_at]);
  local $self->{_storing} = 1;    ## no critic (Variables::ProhibitLocalVars) -- Restore the nested persistence guard on exception.
  my $stored = Overnet::Relay::Store::store($self, $event, $accepted_at);
  $self->_maybe_compact;
  return $stored;
}

sub delete_by_id {
  my ($self, $id) = @_;
  return if !$self->get_by_id($id);
  if (!$self->{_replaying}) {
    $self->_persist_record([q{-}, $id]);
  }
  my $deleted = Overnet::Relay::Store::delete_by_id($self, $id);
  if (!$self->{_replaying} && !$self->{_storing}) {
    $self->_maybe_compact;
  }
  return $deleted;
}

sub clear {
  my ($self) = @_;
  Overnet::Relay::Store::clear($self);
  my $ok = eval { $self->_compact_to_disk; 1; };
  if (!$ok) { $self->{_write_failed} = 1; croak $EVAL_ERROR; }
  return 1;
}

sub _load_from_disk {
  my ($self) = @_;
  local $self->{_replaying} = 1;    ## no critic (Variables::ProhibitLocalVars) -- Replay must never append, including nested eviction.
  my $path = $self->{path};
  if (!-e $path) {
    return 1;
  }

  open my $fh, '<:raw', $path
    or croak "Can't open relay store file $path for reading: $OS_ERROR";
  my $raw = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  close $fh                         # uncoverable branch true reason: close cannot fail on a readable handle here
    or croak "Can't close relay store file $path after reading: $OS_ERROR";

  if (!(defined $raw && length $raw)) {
    return 1;
  }

  my @lines   = split /\n/mxs, $raw;
  my $records = 0;
  for my $index (0 .. $#lines) {
    my $line = $lines[$index];
    if (!length $line) {
      next;
    }

    my $decoded;
    my $ok = eval {
      $decoded = Overnet::Core::JSON::decode_json($line);
      1;
    };
    if (!$ok) {

      # A torn final line can result from a crash mid-append; tolerate it but
      # treat any earlier undecodable line as genuine corruption.
      if ($index == $#lines && $raw !~ /\n\z/mxs) {
        next;
      }
      croak "Invalid relay store file $path: $EVAL_ERROR";
    }

    $records += $self->_replay_record($path, $decoded);
  }

  $self->{_records_on_disk} = $records;

  # The on-disk log may hold the legacy single-array format, superseded
  # records, or tombstones. Leave the file untouched for read-only consumers
  # (for example the backup tool) and normalize it on the first mutation.
  $self->{_needs_rewrite} = length($raw) ? 1 : 0;
  return 1;
}

sub _replay_record {
  my ($self, $path, $decoded) = @_;
  if (ref($decoded) ne 'ARRAY') {
    croak "Relay store file $path must contain array records";
  }

  my $tag = $decoded->[0];
  if (!@{$decoded} || ref($tag) eq 'HASH') {

    return $self->_replay_legacy($decoded);
  }
  if (!ref($tag) && $tag eq q{+} && ref($decoded->[1]) eq 'HASH') {
    Overnet::Core::Nostr::Event->assert_wire_types($decoded->[1]);
    croak 'Invalid acceptance time'
      if defined($decoded->[2])
      && (ref($decoded->[2]) || $decoded->[2] !~ /\A[0-9]+\z/mxs);
    Overnet::Relay::Store::store($self, Net::Nostr::Event->from_wire($decoded->[1]), $decoded->[2]);
    return 1;
  }
  if (!ref($tag) && $tag eq q{-} && defined $decoded->[1] && !ref($decoded->[1])) {
    Overnet::Relay::Store::delete_by_id($self, $decoded->[1]);
    return 1;
  }

  if (!ref($tag) && $tag eq 'evidence' && ref($decoded->[1]) eq 'HASH') {
    my $evidence = $decoded->[1];
    for my $field (qw(_discarded_states _discarded_removals)) {
      croak "Invalid retention evidence" if ref($evidence->{$field}) ne 'HASH';
      $self->{$field} = $evidence->{$field};
    }
    return 1;
  }

  croak "Relay store file $path contains an unrecognized record";
}

sub _replay_legacy {
  my ($self, $events) = @_;
  for my $wire (@{$events}) {
    croak 'Invalid event in legacy relay store' if ref($wire) ne 'HASH';
    Overnet::Core::Nostr::Event->assert_wire_types($wire);
    Overnet::Relay::Store::store($self, Net::Nostr::Event->from_wire($wire));
  }
  return scalar @{$events};
}

sub _persist_record {
  my ($self, $entry) = @_;

  my $ok = eval {
    if ($self->{_needs_rewrite}) {
      $self->_compact_to_disk;
    }
    $self->_append_record($entry);
    $self->{_records_on_disk}++;
    1;
  };
  if (!$ok) {
    $self->{_write_failed} = 1;
    croak $EVAL_ERROR;
  }
  return 1;
}

sub _maybe_compact {
  my ($self) = @_;
  my $live = $self->event_count;
  if ( $self->{_records_on_disk} >= $COMPACT_MIN_RECORDS
    && $self->{_records_on_disk} >= $COMPACT_LIVE_FACTOR * ($live + 1)) {
    my $ok = eval { $self->_compact_to_disk; 1; };
    if (!$ok) {
      $self->{_write_failed} = 1;
      croak $EVAL_ERROR;
    }
  }
  return 1;
}

sub _append_record {
  my ($self, $entry) = @_;
  my $path = $self->{path};
  $self->_ensure_directory($path);

  open my $fh, '>>:raw', $path
    or croak "Can't open relay store file $path for appending: $OS_ERROR";
  _write_payload($fh, $JSON->encode($entry) . "\n", "relay store file $path", 'append to');
  $self->_sync_directory;
  return 1;
}

sub _compact_to_disk {
  my ($self) = @_;
  my $path = $self->{path};
  $self->_ensure_directory($path);

  # uncoverable branch true reason: all_events always returns an array reference
  my @records = map { $JSON->encode([q{+}, $_->to_hash, $self->{_accepted_at}{$_->id}]) } @{$self->all_events || []};
  if (keys %{$self->{_discarded_states} || {}} || keys %{$self->{_discarded_removals} || {}}) {
    push @records,
      $JSON->encode(
      [
        'evidence',
        {
          _discarded_states   => $self->{_discarded_states}   || {},
          _discarded_removals => $self->{_discarded_removals} || {},
        }
      ]
      );
  }
  my $payload = @records ? join("\n", @records) . "\n" : q{};

  my ($fh, $tmp_path) = tempfile('.overnet-store-XXXXXX', DIR => dirname($path), UNLINK => 1);
  binmode $fh, ':raw';
  _write_payload($fh, $payload, "relay store temp file $tmp_path", 'write');

  rename $tmp_path, $path
    or croak "Can't rename relay store temp file $tmp_path to $path: $OS_ERROR";

  $self->_sync_directory;
  $self->{_records_on_disk} = scalar @records;
  $self->{_needs_rewrite}   = 0;
  return 1;
}

sub _write_payload {
  my ($fh, $payload, $label, $operation) = @_;

  # Keep the handle alive across the exception, then close it explicitly.
  # An implicit close during unwinding can replace the original write error.
  my $ok = eval {
    print {$fh} $payload      or croak "Can't $operation $label: $OS_ERROR";
    ($fh->flush && $fh->sync) or croak "Can't sync $label: $OS_ERROR";
    1;
  };
  my $error  = $EVAL_ERROR;
  my $closed = close $fh;
  if (!$ok) {
    croak $error;
  }
  if (!$closed) {
    croak "Can't close $label: $OS_ERROR";
  }
  return 1;
}

sub _sync_directory {
  my ($self) = @_;
  open my $dir, '<', dirname($self->{path}) or croak "Can't open store directory: $OS_ERROR";
  $dir->sync or croak "Can't sync store directory: $OS_ERROR";
  close $dir or croak "Can't close store directory: $OS_ERROR";
  return;
}

sub _ensure_directory {
  my ($self, $path) = @_;
  my $dir = dirname($path);
  if (!-d $dir) {
    make_path($dir);
  }
  return 1;
}

1;

=head1 NAME

Overnet::Relay::Store::File - File-backed Nostr relay store

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $store = Overnet::Relay::Store::File->new(path => 'relay-store.json');

=head1 DESCRIPTION

Persists relay events to disk while preserving the L<Net::Nostr::RelayStore>
API. Persistence is append-structured: each accepted event or deletion appends
one JSON-lines record rather than rewriting the whole store, so ingesting N
events costs O(N) total instead of O(N^2). The log is compacted back to one
record per live event once it outgrows the live set, keeping the file bounded
under churn. The legacy single-JSON-array format is still read, and is
normalized to the record log on the first subsequent write.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a file-backed store.

=head2 path

Returns the configured store path.

=head2 query

=head2 all_events

=head2 get_by_id

=head2 find_addressable

=head2 find_replaceable

=head2 acceptance_for

=head2 discarded_state

=head2 discarded_removal

These inherited read operations refuse access after a persistence failure. Reopen
the store to recover its durable state before making authorization decisions.

=head2 store

Stores an event and appends a persistence record if the event was accepted.

=head2 delete_by_id

Deletes an event and appends a tombstone record if an event was removed.

=head2 clear

Clears the store and rewrites the persisted state as empty.

=head1 DIAGNOSTICS

Invalid store files and file-system errors are reported with C<croak>.

=head1 CONFIGURATION AND ENVIRONMENT

The caller supplies the JSON store path.

=head1 DEPENDENCIES

Requires L<JSON> and L<Net::Nostr::RelayStore>.

=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

Report issues at L<https://github.com/overnet-project/overnet-perl/issues>.

=head1 AUTHOR

Nicholas B. Hubbard C<< <nicholashubbard@posteo.net> >>

=head1 LICENSE AND COPYRIGHT

This software is distributed under the GNU General Public License, version 3.

=cut
