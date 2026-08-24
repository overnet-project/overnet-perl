package Overnet::Program::Store;

use strictures 2;
use Moo;
use Carp qw(croak);
use JSON ();

our $VERSION = '0.001';

my $JSON = JSON->new->utf8->canonical;

has streams   => (is => 'rw', accessor => '_streams');
has documents => (is => 'rw', accessor => '_documents');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  _constructor_args_hash(@args);
  return {
    streams   => {},
    documents => {},
  };
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub has_document {
  my ($self, %args) = @_;
  my $key = $args{key};

  if (!(defined $key && !ref($key) && length($key))) {
    croak "key is required\n";
  }

  return exists $self->{documents}{$key} ? 1 : 0;
}

sub put_document {
  my ($self, %args) = @_;
  my $key   = $args{key};
  my $value = $args{value};

  if (!(defined $key && !ref($key) && length($key))) {
    croak "key is required\n";
  }
  if (!(ref($value) eq 'HASH')) {
    croak "value must be an object\n";
  }

  $self->{documents}{$key} = _clone_json_object($value);
  return {key => $key,};
}

sub get_document {
  my ($self, %args) = @_;
  my $key = $args{key};

  if (!(defined $key && !ref($key) && length($key))) {
    croak "key is required\n";
  }
  if (!(exists $self->{documents}{$key})) {
    croak "Unknown key: $key\n";
  }

  return {
    key   => $key,
    value => _clone_json_object($self->{documents}{$key}),
  };
}

sub delete_document {
  my ($self, %args) = @_;
  my $key = $args{key};

  if (!(defined $key && !ref($key) && length($key))) {
    croak "key is required\n";
  }
  if (!(exists $self->{documents}{$key})) {
    croak "Unknown key: $key\n";
  }

  delete $self->{documents}{$key};
  return {};
}

sub list_documents {
  my ($self, %args) = @_;
  my $prefix = $args{prefix};

  if (defined $prefix && ref($prefix)) {
    croak "prefix must be a string\n";
  }

  my @keys = sort keys %{$self->{documents}};
  if (defined $prefix) {
    @keys = grep { index($_, $prefix) == 0 } @keys;
  }

  return {keys => \@keys,};
}

sub append_event {
  my ($self, %args) = @_;
  my $stream = $args{stream};
  my $event  = $args{event};

  if (!(defined $stream && !ref($stream) && length($stream))) {
    croak "stream is required\n";
  }
  if (!(ref($event) eq 'HASH')) {
    croak "event must be an object\n";
  }

  my $stored_event = _clone_json_object($event);
  my $entries      = $self->{streams}{$stream} ||= [];
  my $offset       = scalar @{$entries};

  push @{$entries},
    {
    offset => $offset,
    event  => $stored_event,
    };

  return {
    stream => $stream,
    offset => $offset,
  };
}

sub read_events {
  my ($self, %args) = @_;
  my $stream       = $args{stream};
  my $after_offset = $args{after_offset};
  my $limit        = $args{limit};

  if (!(defined $stream && !ref($stream) && length($stream))) {
    croak "stream is required\n";
  }
  if (defined $after_offset
    && (ref($after_offset) || $after_offset !~ /\A-?\d+\z/mxs)) {
    croak "after_offset must be an integer\n";
  }
  if (defined $limit && (ref($limit) || $limit !~ /\A\d+\z/mxs)) {
    croak "limit must be a non-negative integer\n";
  }

  my @entries = @{$self->{streams}{$stream} || []};
  if (defined $after_offset) {
    @entries = grep { $_->{offset} > $after_offset } @entries;
  }
  if (defined $limit) {
    @entries = splice(@entries, 0, $limit);
  }

  return {
    stream  => $stream,
    entries => [map { {offset => $_->{offset}, event => _clone_json_object($_->{event}),} } @entries],
  };
}

sub _clone_json_object {
  my ($value) = @_;
  return $JSON->decode($JSON->encode($value));
}

1;

=head1 NAME

Overnet::Program::Store - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::Store;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 has_document

Public API entry point.

=head2 put_document

Public API entry point.

=head2 get_document

Public API entry point.

=head2 delete_document

Public API entry point.

=head2 list_documents

Public API entry point.

=head2 append_event

Public API entry point.

=head2 read_events

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
