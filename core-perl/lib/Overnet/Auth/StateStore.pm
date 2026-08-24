package Overnet::Auth::StateStore;

use strictures 2;
use Moo;
use Carp    qw(croak);
use English qw(-no_match_vars);

use File::Basename qw(dirname);
use File::Path     qw(make_path);
use JSON           ();

our $VERSION = '0.001';

my $STATE_JSON = JSON->new;
$STATE_JSON->utf8;
$STATE_JSON->canonical;
$STATE_JSON->pretty;

has path => (is => 'ro');

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);
  my $path = $args{path};

  if (!(defined $path && !ref($path) && length($path))) {
    croak "path is required\n";
  }

  return {path => $path,};
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub load_state {
  my ($self) = @_;
  my $path = $self->{path};

  if (!(-e $path)) {
    return;
  }

  open my $fh, '<', $path
    or croak "open $path failed: $OS_ERROR";
  my $json = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  close $fh
    or croak "close $path failed: $OS_ERROR";

  my $decoded = eval { JSON->new->utf8->decode($json) };
  if (!(defined $decoded)) {
    croak "auth state file $path is not valid JSON: $EVAL_ERROR";
  }

  return _normalize_state($decoded);
}

sub save_state {
  my ($self, %args) = @_;
  my $state  = _normalize_state($args{state});
  my $path   = $self->{path};
  my $parent = dirname($path);
  my $tmp    = $path . '.tmp.' . $PROCESS_ID;

  if (!(-d $parent)) {
    make_path($parent);
  }

  my $json = $STATE_JSON->encode($state);

  open my $fh, '>', $tmp
    or croak "open $tmp failed: $OS_ERROR";
  print {$fh} $json
    or croak "write $tmp failed: $OS_ERROR";
  close $fh
    or croak "close $tmp failed: $OS_ERROR";

  rename $tmp, $path
    or croak "rename $tmp to $path failed: $OS_ERROR";

  return 1;
}

sub _normalize_state {
  my ($state) = @_;

  if (!(ref($state) eq 'HASH')) {
    croak "auth state must decode to an object\n";
  }
  if (exists($state->{policies}) && ref($state->{policies}) ne 'ARRAY') {
    croak "auth state policies must be an array\n";
  }
  if (exists($state->{service_pins})
    && ref($state->{service_pins}) ne 'HASH') {
    croak "auth state service_pins must be an object\n";
  }
  if (exists($state->{sessions}) && ref($state->{sessions}) ne 'ARRAY') {
    croak "auth state sessions must be an array\n";
  }

  return {
    policies     => _clone($state->{policies}     || []),
    service_pins => _clone($state->{service_pins} || {}),
    sessions     => _clone($state->{sessions}     || []),
  };
}

sub _clone {
  my ($value) = @_;
  if (!(defined $value)) {
    return $value;
  }
  if (!(ref($value))) {
    return $value;
  }

  if (ref($value) eq 'HASH') {
    return {
      map { $_ => _clone($value->{$_}) }
        keys %{$value}
    };
  }

  if (ref($value) eq 'ARRAY') {
    return [map { _clone($_) } @{$value}];
  }

  return "$value";
}

1;

=head1 NAME

Overnet::Auth::StateStore - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::StateStore;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 path

Public API entry point.

=head2 load_state

Public API entry point.

=head2 save_state

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
