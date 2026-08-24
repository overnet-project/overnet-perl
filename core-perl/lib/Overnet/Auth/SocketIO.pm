package Overnet::Auth::SocketIO;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);

our $VERSION = '0.001';

sub write_all {
  my ($class, %args) = @_;
  my $socket = $args{socket};
  my $bytes  = defined($args{bytes}) ? $args{bytes} : q{};
  my $target = $args{target} || 'socket';
  my $writer = $args{writer} || \&_syswrite;
  my $offset = 0;

  while ($offset < length($bytes)) {
    my $written = $writer->(
      socket => $socket,
      bytes  => $bytes,
      length => length($bytes) - $offset,
      offset => $offset,
    );
    if (!(defined $written)) {
      croak "write to $target failed: $OS_ERROR";
    }
    if ($written == 0) {
      croak "zero-byte write to $target";
    }
    $offset += $written;
  }

  return 1;
}

sub _syswrite {
  my (%args) = @_;
  return syswrite($args{socket}, $args{bytes}, $args{length}, $args{offset});
}

1;

=head1 NAME

Overnet::Auth::SocketIO - Overnet auth socket I/O helpers

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::SocketIO;

=head1 DESCRIPTION

This module contains shared socket I/O helpers for the Overnet auth client and server.

=head1 SUBROUTINES/METHODS

=head2 write_all

Writes the complete byte string to a socket.

=head1 DIAGNOSTICS

This module reports errors through normal Perl exceptions.

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
