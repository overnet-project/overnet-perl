use strictures 2;

use Test2::V0;

use Overnet::Auth::SocketIO;

subtest 'write_all writes every byte through the writer' => sub {
  my @writes;
  my $writer = sub {
    my (%args) = @_;
    push @writes, {length => $args{length}, offset => $args{offset}};
    return 2;
  };

  ok(
    Overnet::Auth::SocketIO->write_all(socket => undef, bytes => 'abcd', writer => $writer),
    'write_all succeeds once every byte is written',
  );
  is(
    \@writes,
    [{length => 4, offset => 0}, {length => 2, offset => 2}],
    'partial writes continue from the reached offset',
  );
};

subtest 'write_all tolerates missing byte payloads' => sub {
  ok(
    Overnet::Auth::SocketIO->write_all(socket => undef, writer => sub { die 'never called' }),
    'missing bytes default to an empty write',
  );
};

subtest 'write_all reports writer failures' => sub {
  like(
    dies {
      Overnet::Auth::SocketIO->write_all(
        socket => undef,
        bytes  => 'abcd',
        target => 'client socket',
        writer => sub { return undef },
      )
    },
    qr/write to client socket failed/,
    'undefined write results croak with the target name',
  );
  like(
    dies {
      Overnet::Auth::SocketIO->write_all(
        socket => undef,
        bytes  => 'abcd',
        writer => sub { return 0 },
      )
    },
    qr/zero-byte write to socket/,
    'zero-byte writes croak with the default target name',
  );
};

subtest 'the default writer performs a real syswrite' => sub {
  my ($reader, $writer);
  pipe $reader, $writer or die "pipe failed: $!";
  ok(
    Overnet::Auth::SocketIO->write_all(socket => $writer, bytes => "ping\n"),
    'writing to a pipe succeeds',
  );
  close $writer or die "close failed: $!";
  my $line = <$reader>;
  is($line, "ping\n", 'the bytes arrive at the reader');
  close $reader or die "close failed: $!";
};

done_testing;
