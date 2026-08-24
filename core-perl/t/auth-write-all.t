use strictures 2;

use Test2::V0;

use Overnet::Auth::SocketIO;

our $VERSION = '0.001';

subtest 'auth socket writer rejects zero-byte writes' => sub {
  like(
    dies {
      Overnet::Auth::SocketIO->write_all(
        socket => 'fake socket',
        bytes  => 'frame',
        target => 'auth-agent test socket',
        writer => sub { return 0; },
      );
    },
    qr/zero-byte\ write\ to\ auth-agent\ test\ socket/smx,
    'zero-byte writes are rejected instead of spinning',
  );
};

done_testing();
