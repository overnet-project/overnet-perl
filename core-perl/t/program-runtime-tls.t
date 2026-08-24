use strictures 2;
use Test::More;
use JSON ();

use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use Overnet::Program::TLSConfig;

sub exception (&);

subtest 'normalize accepts enabled server TLS config with implicit mode' => sub {
  my $tls = Overnet::Program::TLSConfig->normalize(
    tls => {
      enabled          => JSON::true,
      cert_chain_file  => '/tmp/server-cert.pem',
      private_key_file => '/tmp/server-key.pem',
      min_version      => 'TLSv1.2',
    },
    implicit_mode => 'server',
  );

  is_deeply $tls,
    {
    enabled          => 1,
    mode             => 'server',
    cert_chain_file  => '/tmp/server-cert.pem',
    private_key_file => '/tmp/server-key.pem',
    min_version      => 'TLSv1.2',
    },
    'server TLS config normalizes to baseline shape';
};

subtest 'normalize rejects invalid baseline TLS shapes' => sub {
  like(
    exception {
      Overnet::Program::TLSConfig->normalize(
        tls => {
          cert_chain_file  => '/tmp/server-cert.pem',
          private_key_file => '/tmp/server-key.pem',
        },
        implicit_mode => 'server',
      );
    },
    qr/tls\.enabled\ is\ required/mx,
    'enabled is required when tls is present',
  );

  like(
    exception {
      Overnet::Program::TLSConfig->normalize(
        tls => {
          enabled => JSON::true,
          mode    => 'server',
        },
      );
    },
    qr/tls\.cert_chain_file\ is\ required/mx,
    'server mode requires a cert chain file',
  );

  like(
    exception {
      Overnet::Program::TLSConfig->normalize(
        tls => {
          enabled          => JSON::true,
          mode             => 'server',
          cert_chain_file  => '/tmp/server-cert.pem',
          private_key_file => '/tmp/server-key.pem',
          min_version      => 'TLSv1.1',
        },
      );
    },
    qr/tls\.min_version\ must\ be\ TLSv1\.2\ or\ TLSv1\.3/mx,
    'min_version is restricted to the baseline secure values',
  );
};

subtest 'server_start_args maps baseline TLS config to IO::Socket::SSL arguments' => sub {
  my $tls = Overnet::Program::TLSConfig->normalize(
    tls => {
      enabled          => 1,
      cert_chain_file  => '/tmp/server-cert.pem',
      private_key_file => '/tmp/server-key.pem',
      verify_peer      => 0,
      min_version      => 'TLSv1.2',
    },
    implicit_mode => 'server',
  );

  my $args = Overnet::Program::TLSConfig->server_start_args($tls);

  is $args->{SSL_server},         1,                      'SSL_server is enabled';
  is $args->{SSL_startHandshake}, 1,                      'server TLS does an immediate handshake';
  is $args->{SSL_cert_file},      '/tmp/server-cert.pem', 'cert chain file is mapped';
  is $args->{SSL_key_file},       '/tmp/server-key.pem',  'key file is mapped';
  is $args->{SSL_verify_mode},    SSL_VERIFY_NONE,        'verify mode defaults to none when verify_peer is false';
  is $args->{SSL_version}, 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1',
    'TLSv1.2 minimum maps to the expected SSL version string';
};

sub exception (&) {
  my ($code) = @_;
  my $error;
  eval { $code->(); 1 } or $error = $@;
  return $error;
}

sub _tls_error (&) {
  my ($code) = @_;
  return eval { $code->(); 1 } ? undef : $@;
}

subtest 'normalize rejects malformed TLS configuration' => sub {
  is(Overnet::Program::TLSConfig->normalize, undef, 'no tls key normalizes to nothing');
  like(_tls_error { Overnet::Program::TLSConfig->normalize(tls => 'junk') },
    qr/tls must be an object/, 'non-object tls sections croak');
  like(
    _tls_error {
      Overnet::Program::TLSConfig->normalize(tls => {enabled => 1}, implicit_mode => 'proxy')
    },
    qr/implicit_mode must be client or server/,
    'unknown implicit modes croak',
  );
  like(
    _tls_error { Overnet::Program::TLSConfig->normalize(tls => {enabled => 1, mode => 'proxy'}) },
    qr/tls[.]mode must be client or server/,
    'unknown tls modes croak',
  );
  like(
    _tls_error { Overnet::Program::TLSConfig->normalize(tls => {enabled => 1, cert_chain_file => q{}}) },
    qr/tls[.]cert_chain_file must be a non-empty string/,
    'empty string fields croak',
  );
  like(
    _tls_error { Overnet::Program::TLSConfig->normalize(tls => {enabled => 'yes'}) },
    qr/tls[.]enabled must be a boolean/,
    'non-boolean enabled flags croak',
  );
  like(
    _tls_error { Overnet::Program::TLSConfig->normalize(tls => {enabled => 1, min_version => 'SSLv3'}) },
    qr/tls[.]min_version must be TLSv1[.]2 or TLSv1[.]3/,
    'unsupported minimum versions croak',
  );
  like(
    _tls_error {
      Overnet::Program::TLSConfig->normalize(tls => {enabled => 1}, implicit_mode => 'server')
    },
    qr/tls[.]cert_chain_file is required/,
    'enabled server tls requires a certificate chain',
  );
  like(
    _tls_error {
      Overnet::Program::TLSConfig->normalize(
        tls => {enabled => 1, cert_chain_file => 'c.pem'},
        implicit_mode => 'server',
      )
    },
    qr/tls[.]private_key_file is required/,
    'enabled server tls requires a private key',
  );
  like(
    _tls_error {
      Overnet::Program::TLSConfig->normalize(
        tls => {enabled => 1, verify_peer => 1},
        implicit_mode => 'client',
      )
    },
    qr/tls[.]ca_file is required/,
    'peer verification requires a CA file',
  );

  my $flexible = Overnet::Program::TLSConfig->normalize(
    tls => {enabled => '0', verify_peer => JSON::false},
  );
  is($flexible->{enabled}, 0, 'string booleans normalize');
  ok(!exists $flexible->{mode}, 'no mode is recorded without one');
};

subtest 'server_start_args builds IO::Socket::SSL arguments' => sub {
  is(Overnet::Program::TLSConfig->server_start_args(undef), undef, 'no tls yields no args');
  like(_tls_error { Overnet::Program::TLSConfig->server_start_args('junk') },
    qr/tls must be an object/, 'non-object tls croaks');
  is(Overnet::Program::TLSConfig->server_start_args({enabled => 0}), undef,
    'disabled tls yields no args');
  like(
    _tls_error { Overnet::Program::TLSConfig->server_start_args({enabled => 1, mode => 'client'}) },
    qr/tls[.]mode must be server/,
    'client mode cannot build server args',
  );

  my $args = Overnet::Program::TLSConfig->server_start_args(
    {
      enabled          => 1,
      mode             => 'server',
      cert_chain_file  => 'c.pem',
      private_key_file => 'k.pem',
      verify_peer      => 1,
      ca_file          => 'ca.pem',
      min_version      => 'TLSv1.3',
    },
  );
  is($args->{SSL_cert_file}, 'c.pem',   'the certificate chain is passed through');
  is($args->{SSL_ca_file},   'ca.pem',  'the CA file is passed through');
  is($args->{SSL_version},   'TLSv1_3', 'TLSv1.3 maps to the IO::Socket::SSL version token');
  ok($args->{SSL_verify_mode}, 'peer verification enables SSL_VERIFY_PEER');

  my $minimal = Overnet::Program::TLSConfig->server_start_args(
    {
      enabled          => 1,
      mode             => 'server',
      cert_chain_file  => 'c.pem',
      private_key_file => 'k.pem',
      min_version      => 'TLSv1.2',
    },
  );
  is($minimal->{SSL_version}, 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1', 'TLSv1.2 excludes older protocol versions');
  ok(!exists $minimal->{SSL_ca_file}, 'no CA file is passed without one');
  like(
    _tls_error {
      Overnet::Program::TLSConfig->server_start_args(
        {
          enabled          => 1,
          mode             => 'server',
          cert_chain_file  => 'c.pem',
          private_key_file => 'k.pem',
          min_version      => 'SSLv3',
        },
      )
    },
    qr/Unsupported tls[.]min_version: SSLv3/,
    'unsupported versions croak when building args',
  );
};

done_testing;
