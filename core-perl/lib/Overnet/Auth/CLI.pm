package Overnet::Auth::CLI;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);

use Getopt::Long qw(GetOptionsFromArray);
use JSON         ();

use Overnet::Auth::Client;

our $VERSION = '0.001';

sub run {
  my ($class, %args) = @_;
  my @argv = @{$args{argv} || []};
  if (@argv && $argv[0] eq '--help') {
    return {
      exit_code => 0,
      output    => _usage(),
    };
  }
  my $command = shift @argv || q{};
  my %options = (
    interactive => 1,
    pretty      => 1,
  );
  my $help = 0;

  GetOptionsFromArray(
    \@argv,
    'auth-sock=s'                => \$options{auth_sock},
    'policy-id=s'                => \$options{policy_id},
    'identity-id=s'              => \$options{identity_id},
    'program-id=s'               => \$options{program_id},
    'service-locator=s@'         => \$options{service_locators},
    'service-identity-scheme=s'  => \$options{service_identity_scheme},
    'service-identity-value=s'   => \$options{service_identity_value},
    'service-identity-display=s' => \$options{service_identity_display},
    'scope=s'                    => \$options{scope},
    'action=s'                   => \$options{action},
    'challenge-type=s'           => \$options{challenge_type},
    'challenge-value=s'          => \$options{challenge_value},
    'artifact-json=s@'           => \$options{artifact_json},
    'artifact-file=s@'           => \$options{artifact_files},
    'session-id=s'               => \$options{session_id},
    'interactive!'               => \$options{interactive},
    'pretty!'                    => \$options{pretty},
    'help'                       => \$help,
  ) or croak _usage();

  if ($help || !$command) {
    return {
      exit_code => $help ? 0 : 1,
      output    => _usage(),
    };
  }

  if (!(_valid_command($command))) {
    croak _usage();
  }

  if (@argv) {
    croak "unexpected positional arguments: @argv\n";
  }

  my $client   = _client(%args, options => \%options);
  my $response = $class->_dispatch_command($command, $client, %options);

  return {
    exit_code => $response->{ok} ? 0 : 1,
    output    => $class->_render_response($response, pretty => $options{pretty}),
  };
}

sub _valid_command {
  my ($command) = @_;
  my %valid = map { $_ => 1 } qw(
    identities
    policies
    policy-grant
    policy-revoke
    service-pins
    service-pin-set
    service-pin-forget
    sessions
    authorize
    renew
    revoke
  );
  return $valid{$command} ? 1 : 0;
}

sub _client {
  my (%args) = @_;
  my $options = $args{options};
  if ($args{client}) {
    return $args{client};
  }
  if (ref($args{client_factory}) eq 'CODE') {
    return $args{client_factory}->(%{$options});
  }
  return Overnet::Auth::Client->new(
    (
      defined($options->{auth_sock})
      ? (endpoint => $options->{auth_sock})
      : ()
    ),
  );
}

sub _dispatch_command {
  my ($class, $command, $client, %options) = @_;
  my %dispatch = (
    identities     => sub { return $client->identities_list; },
    policies       => sub { return $client->policies_list; },
    'policy-grant' => sub {
      return $client->policies_grant(policy => $class->_policy_descriptor(%options),);
    },
    'policy-revoke' => sub {
      return $client->policies_revoke($class->_policy_id_params(%options),);
    },
    'service-pins'    => sub { return $client->service_pins_list; },
    'service-pin-set' => sub {
      return $client->service_pins_set($class->_service_pin_set_params(%options),);
    },
    'service-pin-forget' => sub {
      return $client->service_pins_forget($class->_service_locator_params(%options),);
    },
    sessions  => sub { return $client->sessions_list; },
    authorize => sub { return $client->sessions_authorize($class->_authorize_params(%options),); },
    renew     => sub {
      return $client->sessions_renew($class->_session_params(%options, include_interactive => 1),);
    },
    revoke => sub { return $client->sessions_revoke($class->_session_params(%options),); },
  );
  return $dispatch{$command}->();
}

sub _authorize_params {
  my ($class, %options) = @_;

  _require_option(\%options, program_id => '--program-id is required');
  _require_option(\%options, scope      => '--scope is required');
  _require_option(\%options, action     => '--action is required');

  my $service = $class->_service_descriptor(%options);

  my %params = (
    program_id  => $options{program_id},
    service     => $service,
    scope       => $options{scope},
    action      => $options{action},
    interactive => $options{interactive} ? JSON::true : JSON::false,
    artifacts   => $class->_artifacts(%options),
  );
  if (_has_option(\%options, 'identity_id')) {
    $params{identity_id} = $options{identity_id};
  }

  my $challenge = _challenge_option(%options);
  if ($challenge) {
    $params{challenge} = $challenge;
  }

  return %params;
}

sub _require_option {
  my ($options, $name, $message) = @_;
  if (!(_has_option($options, $name))) {
    croak "$message\n";
  }
  return;
}

sub _has_option {
  my ($options, $name) = @_;
  return defined($options->{$name}) && !ref($options->{$name}) && length($options->{$name}) ? 1 : 0;
}

sub _challenge_option {
  my (%options) = @_;
  if (!(defined($options{challenge_type}) || defined($options{challenge_value}))) {
    return;
  }
  if (!(_has_option(\%options, 'challenge_type') && _has_option(\%options, 'challenge_value'))) {
    croak "--challenge-type and --challenge-value are required together\n";
  }
  return {
    type  => $options{challenge_type},
    value => $options{challenge_value},
  };
}

sub _policy_descriptor {
  my ($class, %options) = @_;

  if (!(defined($options{identity_id}) && !ref($options{identity_id}) && length($options{identity_id}))) {
    croak "--identity-id is required\n";
  }
  if (!(defined($options{program_id}) && !ref($options{program_id}) && length($options{program_id}))) {
    croak "--program-id is required\n";
  }
  if (!(defined($options{scope}) && !ref($options{scope}) && length($options{scope}))) {
    croak "--scope is required\n";
  }
  if (!(defined($options{action}) && !ref($options{action}) && length($options{action}))) {
    croak "--action is required\n";
  }

  return {
    identity_id => $options{identity_id},
    program_id  => $options{program_id},
    service     => $class->_service_descriptor(%options),
    scope       => $options{scope},
    action      => $options{action},
  };
}

sub _policy_id_params {
  my ($class, %options) = @_;

  if (!(defined($options{policy_id}) && !ref($options{policy_id}) && length($options{policy_id}))) {
    croak "--policy-id is required\n";
  }

  return (policy_id => $options{policy_id},);
}

sub _session_params {
  my ($class, %options) = @_;

  if (!(defined($options{session_id}) && !ref($options{session_id}) && length($options{session_id}))) {
    croak "--session-id is required\n";
  }

  my %params = (
    session_handle => {
      id => $options{session_id},
    },
  );
  if ($options{include_interactive}) {
    $params{interactive} = $options{interactive} ? JSON::true : JSON::false;
  }

  return %params;
}

sub _service_pin_set_params {
  my ($class, %options) = @_;
  my %params           = $class->_service_locator_params(%options);
  my $service_identity = $class->_service_identity_descriptor(%options);
  if (!($service_identity)) {
    croak "--service-identity-scheme and --service-identity-value are required\n";
  }

  $params{service_identity} = $service_identity;
  return %params;
}

sub _service_locator_params {
  my ($class, %options) = @_;

  if (!(ref($options{service_locators}) eq 'ARRAY' && @{$options{service_locators}})) {
    croak "--service-locator is required\n";
  }
  if (!(@{$options{service_locators}} == 1)) {
    croak "exactly one --service-locator is required\n";
  }

  return (locator => $options{service_locators}[0],);
}

sub _service_descriptor {
  my ($class, %options) = @_;

  if (!(ref($options{service_locators}) eq 'ARRAY' && @{$options{service_locators}})) {
    croak "--service-locator is required\n";
  }

  my $service          = {locators => [@{$options{service_locators}}],};
  my $service_identity = $class->_service_identity_descriptor(%options);
  if ($service_identity) {
    $service->{service_identity} = $service_identity;
  }

  return $service;
}

sub _artifacts {
  my ($class, %options) = @_;
  my @artifacts;

  for my $json (@{$options{artifact_json} || []}) {
    push @artifacts, $class->_decode_artifact_json($json, '--artifact-json');
  }
  for my $path (@{$options{artifact_files} || []}) {
    open my $fh, '<', $path
      or croak "open $path failed: $OS_ERROR";
    my $json = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
    close $fh
      or croak "close $path failed: $OS_ERROR";
    push @artifacts, $class->_decode_artifact_json($json, "--artifact-file $path");
  }

  if (!(@artifacts)) {
    croak "--artifact-json or --artifact-file is required\n";
  }

  return \@artifacts;
}

sub _decode_artifact_json {
  my ($class, $json, $source) = @_;
  my $artifact = eval { JSON->new->utf8->decode($json) };
  if (!(defined $artifact)) {
    croak "$source did not contain valid JSON: $EVAL_ERROR";
  }
  if (!(ref($artifact) eq 'HASH')) {
    croak "$source must decode to an object\n";
  }
  return $artifact;
}

sub _service_identity_descriptor {
  my ($class, %options) = @_;
  my $scheme = $options{service_identity_scheme};
  my $value  = $options{service_identity_value};

  if (!(defined($scheme) || defined($value) || defined($options{service_identity_display}))) {
    return;
  }

  if (!(defined($scheme) && !ref($scheme) && length($scheme) && defined($value) && !ref($value) && length($value))) {
    croak "--service-identity-scheme and --service-identity-value are required together\n";
  }

  my %descriptor = (
    scheme => $scheme,
    value  => $value,
  );
  if ( defined($options{service_identity_display})
    && !ref($options{service_identity_display})
    && length($options{service_identity_display})) {
    $descriptor{display} = $options{service_identity_display};
  }

  return \%descriptor;
}

sub _render_response {
  my ($class, $response, %options) = @_;
  my $encoder = JSON->new->utf8->canonical;
  if ($options{pretty}) {
    $encoder = $encoder->pretty;
  }

  if ($response->{ok}) {
    return $encoder->encode(
      {
        ok     => JSON::true,
        result => $response->{result} || {},
      }
    );
  }

  return $encoder->encode(
    {
      ok    => JSON::false,
      error => $response->{error} || {},
    }
  );
}

sub _usage {
  return <<'USAGE';
Usage:
  overnet-auth.pl identities [options]
  overnet-auth.pl policies [options]
  overnet-auth.pl policy-grant [options]
  overnet-auth.pl policy-revoke [options]
  overnet-auth.pl service-pins [options]
  overnet-auth.pl service-pin-set [options]
  overnet-auth.pl service-pin-forget [options]
  overnet-auth.pl sessions [options]
  overnet-auth.pl authorize [options]
  overnet-auth.pl renew [options]
  overnet-auth.pl revoke [options]

Shared options:
  --auth-sock PATH
  --pretty / --no-pretty
  --help

Policy grant options:
  --identity-id ID
  --program-id PROGRAM_ID
  --service-locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY
  --scope SCOPE
  --action ACTION

Policy revoke options:
  --policy-id ID

Service pin options:
  --service-locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY

Authorize options:
  --identity-id ID
  --program-id PROGRAM_ID
  --service-locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY
  --scope SCOPE
  --action ACTION
  --challenge-type TYPE
  --challenge-value VALUE
  --artifact-json JSON
  --artifact-file PATH
  --interactive / --no-interactive

Renew options:
  --session-id ID
  --interactive / --no-interactive

Revoke options:
  --session-id ID
USAGE
}

1;

=head1 NAME

Overnet::Auth::CLI - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::CLI;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 run

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
