package Overnet::Auth::Exchange;

use strictures 2;

our $VERSION = '0.001';

sub authentication_request {
  my ($class, %args) = @_;
  return {
    scope     => $args{scope},
    action    => 'session.authenticate',
    challenge => {type => 'opaque', value => $args{challenge},},
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => 22_242,
          tags => [[relay => $args{scope}], [challenge => $args{challenge}],],
        },
      },
    ],
  };
}

sub delegation_request {
  my ($class, %args) = @_;
  my @tags = (
    [relay      => $args{relay_url}],
    [server     => $args{scope}],
    [delegate   => $args{delegate_pubkey}],
    [session    => $args{session_id}],
    [expires_at => $args{expires_at}],
  );
  if (_nonempty_scalar($args{nick})) {
    push @tags, [nick => $args{nick}];
  }

  return {
    scope     => $args{scope},
    action    => 'session.delegate',
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => defined($args{grant_kind}) ? $args{grant_kind} : 14_142,
          tags => \@tags,
        },
      },
    ],
  };
}

sub challenge_payload {
  my ($class, %args) = @_;
  my %payload = (challenge => $args{challenge}, scope => $args{scope},);
  if (ref($args{delegation}) eq 'HASH') {
    for my $field (_delegation_fields()) {
      $payload{$field} = $args{delegation}{$field};
    }
  }
  return \%payload;
}

sub parse_challenge {
  my ($class, $payload) = @_;
  return if ref($payload) ne 'HASH';
  return if !_nonempty_scalar($payload->{challenge});
  return if !_nonempty_scalar($payload->{scope});

  my ($required, $complete) = (0, 1);
  my %delegation;
  for my $field (_delegation_fields()) {
    if (exists $payload->{$field}) {
      $required = 1;
    }
    if (!_nonempty_scalar($payload->{$field})) {
      $complete = 0;
    }
    $delegation{$field} = $payload->{$field};
  }

  return {
    challenge           => $payload->{challenge},
    scope               => $payload->{scope},
    delegation_required => $required,
    delegation          => $complete ? \%delegation : undef,
  };
}

sub response_payload {
  my ($class, %args) = @_;
  my %response = (auth_event => $args{auth_event},);
  if (defined $args{delegate_event}) {
    $response{delegate_event} = $args{delegate_event};
  }
  return \%response;
}

sub _delegation_fields {
  return qw(relay_url grant_kind delegate_pubkey session_id expires_at);
}

sub _nonempty_scalar {
  my ($value) = @_;
  return defined($value) && !ref($value) && length($value) ? 1 : 0;
}

1;

=head1 NAME

Overnet::Auth::Exchange - Shared service authentication requests and payloads

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $request = Overnet::Auth::Exchange->authentication_request(
    scope => 'https://lists.example.test/family', challenge => $challenge,
  );
  my $response = $agent_client->sessions_authorize(%context, %{$request});

=head1 DESCRIPTION

Builds the requests and combined exchange objects defined in the authentication
specification, independently of IRC framing. These helpers do not sign, approve,
or validate cryptographic authority. The auth agent and receiving service retain
those responsibilities. Callers supply program identity and service trust context.

=head1 SUBROUTINES/METHODS

=head2 authentication_request

Returns the scope, action, challenge context, and artifact request for sign-in.

=head2 delegation_request

Returns a session-delegation artifact request. An optional C<nick> is preserved
for the IRC binding; it is not required for other applications.

=head2 challenge_payload

Builds a service challenge from C<challenge>, C<scope>, and optional C<delegation>
parameters. Only public exchange fields are copied from the delegation parameters.

=head2 parse_challenge

Returns challenge and scope, or no value for an unusable authentication challenge.
Any delegation field sets C<delegation_required>. C<delegation> contains the
complete parameter set or is undefined if incomplete; callers MUST reject that
incomplete delegation, not fall back to sign-in alone. This is a shape check;
the agent still validates the requested artifact's semantics.

=head2 response_payload

Combines C<auth_event> and optional C<delegate_event> without modifying either
signed event. Encoding and transport framing belong to the caller.

=head1 DIAGNOSTICS

See C<parse_challenge> for malformed challenge handling.

=head1 CONFIGURATION AND ENVIRONMENT

No module-specific configuration is required.

=head1 DEPENDENCIES

See the distribution metadata.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

This module provides no transport, key storage, or approval policy.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
