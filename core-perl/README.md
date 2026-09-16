# Overnet Core Perl

Perl reference implementation workspace for the shared Overnet core, authority, and program runtime layers.

GitHub: <https://github.com/overnet-project/overnet-perl/tree/main/core-perl>

This distribution tracks the draft specifications in:

- [spec/docs/core.md](https://github.com/overnet-project/spec/blob/main/docs/core.md)
- [spec/docs/decisions.md](https://github.com/overnet-project/spec/blob/main/docs/decisions.md)
- [spec/fixtures/core/](https://github.com/overnet-project/spec/tree/main/fixtures/core)

## Status

This distribution intentionally excludes the relay application and relay-heavy integration gate.

Current implemented scope:

- Overnet event parsing and validation
- required core tags and duplicate-tag handling
- JSON `content` envelope validation
- native versus adapted provenance checks
- kind `37800` state-event checks
- `7801` removal checks
- baseline removal authorization
- baseline delegation semantics for delegated removal
- hosted-channel authority helpers
- naming v1 record/history verification and its IRC binding
- naming lookup nonces, rollback detection, and checkpoint persistence callbacks
- Overnet program runtime modules
- local auth-agent config, daemon, and client CLI
- shared fixture regeneration from `spec`
- non-relay program/runtime tests

## Naming Verification

`Overnet::Core::Naming` validates naming records against an explicitly pinned
namespace configuration. It checks real Nostr signatures, embedded requests,
canonical identities and endpoints, prior-controller authorization, complete
history, legal recorded transitions, and fresh current-head proofs. Malformed
JSON, duplicate members, and unknown profiles cannot establish authority.

`Overnet::Core::Naming::Verifier` adds one-use random lookup nonces and retained
checkpoints and conflict evidence. It requires `load_state` and `save_state`
callbacks and an explicit clock-error bound. The save callback must durably
persist the supplied snapshot before returning true; failed persistence returns
`unavailable` without an authority. Store access must have one serialized owner.
Missing state requires explicit recovery, not automatic initialization.

```perl
my $verifier = Overnet::Core::Naming::Verifier->new(
  namespace  => $pinned_config,
  epsilon    => 2,
  load_state => sub { return $store->load; },
  save_state => sub { return $store->durably_save($_[0]); },
);
my $lookup = $verifier->begin_lookup(name => '#Overnet');
# Send lookup namespace_id, name, and nonce to the configured registrar.
my $result = $verifier->verify_resolution(
  nonce   => $lookup->{nonce},
  proof   => $response->{proof},
  history => $response->{history},
);
```

Only `resolved` includes an active authority. Callers must continue to enforce
proof expiry and their monitored clock bound each time they use it. A signed
`not_found` permits an atomic registration attempt; it does not reserve a name.
POD in both modules documents input/result fields, local plaintext exceptions,
resource limits, and the explicit initial-store provisioning API.

These are shared verification components. Network lookup, a durable storage
backend, registrar transactions, runtime service dispatch, and IRC hosting
integration remain follow-up work. The components do not advertise a naming
role or cryptographically prove operational fencing and destination recovery.

`t/naming.t` constructs real signed events for the spec's normalization and
resolution scenarios and exercises unauthorized transitions, expiry, forks,
replay, storage failures, and checkpoint/conflict retention across restart.
The test bundles those two scenario files for standalone distribution testing
and checks them against a sibling spec checkout when available. Keep the copies
in `t/fixtures/naming/` synchronized with `spec/fixtures/naming/`. Registrar
atomicity, host provisioning, and application-state transfer fixtures require
the corresponding future implementations.

## Auth Agent

The reference auth-agent daemon reads one JSON config file and listens on one local auth socket.
The default socket has no authenticated program binding: it permits discovery,
but signing, session management and policy administration fail closed. A matching
Unix user or request `program_id` is not sufficient. An embedding host may supply
`caller_resolver` to `Overnet::Auth::Daemon` / `Overnet::Auth::Server`; it receives
only the connected socket, before request parsing, and must derive `program_id`
and optional administrative authority from a protected launch channel or platform
application identity. The command-line daemon does not yet provide that binding.
The client commands below require such a trusted host for privileged operations.
Local session handles expire within five minutes and cannot outlive their grants.

Static identity and backend configuration live in the daemon config file. Mutable auth-agent state lives in a separate state file managed by the daemon.

Example config:

```json
{
  "daemon": {
    "endpoint": "/tmp/overnet-auth.sock",
    "state_file": "/home/alice/.local/state/overnet/auth-state.json"
  },
  "identities": [
    {
      "identity_id": "default",
      "backend_type": "pass",
      "backend_config": {
        "entry": "overnet-priv-key"
      },
      "public_identity": {
        "scheme": "nostr.pubkey",
        "value": "274722f14ff06e2a790322ae1cee2d28c9cb0ffcd18d78d3bc7cca3f19e9764d"
      }
    }
  ]
}
```

The daemon writes `policies`, `service_pins`, and `sessions` into the configured state file atomically whenever those mutable records change.

Start the daemon with:

```bash
overnet-auth-agent.pl --config-file ~/.config/overnet/auth-agent.json
```

Query it with:

```bash
OVERNET_AUTH_SOCK=/tmp/overnet-auth.sock overnet-auth.pl identities
```

Inspect daemon-managed state with:

```text
overnet-auth.pl identities
overnet-auth.pl policies
overnet-auth.pl service-pins
overnet-auth.pl sessions
```

Manage daemon-held approval state with:

```text
overnet-auth.pl policy-grant
overnet-auth.pl policy-revoke
overnet-auth.pl service-pin-set
overnet-auth.pl service-pin-forget
```

The generic client CLI also exposes the auth/session flow methods:

```text
overnet-auth.pl authorize
overnet-auth.pl renew
overnet-auth.pl revoke
```

## Browser Authentication Connector

This connector contains the earlier Perl-backed browser integration. Its signing
flow requires a trusted caller binding in the agent host; registering the native
host alone does not supply that binding, and the default daemon refuses it. The current
TypeScript extension in `overnet-client` runs its own agent and does not need it.

`bin/overnet-auth-native.pl` connects a browser extension to the existing local
auth agent through native messaging. It accepts `agent.info`, `identities.list`,
and `browser.authenticate`; raw signing and administrative methods are rejected.
It keeps
the existing Overnet request/response envelopes and translates the browser's
native-endian 32-bit framing into the auth client's socket protocol.

From the top-level development workspace, register it for Firefox on Linux:

```sh
plx repos/overnet-perl/core-perl/deploy/native-messaging/install-firefox.pl \
  --config-file /path/to/auth-agent.json
```

The installer reads the configured agent's `daemon.endpoint` and the extension
ID from the local `overnet-client` checkout and writes a per-user native host
manifest and launcher under `~/.mozilla/native-messaging-hosts/`. The launcher
uses the workspace's `plx` configuration and existing Perl installation. The
connector reads the socket path from your existing configuration and starts the
agent when needed. Concurrent checks
share a startup lock. The agent keeps running after the browser closes; diagnostics
go to `<socket>.log` beside the socket. Re-running registration updates the launcher
and manifest, including the socket path.

The native host name is `org.overnet.auth`. Frames are limited to one MiB and
status requests time out after five seconds. Authentication allows sixty seconds
plus five seconds for cleanup. Connection failures return the structured error
`native.agent_unavailable`.

`browser.authenticate` is for the trusted extension after its approval UI obtains
consent. It accepts the browser-derived `origin`, a unique `request_id`, selected
`identity_id`, and shared service `challenge`. It constructs authentication and
optional delegation requests with `Overnet::Auth::Exchange`. It creates temporary
policies scoped to that origin, approval ID, identity, service, and action, then
revokes those policies and local renewal handles before returning signed events.
No general agent administration is exposed to websites.

This first binding supports provisional locator trust and refuses to downgrade
existing cryptographic pins. Delegation must be complete, use kind 14142, and
expire within 24 hours. Forced termination or agent failure can prevent cleanup;
approval IDs are unique and never reused by the extension. The Perl bridge remains
a development step toward a JavaScript agent. See the
browser extension README for the
website protocol and approval interface.

## Tests

Run the core test suite with:

```bash
prove -r t
```

Regenerate shared fixtures from `spec` with:

```bash
perl t/generate-fixtures.pl
```

Relay daemons, relay sync, deploy packaging, and the heavy IRC release gate now live in [relay-perl](https://github.com/overnet-project/overnet-perl/tree/main/relay-perl).

## Related Components

- [spec](https://github.com/overnet-project/spec)
- [relay-perl](https://github.com/overnet-project/overnet-perl/tree/main/relay-perl)
- [adapter-irc-perl](https://github.com/overnet-project/overnet-perl/tree/main/adapter-irc-perl)
- [irc-server](https://github.com/overnet-project/irc-server)

## Notes

Generated build artifacts and dependency caches are intentionally ignored by git.

## AI Usage

This code was developed in part with AI tooling such as Claude Code and Codex. We want to be upfront about that.
