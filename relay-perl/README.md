# Overnet Relay Perl

Perl reference implementation workspace for the Overnet relay, relay sync, deploy wrappers, and relay-backed IRC integration gate.

GitHub: <https://github.com/overnet-project/overnet-perl/tree/main/relay-perl>

This distribution depends on [core-perl](https://github.com/overnet-project/overnet-perl/tree/main/core-perl) for shared core, authority, and program runtime modules.

## Scope

This distribution owns:

- `Overnet::Relay` and the relay module tree
- relay persistence, backup, and sync CLIs
- authoritative relay helpers
- relay deploy packaging and canary topology assets
- relay-backed IRC integration and release-gate tests

Shared core validation and runtime code live in [core-perl](https://github.com/overnet-project/overnet-perl/tree/main/core-perl).

## Container Deployment

The relay includes a minimal, security-focused container image and rootless
Podman Quadlet units for its generic and authority roles. See the
[Podman and Quadlet deployment guide](deploy/podman/README.md) for image builds,
installation, configuration, persistence, security controls, and automated
Fedora base-image updates.

## Tests

Run the full relay-heavy verification path with:

```bash
prove -r t
```

The default release gate is `bin/overnet-release-gate.pl`.

It runs the IRC verification path:

- `t/spec-conformance-irc-server.t`
- `t/program-irc-server.t`
- `t/program-irc-server-relay.t`
- `t/program-irc-server-relay-fault.t`
- `t/program-irc-server-relay-failover.t`
- `t/relay-live.t`
- `t/relay-sync-live.t`
- `t/deploy-restore-drill-live.t`

Run the default release gate with:

```bash
perl bin/overnet-release-gate.pl
```

## Related Components

- [spec](https://github.com/overnet-project/spec)
- [core-perl](https://github.com/overnet-project/overnet-perl/tree/main/core-perl)
- [adapter-irc-perl](https://github.com/overnet-project/overnet-perl/tree/main/adapter-irc-perl)
- [irc-server](https://github.com/overnet-project/irc-server)

## AI Usage

This code was developed in part with AI tooling such as Claude Code and Codex. We want to be upfront about that.
