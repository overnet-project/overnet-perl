# Overnet relay — podman deployment

This directory packages the Overnet relay as a container image plus
[Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
units so it can be run and supervised as a rootless `systemd --user` service.

One image serves **two relay roles**, selected by which Quadlet unit you install:

- The **generic relay** — the `overnet-relay.pl` entrypoint, serving the
  Overnet relay protocol (publish, query, subscribe, sync, object read) with a
  persistent on-disk event store.
- The **authority relay** — the `overnet-authority-relay.pl` entrypoint, an
  authoritative NIP-29 hosted-channel relay that enforces group membership,
  moderation, and snapshot authority. This is the relay an IRC server points at
  (`--authority-relay-url`) to host channels.

## Contents

| File | Purpose |
| --- | --- |
| `Containerfile` | Builds the minimal relay image from `core-perl/` and `relay-perl/`. |
| `entrypoint.pl` | Dispatches directly to the generic or authority relay without a shell. |
| `overnet-relay.container` / `overnet-relay.volume` | Quadlet units for the generic relay. |
| `overnet-authority-relay.container` / `overnet-authority-relay.volume` | Quadlet units for the authority relay (same image, different role). |

## Published image

The tested image is published at `quay.io/overnet/relay`. Every successful
push to the `main` source branch publishes two tags:

- `main` is the convenient moving tag used by the supplied Quadlet units.
- `sha-<full-git-commit>` identifies the source commit for that build.

The workflow does not publish `latest`. It records the registry digest in the
GitHub Actions job summary after both tags resolve to the same manifest. For a
reproducible production deployment, replace the unit's image reference with
the recorded digest:

```ini
Image=quay.io/overnet/relay@sha256:<published-digest>
```

Hosted Quay.io does not currently provide registry-enforced immutable tags.
The publication workflow therefore treats `sha-<full-git-commit>` tags as
write-once: it refuses to replace one that appears during a build. On a rerun,
it pulls the existing image by digest, verifies its source labels, repeats both
smoke tests, rechecks that the commit tag has not moved, and moves `main` to
that exact tested artifact without pushing the commit tag again. The digest,
rather than either tag, remains the immutable deployment identity.

The units set `Pull=missing`, so restarting a service does not silently replace
an image already present on the host. Pull and inspect an update explicitly
before restarting the service.

### Software bill of materials

Every published image has an SPDX 2.3 JSON software bill of materials generated
from its immutable registry digest by Syft. The image embeds an inventory built
from every installed CPAN distribution's cpanm metadata and `.packlist`, plus
the locally built Overnet Core and Overnet Relay distributions. Syft merges
that inventory with its RPM and filesystem findings. CI rejects an SBOM unless
representative CPAN, Net::Nostr, and Overnet package URLs are present, so a
successful but incomplete native Perl scan cannot pass unnoticed.

The publishing workflow validates the complete document, signs it with
GitHub's workload identity, stores it as a GitHub artifact for 14 days, and
attaches the signed SBOM attestation to the image in Quay. Pull-request and
scheduled builds generate and validate an SBOM from the exact OCI archive they
smoke-tested, but cannot sign or publish one.

Verify that an image's registry-hosted SBOM was signed by the protected `main`
workflow in this repository:

```bash
gh attestation verify \
  oci://quay.io/overnet/relay@sha256:<published-digest> \
  --repo overnet-project/overnet-perl \
  --signer-workflow overnet-project/overnet-perl/.github/workflows/relay-container.yml \
  --source-ref refs/heads/main \
  --bundle-from-oci \
  --predicate-type https://spdx.dev/Document/v2.3
```

To inspect the verified SPDX document, add `--format json` and extract the
predicate rather than trusting an unattested file:

```bash
gh attestation verify \
  oci://quay.io/overnet/relay@sha256:<published-digest> \
  --repo overnet-project/overnet-perl \
  --signer-workflow overnet-project/overnet-perl/.github/workflows/relay-container.yml \
  --source-ref refs/heads/main \
  --bundle-from-oci \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --format json \
  --jq '.[0].verificationResult.statement.predicate'
```

## Why podman + Quadlet

The relay is a long-lived network service that must survive restarts and keep
a persistent store. Quadlet lets podman describe the container declaratively
and hands supervision (restart, ordering, health) to systemd, with no daemon
and no root. Everything below runs as an ordinary user.

## Prerequisites

- `podman` 4.9+ with the `systemd --user` session usable.
  For a login-independent service, enable lingering: `loginctl enable-linger`.
- The `overnet-perl` monorepo checkout for installing the supplied unit files
  or building an image locally.

## Build the image

Local development builds are optional. Run from the `overnet-perl` repository
root:

```bash
podman build \
  --file relay-perl/deploy/podman/Containerfile \
  --tag localhost/overnet-relay:latest \
  .
```

The supplied units use the published image. To exercise a local build through
Quadlet, change their `Image=` value to `localhost/overnet-relay:latest`.

The Fedora Minimal builder comes from Fedora's authoritative
`registry.fedoraproject.org/fedora-minimal` registry and is pinned to one
literal major-release tag and digest in the `Containerfile`. It is used only to
build and test the Perl distributions and assemble the runtime RPM closure. The
final image starts from `scratch`; it contains the Fedora Perl runtime, required
shared libraries and certificates, installed CPAN and Overnet modules, and the
two service scripts. It does not contain the source trees, package manager,
compiler, build tools, shell, or build-only `Alien::cmake3` payload.

## Runtime security

The final image runs as numeric UID/GID `10001:10001`. Both Quadlet units make
the image read-only, provide only the normal Podman runtime tmpfs mounts, set
`no-new-privileges`, drop every Linux capability, and cap the service at 256
processes. The named event-store volume is the only persistent writable path.

The Fedora base uses one literal release-and-digest reference so rebuilds
cannot silently select a different base, and the runtime package repository
release is derived from that image's RPM metadata. Dependabot checks the
`Containerfile` weekly and proposes reviewed release or digest updates. The
container workflow also performs a complete scheduled rebuild every week so
the current Fedora package set continues to pass both relay smoke tests.

Each build also installs the latest `CPAN::Audit` and `CPANSA::DB` into a
build-only tree and runs `cpan-audit --fresh` against the pruned CPAN tree that
will enter the final image. New CPAN advisories fail the build. Fedora-provided
Perl and core modules are excluded from this pass because Quay and Fedora scan
their RPM provenance. The small CVE-specific exception list is reviewed in
`cpan-audit-exclusions.txt`; it documents patched source and code paths that
are not reachable in this service. The audit program and database are not
copied into the runtime image.

Production builds never use `latest` for their base. Fedora major-version
updates land through reviewed pull requests and must pass the same image,
runtime, and Quadlet checks as application changes. The Quadlet health checks
use JSON exec form to invoke `/usr/bin/perl` directly, which preserves health
monitoring without adding a shell.

## Install and start the service (rootless)

```bash
mkdir -p ~/.config/containers/systemd
cp relay-perl/deploy/podman/overnet-relay.container \
   relay-perl/deploy/podman/overnet-relay.volume \
   ~/.config/containers/systemd/

systemctl --user daemon-reload
systemctl --user start overnet-relay
```

Quadlet generates a transient `overnet-relay.service` from the `.container`
file. Manage it like any user service:

```bash
systemctl --user status overnet-relay
journalctl --user -u overnet-relay -f
```

## Verify

The relay writes readiness transitions to its log and maintains a health file
inside the store volume:

```bash
# Readiness and other lifecycle lines are logged to the journal:
journalctl --user -u overnet-relay | grep '\[relay.health\]'

# The health file reports ready/stopping/stopped with the listen address:
podman exec overnet-relay \
  perl -0777 -pe 1 /var/lib/overnet/relay/health.json
```

The Quadlet unit also defines a podman health check that opens a TCP
connection to the listener; `podman healthcheck run overnet-relay` runs it on
demand.

## Configuration

Tuning knobs are the `overnet-relay.pl` arguments after the `relay` role on the
unit's `Exec=` line. Edit them in place, then reload:

```bash
$EDITOR ~/.config/containers/systemd/overnet-relay.container
systemctl --user daemon-reload
systemctl --user restart overnet-relay
```

Commonly adjusted arguments:

| Argument | Meaning |
| --- | --- |
| `--relay-profile` | Relay capability profile (default `volunteer-basic`). |
| `--max-connections-per-ip` | Per-IP connection cap. |
| `--event-rate-limit` | Publish rate limit as `COUNT/SECONDS`. |
| `--service-policy NAME=VALUE` | Per-operation access policy (`publish`, `query`, `subscribe`, `sync`, `object_read`). |
| `--store-file` | Store path; must stay inside the mounted volume. |

Run `podman run --rm quay.io/overnet/relay:main relay --help` for the full
argument list. Replace `relay` with `authority` for the authority relay.

## Persistence

The event store lives in the `overnet-relay-store` named volume, mounted at
`/var/lib/overnet/relay`. The store file is append-structured JSON lines and
survives container restarts, rebuilds, and image updates. To inspect or back
it up:

```bash
podman volume inspect overnet-relay-store
```

The `overnet-relay-backup.pl` and `overnet-relay-sync.pl` tools in `bin/`
operate on this store for backups and relay-to-relay replication.

## Public exposure

`PublishPort` defaults to `127.0.0.1:7447:7447`, so the relay is reachable
only from the host. For a public relay, terminate TLS in a reverse proxy in
front of the loopback listener (recommended), or change `PublishPort` to bind
a public address directly. Overnet relays speak `ws://`; public deployments
should be fronted as `wss://`.

## Authority relay (hosted NIP-29 channels)

The `overnet-authority-relay.container` unit runs the **same image** and selects
its `authority` role. Install it exactly like the generic relay:

```bash
cp relay-perl/deploy/podman/overnet-authority-relay.container \
   relay-perl/deploy/podman/overnet-authority-relay.volume \
   ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start overnet-authority-relay
```

It listens on `127.0.0.1:7448` by default, on its own
`overnet-authority-relay-store` volume, so it can run alongside a generic relay.
Two settings on its `Exec=` line matter for correctness:

- `--relay-url` participates in authorization (delegation grants reference it).
  Set it to the public `wss://` URL that IRC servers and clients actually use.
- `--snapshot-pubkey <64-hex>` (repeatable) authorizes group-metadata snapshot
  signers. **By default none is trusted, so every `39xxx` snapshot is rejected**
  until you add one — this is the safe default, not a misconfiguration.

Point an IRC server at it with `--authority-relay-url ws://<host>:7448` (see
`irc-server/deploy/podman/`).

## Updating

Pull the reviewed image and restart:

```bash
podman pull quay.io/overnet/relay:main
systemctl --user restart overnet-relay
```

For a pinned production deployment, update `Image=` to the new digest and run
`systemctl --user daemon-reload` before restarting. The store volume is
independent of the image, so data is retained across updates.
