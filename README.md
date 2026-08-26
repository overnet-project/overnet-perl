# Overnet Perl

This monorepo contains the Perl reference implementation components developed
together as the Overnet platform. Each component remains an independently
buildable and releasable Perl distribution:

- `core-perl/` - shared validation, authority, and program runtime libraries
- `relay-perl/` - relay, synchronization, deployment, and recovery tooling
- `adapter-irc-perl/` - IRC protocol adapter
- `overnet-perl-style/` - shared Perl::Critic policy distribution and tooling

The scalable system-test harness and deployable IRC service remain in the
separate [`overnet-burner`](https://github.com/overnet-project/overnet-burner)
and [`irc-server`](https://github.com/overnet-project/irc-server) repositories.
The authoritative protocol specification remains in the separate
[`spec`](https://github.com/overnet-project/spec) repository.

## Development

The machine-local root `.plx` layout selects the shared project Perl and source
libraries. Because component directories no longer contain nested Git
repositories, `plx` can discover that layout from any distribution directory.
Run each distribution's tests from its own root so relative test paths behave
the same way they do in CI:

```bash
cd core-perl && plx prove -r t/ xt/author/
cd ../relay-perl && plx prove -r t/ xt/author/
cd ../adapter-irc-perl && plx prove -r t/ xt/author/
cd ../overnet-perl-style && plx prove -r t/ xt/author/
```

Local checkouts of the separate Burner and IRC repositories are ignored at the
monorepo root. Run their commands through the root `plx` environment so they use
the same project Perl and active monorepo sources. For example:

```bash
plx bash -c 'cd overnet-burner && prove -r -l t/ xt/author/'
```

Consult the relevant component README and tests before changing a component.

External GitHub Actions are pinned to full commit SHAs, with release comments
kept beside the pins for review. `t/github-actions-pinning.t` enforces that
policy across every workflow, and Dependabot proposes weekly updates to the
pinned references.
