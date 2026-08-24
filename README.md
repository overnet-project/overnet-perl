# Overnet Perl

This monorepo contains the Perl reference implementation components developed
together as the Overnet platform. Each component remains an independently
buildable and releasable Perl distribution:

- `core-perl/` - shared validation, authority, and program runtime libraries
- `relay-perl/` - relay, synchronization, deployment, and recovery tooling
- `adapter-irc-perl/` - IRC protocol adapter
- `overnet-burner/` - scalable system, performance, and chaos test harness
- `overnet-perl-style/` - shared Perl::Critic policy distribution and tooling

The deployable IRC service remains in the separate
[`irc-server`](https://github.com/overnet-project/irc-server) repository. The
authoritative protocol specification remains in the separate
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
cd ../overnet-burner && plx prove -r t/ xt/author/
cd ../overnet-perl-style && plx prove -r t/ xt/author/
```

Read the root and component `AGENTS.md` files before changing a component.
