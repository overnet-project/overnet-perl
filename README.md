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

All component commands are run from this repository root through the shared
project Perl:

```bash
plx prove -r core-perl/t/
plx prove -r relay-perl/t/
plx prove -r adapter-irc-perl/t/
plx prove -r overnet-burner/t/
plx prove -r overnet-perl-style/t/
```

Read the root and component `AGENTS.md` files before changing a component.

