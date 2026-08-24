# Overnet Perl Monorepo - Project Instructions

This repository contains the Perl reference implementation distributions that
are developed together as the Overnet platform. The distributions remain
independently buildable and releasable.

## Layout And Ownership

- `core-perl/` owns core validation, shared authority helpers, and program/runtime libraries.
- `relay-perl/` owns relay behavior, synchronization, deployment, recovery, and relay-heavy gates.
- `adapter-irc-perl/` owns IRC-specific protocol mapping.
- `overnet-burner/` owns implementation-neutral system, performance, and chaos testing.
- `overnet-perl-style/` owns the shared Perl::Critic policies and author-test templates.
- `irc-server` remains a separate repository and deployable application.
- The separate `spec` repository is authoritative for protocol behavior.

Read a component's own `AGENTS.md` before changing that component.

## Spec-First Development

When behavior and the specification disagree, fix the implementation unless
the specification is explicitly changed first. For new or changed protocol
behavior, update the specification, fixtures, tests, and implementation in
that order. Do not hand-edit generated core fixtures.

## Perl Environment

Use the single project Perl at `perl-5.42/` and run commands through the
machine-local root `.plx` layout. CPAN dependencies belong in that shared Perl.
Active Overnet distributions must be loaded from their checkout `lib/`
directories rather than installed into the shared Perl.

The component directories are not nested Git repositories, so `plx` discovers
the root layout from them. Run component suites from the corresponding
distribution root when they use relative `lib/`, `t/`, or `xt/` paths. For
example:

```bash
cd core-perl
plx prove -v t/validator.t
plx prove -r t/ xt/author/
```

## Testing

Follow strict TDD for behavior changes: add or update the test first, confirm
the expected failure, implement, then run the focused and broader relevant
suites. Run author tests for every touched distribution. Relay, IRC,
deployment, recovery, or orchestration changes also require the corresponding
live, container, release-gate, or Burner validation.

Keep cross-component behavior in the component that owns it. Do not duplicate
core validation in relay or adapter code, and do not let Burner redefine
protocol correctness.
