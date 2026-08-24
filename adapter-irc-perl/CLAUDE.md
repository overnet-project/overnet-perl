# Overnet Adapter IRC — Project Instructions

This directory contains the IRC adapter implementation for Overnet.

The authoritative specification lives in:

- `../spec/docs/core.md`
- `../spec/docs/adapters/irc.md`
- `../spec/fixtures/irc/`

The Overnet core spec remains authoritative for all core semantics. The IRC adapter spec is authoritative for IRC-specific mapping, identity, provenance, and capability behavior.

## Priorities

When rules conflict, follow this order:

1. Overnet core spec correctness
2. IRC adapter spec correctness
3. Preserving documented adapter behavior unless intentionally changing it
4. Fixtures and tests
5. Validation and documentation completeness
6. Local style rules

## Workflow

Work in this order:

1. update or clarify the IRC adapter spec in `../spec/docs/adapters/irc.md`
2. add or update IRC fixtures in `../spec/fixtures/irc/`
3. add or update adapter tests here
4. run tests to confirm failures
5. implement until tests pass
6. re-run the relevant tests before considering the work done

Do not let the adapter implementation become the de facto IRC spec.

## Adapter Fidelity

Adapters must preserve source-system semantics as faithfully as possible.

Use this checklist when designing or changing a mapping:

1. What is the true scope in the source system: network, object, channel, user, session, or something else?
2. Is this source concept state, an event, or only an observation of another system's state?
3. Are we overstating identity stability, object stability, authorship, authority, or capability?
4. Are we turning a derived or convenience view into the canonical meaning of the adapted data?
5. Does a generic Overnet name preserve the source meaning, or does this need a source-specific object or event type?
6. What information is lost, synthetic, partial, delayed, or policy-shaped, and how is that disclosed?

When in doubt, prefer fidelity to the source system over symmetry with existing adapter event names.

## Testing

Follow TDD strictly.

Add tests for:

- IRC identity mapping
- channel and message mapping
- provenance and limitations
- lossy or ambiguous translations
- rejection paths and invalid inputs

Run tests with:

```bash
/opt/perl-5.42/bin/prove -Ilib -v t/
```

## Scope

This dist should contain IRC-specific implementation logic only.

Do not copy Overnet core validation rules into this dist unless the adapter specifically needs to enforce them at its own boundary.

Shared core semantics should stay in `core-perl/`.

## Dependencies

`Overnet::Adapter::IRC` MAY depend on `Net::Nostr` directly when the IRC adapter specification requires explicit Nostr or NIP behavior such as `NIP-29`.

Overnet programs are the layer that SHOULD NOT import `Net::Nostr` directly. Programs should rely on `Overnet::*` components instead.

## Output Requirements

At the end of every task, report:

- files changed
- behavior changes
- validation changes
- fixtures updated or not
- tests run
- spec sections consulted
- anything not verified
