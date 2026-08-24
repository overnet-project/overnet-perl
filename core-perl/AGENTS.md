# Overnet Core Perl — Project Instructions

This directory contains the Perl reference implementation for the shared Overnet core, authority, and program runtime layers.

The [Overnet specification](https://github.com/overnet-project/spec) is authoritative. The implementation must conform to the spec and its fixtures. If implementation work reveals a gap or ambiguity, fix the spec first, then update the implementation.

## Priorities

When rules conflict, follow this order:

1. Overnet spec correctness
2. Preserving documented implementation behavior unless we are intentionally changing it
3. Spec fixtures and implementation tests, unless they conflict with the spec
4. Validation and documentation completeness
5. Local style rules

If a change tightens validation or otherwise changes behavior, update the spec, fixtures, tests, and any relevant documentation together.

## Spec-First Workflow

Work on the [Overnet specification](https://github.com/overnet-project/spec) and `core-perl` in parallel, but in this order:

1. Update or clarify the normative spec text in [`docs/`](https://github.com/overnet-project/spec/tree/main/docs)
2. Add or update conformance fixtures in [`fixtures/core/`](https://github.com/overnet-project/spec/tree/main/fixtures/core)
3. With a local checkout of the spec fixtures available, run `t/generate-fixtures.pl` to regenerate `t/fixtures/`
4. Run tests and confirm the new case fails for the expected reason
5. Implement the code change until tests pass
6. Re-run the relevant tests and fix all failures before considering the work done

Do not hand-edit `t/fixtures/`. They are generated artifacts.

If no fixture changes were required for a supposed spec change, treat that as a warning sign and verify whether the requirement is actually testable.

## Testing

Follow TDD strictly: write or update the spec fixture and test first, run tests to confirm they fail, then implement until they pass.

We care deeply about test quality. Cover:

- valid and invalid cases
- one-rule-at-a-time rejection cases
- edge cases and boundary conditions
- regression tests for every validation bug
- concrete wire examples from the spec

The core validator is fixture-driven. Every normative MUST or MUST NOT that the implementation enforces should have at least one corresponding fixture.

After making changes, always run the relevant tests. If a fix introduces new failures, keep iterating until all relevant tests pass.

When a task changes fixture generation, re-run fixture generation and then the validator tests.

## Fixtures

Spec fixtures in [`fixtures/core/`](https://github.com/overnet-project/spec/tree/main/fixtures/core) are the source of truth.

Implementation fixtures in `t/fixtures/` are generated from them:

- valid fixtures are re-signed with real Nostr keys so crypto validation is exercised
- invalid fixtures are copied as-is when they fail before crypto checks

Fixture rules:

- each invalid fixture should test one normative rule
- descriptions should state the rule being tested
- examples should match the spec's wire format and terminology
- when adding a new required field, tag, or semantic rule, add both passing and failing fixtures when practical

## Validation

Be strict and be consistent. Callers should not have to guess what gets rejected.

Rules:

- Always leverage `Net::Nostr` when it already provides the needed Nostr-level parsing, serialization, event-object, kind-classification, hashing, signing, or validation behavior. Do not re-implement Nostr primitives.
- Parsing of untrusted Nostr events must reject malformed input as early as possible.
- Structural checks belong as early as they can be performed reliably.
- Semantic Overnet checks belong in `validate`.
- Do not silently accept malformed protocol-critical data.
- Do not treat missing or malformed required core fields as profile-specific concerns.
- Error messages should be specific enough that fixture failures clearly identify the rejected rule.

For this project, the validation layers are:

- Nostr parsing and cryptographic validation via `Net::Nostr`
- Overnet core structural and semantic validation in `Overnet::Core::Validator`
- profile-specific rules in future modules or validators, not hidden inside unrelated checks

If a caller cannot tell whether an event passed Nostr parsing only or full Overnet validation, the API is wrong.

## Implementation Scope

The implementation is currently narrow on purpose:

- `lib/Overnet/Core/Validator.pm` contains the core validator
- `t/validator.t` runs the fixture-driven test suite
- `t/generate-fixtures.pl` syncs implementation fixtures from the spec
- `lib/Overnet/Program/` contains the shared runtime/program service layer
- `lib/Overnet/Authority/` contains non-relay authority helpers

Keep the implementation aligned with the currently specified core. Do not implement speculative profile or adapter behavior unless it has a clear normative home in the spec.

Relay daemons, relay persistence/sync, deploy packaging, and the relay-heavy IRC gate live in the [relay Perl repository](https://github.com/overnet-project/relay-perl).

### Internal Dispatch Architecture

`Overnet::CommandBus` is internal plumbing for this dist. It is how core implements its own dispatch surfaces (the program service layer and the auth agent), and it is where cross-cutting dispatch concerns such as permission checks and error normalization are implemented once as middleware.

Boundary rules:

- Dists outside `core-perl` MUST NOT depend on `Overnet::CommandBus`. Downstream systems interact with core through the specified protocol surfaces, never by constructing buses.
- Cross-cutting dispatch behavior reaches programs through the program protocol (they observe the specified envelope and error codes, not the mechanism).
- The bus belongs on a dispatch surface only when all three hold: it is a command surface (named operations, request-shaped input, uniform response and error envelope); per-operation cross-cutting concerns apply; and the dispatch is neither a protocol state machine nor a performance-critical wire loop.
- Do not promote the bus into a shared framework on the strength of one additional consumer. If multiple systems grow identical inbound-dispatch needs, design that abstraction deliberately, spec-first.

## Documentation and Drift Control

The spec is the primary documentation. When code and spec disagree, resolve the disagreement explicitly.

When implementation work exposes a spec ambiguity:

1. identify the exact missing or unclear rule
2. update the spec text
3. add or update fixtures
4. then change the implementation

Do not let the validator become the de facto spec.

## Output Requirements

At the end of every task, report:

- files changed
- behavior changes
- validation changes
- fixtures added or updated
- tests run
- spec sections consulted
- anything not verified
- follow-up risks or edge cases still worth checking

Do not claim completion if the relevant tests were not run or if spec/fixture alignment was not checked.
