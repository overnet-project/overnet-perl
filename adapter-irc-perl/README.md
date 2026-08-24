# Overnet Adapter IRC

Perl implementation workspace for the Overnet IRC adapter.

GitHub: <https://github.com/overnet-project/adapter-irc-perl>

This dist is intended to implement the IRC adapter specification from [spec/docs/adapters/irc.md](https://github.com/overnet-project/spec/blob/main/docs/adapters/irc.md).

## Dependency Policy

`Overnet::Adapter::IRC` depends on `Overnet` and MAY also depend directly on `Net::Nostr` when the IRC adapter specification requires explicit Nostr or NIP behavior such as `NIP-29`.

Overnet programs are the layer that SHOULD NOT depend directly on `Net::Nostr`. Programs should rely on `Overnet::*` components instead.

## Status

Initial mapping behavior is implemented.

Current supported mappings:

- channel `PRIVMSG` to `chat.message`
- channel `NOTICE` to `chat.notice`
- channel `TOPIC` to `chat.topic`
- channel `JOIN` to `chat.join`
- channel `PART` to `chat.part`
- channel-context `QUIT` to `chat.quit`
- channel `KICK` to `chat.kick`
- channel `MODE` to `irc.mode`
- direct-message `PRIVMSG` to `chat.dm_message`
- direct-message `NOTICE` to `chat.dm_notice`
- network `NICK` to `irc.nick`
- optional identity enrichment in `body.irc_identity`
- optional authoritative `NIP-29` event drafts for hosted-channel `KICK` and writable `MODE`
- optional derived authoritative IRC channel state from `NIP-29` group events

The adapter currently produces unsigned Overnet event drafts from IRC inputs.

The current design goal is fidelity to IRC semantics first. Observed IRC actions are preserved as adapted events and are not automatically treated as native Overnet authority or derived canonical state.

## Internal Design

`Overnet::Adapter::IRC` is the stable adapter facade and owns only session
lifecycle and operation dispatch. Standard IRC input mapping lives in
`InputMapper`, observed membership projection lives in `Presence`, and all
NIP-29 event mapping, state reconstruction, admission, and permission behavior
lives in `NIP29`. The collaborators share only the validation primitives in the
private `Role::Validation` role.

## Development

Run tests with:

```bash
prove -v t/
```

## Related Repositories

- [spec](https://github.com/overnet-project/spec)
- [core-perl](https://github.com/overnet-project/core-perl)
- [relay-perl](https://github.com/overnet-project/relay-perl)
- [irc-server](https://github.com/overnet-project/irc-server)

## AI Usage

This code was developed in part with AI tooling such as Claude Code and Codex. We want to be upfront about that.
