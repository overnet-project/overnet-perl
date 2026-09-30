# ZNC Overnet Auth Module

`contrib/znc/overnetauth.pm` is a ZNC network module that lets ordinary IRC
clients use Overnet IRC authentication through ZNC. It does not hold keys or
create Nostr signatures itself. Instead, it watches server auth prompts and
delegates response generation to an external helper such as
`overnet-irc-auth.pl bridge`.

The helper is part of the trust boundary. It must sign as the owner of the IRC
account/network being authenticated, not merely as the Unix user running ZNC.
For example, a shared ZNC daemon must not be pointed at another user's auth
agent socket just because that socket exists on the same host.

This keeps the compatibility boundary at the bouncer: IRC clients keep speaking
normal IRC to ZNC, while ZNC speaks `OVERNETAUTH` or SASL `NOSTR` to the
Overnet-aware IRC server.

## Installation

ZNC must be built with Perl support and the global `modperl` module must be
loaded. ZNC's modperl documentation says Perl modules are files named
`modulename.pm`, the package name must match the file name, and modules derive
from `ZNC::Module`.

Copy the module into a ZNC module directory:

```sh
mkdir -p ~/.znc/modules
cp contrib/znc/overnetauth.pm ~/.znc/modules/
```

Load ZNC's Perl support as a global module if it is not already loaded:

```irc
/msg *status LoadMod modperl
```

If your distribution packages ZNC without Perl support, rebuild or install ZNC
with `--enable-perl` or CMake `-DWANT_PERL=ON`.

## Configuration

Load this as a network module:

```irc
/msg *status LoadMod --type=network overnetauth scope=irc://irc.example.test/overnet
```

Useful options:

- `helper=COMMAND`: helper executable or shell command prefix. Default:
  `overnet-irc-auth.pl`.
- `helper_args=ARGS`: extra shell arguments passed after `bridge`, such as
  `--auth-sock /run/user/1000/overnet-auth.sock`.
- `scope=IRC_SCOPE`: scope passed to the helper for `OVERNETAUTH` prompts.
- `mode=overnetauth|sasl|both|passive`: what to start when ZNC connects to the
  IRC server. Default: `overnetauth`.
- `no_quote=true|false`: ask the helper for raw payload output with
  `--no-quote`. Default: `false`; the module strips paste-oriented `/quote`
  prefixes itself.
- `auto_delegate=true|false`: after successful `OVERNETAUTH AUTH`, request an
  authoritative relay delegation for channel writes. Default: `true`.
- `debug=true|false`: emit short module diagnostics.

The same settings can be changed after loading:

```irc
/msg *overnetauth Set scope irc://irc.example.test/overnet
/msg *overnetauth Set helper /home/kestrel/projects/overnet/irc-server/bin/overnet-irc-auth.pl
/msg *overnetauth Set helper_args --auth-sock /run/user/1000/overnet-auth.sock
/msg *overnetauth Set mode both
/msg *overnetauth Set auto_delegate true
/msg *overnetauth Show
```

`Clear scope` and `Clear helper_args` remove optional values.

Use `Doctor` to show the current configuration and warnings:

```irc
/msg *overnetauth Doctor
```

## Behavior

On connect, the module starts the configured auth flow:

- `mode=overnetauth` sends `OVERNETAUTH CHALLENGE`.
- `mode=sasl` sends `AUTHENTICATE NOSTR`.
- `mode=both` sends both.
- `mode=passive` waits for server prompts.

After a successful `OVERNETAUTH AUTH` response, the module sends
`OVERNETAUTH DELEGATE` by default. Authoritative hosted channel writes, such as
creating or joining a NIP-29-backed channel through an authority relay, require
this delegated signing session. You can also request it manually:

```irc
/msg *overnetauth Delegate
```

When the server sends a line containing `OVERNETAUTH` or a SASL
`AUTHENTICATE` challenge, the module runs:

```sh
overnet-irc-auth.pl bridge --scope SCOPE --line SERVER_LINE
```

It forwards only sanitized helper output beginning with `OVERNETAUTH ` or
`AUTHENTICATE `. If a helper emits paste-oriented `/quote ...` lines, the
module strips `/quote` before forwarding the command to the IRC server.

Only real `OVERNETAUTH CHALLENGE ...`, parameterized `OVERNETAUTH DELEGATE ...`,
and SASL `AUTHENTICATE` challenge lines are sent to the helper. Success and
error notices such as `OVERNETAUTH AUTH <pubkey>` or `OVERNETAUTH DELEGATE is
required ...` are not treated as signing prompts.

## Security Notes

The module intentionally leaves identity, key storage, pass integration, and
auth-agent policy to the external helper. ZNC stores only the helper command
configuration in its module state. Make that configuration per network/account:
the helper must authenticate the person who owns that ZNC network entry.

`helper` and `helper_args` are executed through the local shell by ZNC. Configure
them only with trusted local values. Do not expose module administration to
untrusted ZNC users.

If the helper exits nonzero, the module reports the failure and the first short
diagnostic line back to the ZNC module buffer. This is intentional: silent auth
failure can otherwise leave a client connected but unable to perform
authoritative channel writes.

The helper is expected to be quick and local. Keep network calls, prompting, and
long-running key-agent work behind a separate local agent when possible.

## Tests

The repository test `t/50-znc-overnetauth.t` loads the Perl module without ZNC
and checks the generic core: command construction, output sanitization, prompt
detection, and helper execution. This keeps the behavior testable in the normal
Perl test suite while the thin ZNC wrapper remains conventional modperl code.
