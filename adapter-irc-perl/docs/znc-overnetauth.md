# ZNC Overnet Auth Module

`contrib/znc/overnetauth.pm` is a ZNC network module that lets ordinary IRC
clients use Overnet IRC authentication through ZNC. It does not hold keys or
create Nostr signatures itself. Instead, it watches server auth prompts and
delegates response generation to an external helper such as
`overnet-irc-auth.pl bridge`.

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
  `--auth-sock /run/user/1000/overnet-auth.sock` or `--pass-entry overnet`.
- `scope=IRC_SCOPE`: scope passed to the helper for `OVERNETAUTH` prompts.
- `mode=overnetauth|sasl|both|passive`: what to start when ZNC connects to the
  IRC server. Default: `overnetauth`.
- `no_quote=true|false`: ask the helper for raw IRC output with `--no-quote`.
  Default: `true`.
- `debug=true|false`: emit short module diagnostics.

The same settings can be changed after loading:

```irc
/msg *overnetauth Set scope irc://irc.example.test/overnet
/msg *overnetauth Set helper /home/kestrel/projects/overnet/irc-server/bin/overnet-irc-auth.pl
/msg *overnetauth Set helper_args --pass-entry overnet
/msg *overnetauth Set mode both
/msg *overnetauth Show
```

`Clear scope` and `Clear helper_args` remove optional values.

## Behavior

On connect, the module starts the configured auth flow:

- `mode=overnetauth` sends `OVERNETAUTH CHALLENGE`.
- `mode=sasl` sends `AUTHENTICATE NOSTR`.
- `mode=both` sends both.
- `mode=passive` waits for server prompts.

When the server sends a line containing `OVERNETAUTH` or a SASL
`AUTHENTICATE` challenge, the module runs:

```sh
overnet-irc-auth.pl bridge --scope SCOPE --line SERVER_LINE --no-quote
```

It forwards only sanitized helper output beginning with `OVERNETAUTH ` or
`AUTHENTICATE `. If a helper emits paste-oriented `/quote ...` lines, the
module strips `/quote` before forwarding the command to the IRC server.

## Security Notes

The module intentionally leaves identity, key storage, pass integration, and
auth-agent policy to the external helper. ZNC stores only the helper command
configuration in its module state.

`helper` and `helper_args` are executed through the local shell by ZNC. Configure
them only with trusted local values. Do not expose module administration to
untrusted ZNC users.

The helper is expected to be quick and local. Keep network calls, prompting, and
long-running key-agent work behind a separate local agent when possible.

## Tests

The repository test `t/50-znc-overnetauth.t` loads the Perl module without ZNC
and checks the generic core: command construction, output sanitization, prompt
detection, and helper execution. This keeps the behavior testable in the normal
Perl test suite while the thin ZNC wrapper remains conventional modperl code.
