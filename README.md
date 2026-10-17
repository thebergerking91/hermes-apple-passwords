# Hermes Apple Passwords

A native Hermes Agent plugin for credentials already saved in **Apple Passwords /
iCloud Keychain** on a Mac. Includes a discoverable Hermes skill, CLI commands, and
a mapped SecretSource backend. It does not create a replacement password vault.

**Status: experimental, pending live macOS validation.** Portable behavior tests can
validate parsing, selection, isolation and Hermes integration, but do not prove
Apple's browser bridge works on your particular macOS/browser combination. See
VALIDATION.md for the tests actually run and the remaining Mac checklist.

## How it compares to Hermes's 1Password integration

| 1Password workflow | This plugin |
|---|---|
| Interactive desktop authorization | Local pairing PIN displayed by macOS |
| Read a referenced credential | `hermes apple-passwords read REF --reveal` |
| Resolve credentials into a child process | `hermes apple-passwords run --env NAME=REF -- command` |
| Inject references into a template | `hermes apple-passwords inject --input template --output new-file` |
| Fetch verification codes | Reference ending in `/otp` |
| Load configured API credentials at startup | `secrets.apple_passwords.env` mappings |
| Agent knows when/how to use it | Plugin-owned `apple-passwords:apple-passwords` skill |
| Service-account / headless authorization | Not supported; a local paired Mac session is required |
| Global vault search / vault administration | Not supported; exact domain/account lookup only |
| Browser-vault autofill backend | Not registered; Hermes currently lacks a public plugin hook for it |

Apple does not supply an `op`-equivalent public CLI. This plugin depends on
[apwlib](https://github.com/michel-tricot/apwcli/tree/main/packages/apwlib), pinned
to 0.1.2. It uses an **unofficial** bridge through a headless supported browser and
a modified runtime copy of Apple's iCloud Passwords extension. It requires normal
local pairing and does not bypass authentication. The dependency controls browser
lifecycle and may download the extension on first pairing. Apple/browser changes
can break this mechanism.

## Requirements

- macOS 14+ for the bridge; the standalone Apple Passwords app is macOS 15+.
- Python 3.12+ in the Hermes environment.
- Default `plugins.isolation: in_process` mode. Hermes currently skips plugin CLI
  registration in `host` isolation mode. Do not change an operator-enforced isolation
  policy to enable this plugin; its CLI workflow is not supported in that mode.
- Hermes with SecretSource API v1, CLI command registration, and plugin-owned skills.
  The source interface was inspected at Hermes commit
  `e6f57427c198cfd96854522b7a9159eb007e13c2`.
- Apple Passwords/iCloud Keychain configured in your Mac user account.
- A supported browser installed: Chrome, Brave, Edge, or Chromium.
- An interactive local terminal for pairing. After pairing, reads can be
  non-interactive while the daemon and authorization remain available.

## Install the supplied source package

Unzip the package, open Terminal on your Mac, and change into its directory:

    cd /path/to/hermes-apple-passwords
    python3 install.py
    hermes plugins enable apple-passwords
    hermes apple-passwords pair
    hermes apple-passwords status

The installer copies this plugin to `$HERMES_HOME/plugins/apple-passwords`, using
`~/.hermes` when HERMES_HOME is unset. For a profile, explicitly select its home:

    python3 install.py --home /absolute/path/to/your/hermes-profile

Then run the enable/pair commands in that same Hermes profile. Enabling lets Hermes's
package manager install the declared dependency. Do not use raw pip to modify the
Hermes-managed environment. The installer refuses to overwrite an existing plugin
and does not edit configuration or handle credentials.

Start a new Hermes conversation after enabling so its skill appears. Pairing is
operator-only: enter the six-digit macOS PIN locally, never in agent chat. Pair again
if the daemon/browser restarts. The bridge is shared by processes under your macOS
user; it is not an independently secured vault for each Hermes profile.

## Use your credentials

Find the exact saved account without printing its password:

    hermes apple-passwords list github.com

References use `applepw://DOMAIN/ENCODED-USERNAME/FIELD`. Fields are `password`,
`username`, and `otp`. Encode the username as a URL path component; for example,
`person@example.com` becomes `person%40example.com`. Matching checks the exact saved
domain and username and rejects duplicate matches. If a credential is saved under
`www.example.com`, use that saved host rather than assuming sibling hosts match.

Run a trusted command with a password available only in its environment:

    hermes apple-passwords run \
      --env SERVICE_PASSWORD=applepw://example.com/alice/password \
      -- /absolute/path/to/your-command

Child output is discarded by default; the command's exit code is returned. Add
`--show-output` only when you intend its output to be visible. The child gets a
small base environment plus explicit mappings, not all of Hermes's API keys. This
is credential delivery, **not a sandbox**: the child can transmit its credential,
write files, or spawn other programs. Use a command and destination you trust.

For templates, put `{{ applepw://example.com/alice/password }}` where the value belongs:

    hermes apple-passwords inject --input config.template --output private-config.txt

The output is a new owner-only file (0600); existing files and output symlinks are
refused. Substitution is literal, without escaping for JSON, shell, YAML or any
other format. Use a format-compatible template. The file contains plaintext and
must not be committed or read into the model context; remove it after use.

To deliberately print a credential, including an OTP:

    hermes apple-passwords read applepw://example.com/alice/password --reveal
    hermes apple-passwords read applepw://example.com/alice/otp --reveal

These commands expose the value to stdout. When invoked by an agent, it can reach
the model provider and transcript. Prefer `run` to use a credential without printing
it. OTP values are short-lived; resolve immediately before use, not at startup.

## Startup secret source

Merge the example into your active profile's config.yaml, retaining other plugins
and sources:

    plugins:
      enabled:
        - apple-passwords
    secrets:
      apple_passwords:
        enabled: true
        override_existing: false
        timeout_seconds: 45
        env:
          EXAMPLE_API_KEY: applepw://example.com/alice/password

Store the desired API key as the password field of that Apple Passwords entry.
The configuration contains only references. The plugin returns resolved values to
Hermes's normal secret orchestrator; it does not write os.environ itself. Existing
environment/.env values win unless override_existing is enabled. A failed lookup
discards the entire source fetch. Hermes can still start or use another configured
source; this is not a global startup enforcement policy.

Startup fetches never start a daemon, prompt for a PIN, or pair automatically. The
plugin has no plaintext disk cache. Values necessarily exist in process memory and
in the selected consumer's environment; other enabled in-process plugins share
that trust boundary. The plugin's domain mappings are intent controls, not isolation
from arbitrary code running as the same Mac user.

## Troubleshooting

- Unknown command: enable the plugin in the active profile and check
  `hermes plugins list` for dependency/load errors.
- Missing dependency: Python must be 3.12+; use Hermes's plugin enable workflow.
- Bridge stopped/unpaired: run `hermes apple-passwords pair` locally.
- Lookup fails: run `list` for the exact saved domain and check the username; the
  plugin intentionally rejects ambiguous or broader-domain results.
- Background startup fails: log into the Mac and pair interactively first. A remote
  Linux host or a fresh headless boot cannot read this Mac's Passwords through the plugin.

## Development and provenance

No Hermes core files are modified. Source references:

- [Hermes 1Password skill](https://github.com/NousResearch/hermes-agent/blob/e6f57427c198cfd96854522b7a9159eb007e13c2/optional-skills/security/1password/SKILL.md)
- [Hermes SecretSource plugin API](https://github.com/NousResearch/hermes-agent/blob/e6f57427c198cfd96854522b7a9159eb007e13c2/website/docs/developer-guide/secret-source-plugin.md)
- [apwlib inspected source](https://github.com/michel-tricot/apwcli/tree/fecfda7005dd49f1856526a80235d38a11a24c15/packages/apwlib)

This plugin is MIT licensed; apwlib is a separate MIT dependency. No Apple extension
code or upstream CLI code is bundled. This project is not affiliated with Apple or
Nous Research. See SECURITY.md for the credential boundaries and VALIDATION.md for
test commands and the required real-Mac checks.
