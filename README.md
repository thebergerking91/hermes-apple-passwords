# Hermes Apple Passwords

A native Hermes Agent plugin for credentials already saved in **Apple Passwords /
iCloud Keychain** on a Mac. It works the way Hermes's built-in 1Password integration
works:

- a **startup secret source** (`secrets.apple_passwords`, like `secrets.onepassword`);
- an operator **CLI** (`hermes apple-passwords …`, like `hermes secrets onepassword …` plus `op read/run/inject`);
- a **browser-vault login backend** (like `vault.onepassword`) so the agent can sign you in
  without ever seeing the password;
- a plugin-owned **skill** that tells the agent when and how to use it.

It does not create a replacement password vault.

**Status: functional (v0.2.0), validated on one Mac.** The full real-Mac checklist passed on
macOS 27.0.1 with Google Chrome 155 against Hermes `d923a5eb48`, including a real browser
sign-in through `browser_vault`. Apple's bridge is unofficial, so other macOS/browser
combinations and future Apple changes are unverified. See VALIDATION.md.

## How it maps to Hermes's 1Password integration

| 1Password in Hermes | Apple Passwords plugin |
|---|---|
| `hermes secrets onepassword setup` | `hermes apple-passwords setup` |
| `hermes secrets onepassword status` | `hermes apple-passwords status` |
| `hermes secrets onepassword set ENV op://…` / `remove ENV` | `hermes apple-passwords set ENV applepw://…` / `remove ENV` |
| `hermes secrets onepassword sync` (dry run) | `hermes apple-passwords sync` (dry run) |
| `hermes secrets onepassword disable` | `hermes apple-passwords disable` |
| `secrets.onepassword.env` startup mappings | `secrets.apple_passwords.env` startup mappings |
| `override_existing: true` default, per-ref warnings | same |
| Desktop-app / service-account authorization | Local pairing: a six-digit PIN shown by macOS (`hermes apple-passwords pair`) |
| `op read` | `hermes apple-passwords read REF --reveal` |
| `op run --env-file` | `hermes apple-passwords run --env NAME=REF -- command` |
| `op inject` | `hermes apple-passwords inject --input template --output new-file` |
| `op item get --otp` | Reference ending in `/otp` |
| `vault.onepassword` → `browser_vault` list/fill/2FA | `vault.apple_passwords` → `browser_vault` list/fill/2FA (opt-in, per domain) |
| Cache: memory + 0600 disk file | Memory only (no plaintext on disk) |
| Service-account / headless use | **Not supported**: a logged-in, paired Mac session is required |
| `op item list` (whole vault) | **Not possible**: Apple's bridge only answers per-site queries, so lookups and the vault backend need a domain |

Apple does not ship an `op`-equivalent CLI. This plugin depends on
[apwlib](https://github.com/michel-tricot/apwcli/tree/main/packages/apwlib) 0.1.2, an
**unofficial** bridge that runs a headless Chromium-family browser with a downloaded copy of
Apple's iCloud Passwords extension. It uses Apple's normal PIN pairing and does not bypass
authentication. Apple or browser changes can break it.

## Requirements

- macOS 14+ with iCloud Keychain / Apple Passwords set up for your user.
- Chrome, Brave, Edge, or Chromium installed.
- Hermes with SecretSource API v1, plugin CLI commands, and plugin skills (tested against
  Hermes `d923a5eb487a17c0a68801bba9ef0f56c81040a8`).
- Default `plugins.isolation: in_process`. In `host` isolation Hermes skips plugin CLI
  commands and the browser-vault backend cannot reach the agent process. Don't weaken an
  operator-enforced isolation policy for this plugin.
- A local interactive terminal for pairing.

## Install

From GitHub (Hermes installs the declared Python dependencies with your consent):

    hermes plugins install thebergerking91/hermes-apple-passwords --enable

Or from a local checkout (copies files into the profile; refuses to overwrite):

    python3 install.py                       # or: python3 install.py --home /path/to/profile
    hermes plugins enable apple-passwords

If `hermes apple-passwords status` reports `apwlib: missing`, run `hermes pm repair` and
restart Hermes. Never raw-`pip install` into Hermes's managed environment.

## Set up (same flow as 1Password)

    hermes apple-passwords setup          # enable secrets.apple_passwords
    hermes apple-passwords pair           # in a local terminal; type the PIN macOS shows
    hermes apple-passwords list github.com
    hermes apple-passwords set GITHUB_TOKEN applepw://github.com/me%40example.com/password
    hermes apple-passwords sync           # dry run: what would be exported, never values
    hermes apple-passwords status

Start a new Hermes session afterwards. Mapped values are loaded at startup through Hermes's
secret orchestrator, exactly like `secrets.onepassword`.

Pairing is operator-only: type the PIN locally, never in agent chat. Pairing lasts for the
bridge's lifetime; pair again after every reboot or logout and whenever the bridge's
browser restarts (Apple issues a new PIN per pairing by design). Startup
never starts the bridge, prompts, or pairs — an unpaired bridge is reported with a remediation
hint and Hermes carries on without those values.

## References

`applepw://HOST/URL-ENCODED-USERNAME/FIELD`, with FIELD `password`, `username`, or `otp`.
Percent-encode the username (`me@example.com` → `me%40example.com`).

Apple stores sites as bare hosts and strips a leading `www.` when saving, so a login saved on
`www.github.com` is listed (and referenced) as `github.com`; browser sign-in fills it on both.
Apple answers per registrable domain, so `list github.com` also shows logins saved for
`gist.github.com` or `www.github.com`. The first column of `list` is the **exact saved host**
— use that in the reference. Lookups match the exact saved host and username and fail on
duplicates; they never silently fall back to a sibling host or another account.

## Use credentials without printing them

    hermes apple-passwords run --env SERVICE_PASSWORD=applepw://example.com/alice/password -- /path/to/command

The child gets a small base environment plus your mappings (not Hermes's API keys); its
output is discarded unless you pass `--show-output`; its exit code is returned. Names that
would replace the base environment (`PATH`, `HOME`, …) or start with `DYLD_`/`LD_` are
refused. This is credential delivery, **not a sandbox**.

Templates: put `{{ applepw://example.com/alice/password }}` where the value belongs, then

    hermes apple-passwords inject --input config.template --output private-config.txt

The output is a new 0600 file; existing files and symlinks are refused; substitution is
literal (no JSON/YAML/shell escaping). Don't commit it or read it into the model's context.

Deliberate reveal (the value reaches stdout, and an agent's transcript if an agent runs it):

    hermes apple-passwords read applepw://example.com/alice/password --reveal
    hermes apple-passwords read applepw://example.com/alice/otp --reveal

## Browser sign-in (`browser_vault`)

Like `vault.onepassword`, this lets the agent fill a login form while the password stays
server-side: the model sees only a handle, the site and the username.

    hermes apple-passwords vault add github.com
    hermes apple-passwords vault enable
    hermes apple-passwords vault status

Then start a new session and ask the agent to log in. It calls `browser_vault action=list`,
gets an `applepw:` handle, and `action=fill` fills only on the exact saved origins. If the
login stores a verification code, `enter_code` uses it automatically.

Differences from 1Password: because Apple's bridge cannot enumerate the vault, only the
domains you add (and their subdomains) are listed. Apple Passwords logins do not appear in
`hermes vault list`/`hermes vault sources`. Hermes has no public plugin hook for login
backends yet, so this plugin wraps Hermes's backend list in-process; it is defensive (any
mismatch disables only this backend) but could need an update when Hermes changes. Turn it
off with `hermes apple-passwords vault disable`.

## Configuration reference

    secrets:
      apple_passwords:
        enabled: true
        override_existing: true    # 1Password default: the secret manager wins over .env
        timeout_seconds: 45        # whole-fetch budget, max 120
        cache_ttl_seconds: 300     # in-memory only; 0 disables
        env:
          EXAMPLE_API_KEY: applepw://example.com/alice/password
    vault:
      apple_passwords:
        enabled: true
        domains: [example.com]

As with 1Password, an unresolved mapping is a warning and the other mappings still load; if
nothing resolves, the error and a remediation hint are shown. Set `override_existing: false`
to let `.env`/shell values win.

## Troubleshooting

- `apwlib: missing` → `hermes pm repair`, then restart Hermes.
- `Bridge: stopped` / `not paired` → `hermes apple-passwords pair` in a local terminal.
- "No saved login matches" → `hermes apple-passwords list DOMAIN` and copy the exact host and username.
- "More than one saved login matches" → remove the duplicate in the Passwords app.
- Unknown command → check `hermes plugins list` for load errors and that isolation is `in_process`.
- A remote/headless host cannot read this Mac's Passwords; the bridge needs your logged-in session.

## Development and provenance

No Hermes core files are modified. References:
[Hermes 1Password secret source](https://github.com/NousResearch/hermes-agent/blob/d923a5eb487a17c0a68801bba9ef0f56c81040a8/agent/secret_sources/onepassword.py),
[SecretSource plugin API](https://github.com/NousResearch/hermes-agent/blob/d923a5eb487a17c0a68801bba9ef0f56c81040a8/website/docs/developer-guide/secret-source-plugin.md),
[1Password vault backend](https://github.com/NousResearch/hermes-agent/blob/d923a5eb487a17c0a68801bba9ef0f56c81040a8/agent/vault_backends/onepassword.py),
[apwlib source](https://github.com/michel-tricot/apwcli/tree/fecfda7005dd49f1856526a80235d38a11a24c15/packages/apwlib).

MIT licensed; apwlib is a separate MIT dependency. No Apple extension code is bundled. Not
affiliated with Apple or Nous Research. See SECURITY.md and VALIDATION.md.
