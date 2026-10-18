---
name: apple-passwords
description: Use passwords and verification codes saved in Apple Passwords on macOS, the way the 1Password integration works — startup secret mappings, browser sign-in via browser_vault, and op-style read/run/inject without printing secrets.
version: 0.2.1
platforms: [macos]
metadata:
  hermes:
    category: security
    tags: [security, secrets, macos, apple-passwords]
---

# Apple Passwords

The `apple-passwords` plugin connects Hermes to the user's live Apple Passwords through
apwlib, an unofficial browser-extension bridge on their Mac. Drive it with the terminal
tool (`hermes apple-passwords …`) and, for website logins, the `browser_vault` tool.

## First check

    hermes apple-passwords status

- `apwlib: missing` → tell the user to run `hermes pm repair` and restart Hermes.
- `Bridge: stopped` or `Pairing: not paired` → ask the user to run
  `hermes apple-passwords pair` **in their own local terminal** and type the PIN macOS
  shows. Never ask for the PIN or their Mac password in chat, never script the dialog,
  never try to bypass authentication.

## Logging in to a website (preferred for browser tasks)

Use `browser_vault`, never a raw password in browser tool arguments:
`action=list` → pick the `applepw:` handle for the site → navigate to the login page →
`action=fill`. Type the shown identifier yourself if the form needs it. Apple Passwords
items appear only for domains the user allowed; if the site is missing, tell the user to
run `hermes apple-passwords vault add DOMAIN` and `hermes apple-passwords vault enable`
and start a new session. Do not change vault settings yourself unless asked.

## Finding the right reference

    hermes apple-passwords list github.com

Shows saved hosts and usernames only. Use the exact host from the first column and the
percent-encoded username: `applepw://HOST/USERNAME/FIELD` with FIELD `password`,
`username` or `otp` (e.g. `applepw://github.com/me%40example.com/password`). Never pick
the first of several accounts — ask the user which one.

## Using a credential without seeing it

    hermes apple-passwords run --env SERVICE_PASSWORD=applepw://example.com/alice/password -- /absolute/path/to/trusted-command

Output is suppressed by default; do not add `--show-output` unless the user asks and the
command cannot print the credential. Never use echo, printenv, `sh -c`, tracing, or
anything that prints or forwards the environment. Check what the command does with the
credential before running it.

Templates: `{{ applepw://example.com/alice/password }}` placeholders, then

    hermes apple-passwords inject --input config.template --output private-config.txt

The output contains plaintext: never read it into context, commit it, or attach it.
Delete it when done.

## Revealing a value

    hermes apple-passwords read applepw://example.com/alice/password --reveal

Only when the user explicitly asks to see that value — it enters the transcript and the
model provider's context. Verification codes are secrets too; resolve them right before use.

## Startup secrets (API keys)

Same flow as 1Password's `hermes secrets onepassword`:
`hermes apple-passwords setup`, `set ENV_VAR REF`, `sync` (dry run), `remove ENV_VAR`,
`disable`. Values load at the next Hermes start. Don't map OTPs as startup secrets and
don't overwrite the user's other secret sources. Changing their config needs their OK.

## Limits

No whole-vault listing (Apple's bridge is per-site), no passkeys, no creating or editing
passwords, no service accounts or headless use: the user's Mac must be logged in with the
bridge paired.
