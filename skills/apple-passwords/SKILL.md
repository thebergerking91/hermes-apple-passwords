---
name: apple-passwords
description: Use passwords and verification codes saved in Apple Passwords on macOS. Pair locally, find accounts by domain, read explicit references, inject templates, and run commands with credentials without printing them.
version: 0.1.0
platforms: [macos]
metadata:
  hermes:
    category: security
    tags: [security, secrets, macos, apple-passwords]
---

# Apple Passwords

Use the installed native Hermes plugin through the terminal tool on the user's Mac.
This accesses live Apple Passwords through apwlib, an unofficial browser-extension
bridge. It does not use a separate credential vault or export CSVs.

## Setup and pairing

Run `hermes apple-passwords status`. If unavailable or unpaired, ask the user to run
`hermes apple-passwords pair` in a local interactive terminal. The user must enter
the PIN shown by macOS locally. Never request the PIN or Mac login password in chat,
script the authentication dialog, or attempt to bypass authentication. Pairing can
be required again after the bridge/browser restarts. The bridge uses a supported
Chromium browser and a downloaded copy of Apple's extension; it is not an Apple API.

## Find an account

    hermes apple-passwords list github.com

This displays only matching account metadata. Search requires a domain; no global
vault enumeration or arbitrary title search is supported. Use the exact saved
domain and username. Never choose the first result when accounts are ambiguous.

## References

Use `applepw://DOMAIN/URL-ENCODED-USERNAME/FIELD`, with field `password`, `username`,
or `otp`. Example: `applepw://github.com/person%40example.com/password`.
Percent-encode slashes, spaces, @ and other special characters in the username.
References identify credentials but contain no password values.

## Prefer command injection

    hermes apple-passwords run --env SERVICE_PASSWORD=applepw://example.com/alice/password -- /absolute/path/to/trusted-command

The child receives only a small base environment and explicit mappings. Output is
suppressed by default. Do not add `--show-output` unless the user authorizes the
output and the command will not disclose credentials. The child can still use or
send its credential; verify its purpose and destination before running it. Do not
use echo, printenv, tracing, or a command that prints the environment.

## Template injection

Place a reference in a template: `password={{ applepw://example.com/alice/password }}`.

    hermes apple-passwords inject --input config.template --output private-config.txt

The output must be a new file and is created with owner-only permissions. It contains
plaintext secrets: do not read it into model context, commit it, or include it in
attachments. Remove it when no longer needed.

## Explicit reveal only

    hermes apple-passwords read applepw://example.com/alice/password --reveal

Use only when the user explicitly asks to display that value. The output can enter
chat history and the model provider's context. Treat verification codes as secrets
too; prefer injecting a fresh code just before use.

## Startup credentials

The plugin registers `secrets.apple_passwords`. Configure explicit ENV_VAR-to-reference
mappings in the active profile's config.yaml; see the plugin README. Startup is
non-interactive and does not cache plaintext to disk. Do not map short-lived OTPs as
long-lived startup credentials. Never overwrite the user's other secret sources.

## Limits

The plugin has no passkey, SSH-agent, shared-vault administration, or service-account
mode. It does not automatically register as a Hermes browser-vault provider; current
Hermes lacks a public registration hook for that. Use command/template injection for
the user's specified task; do not put a raw password into browser tool arguments.
