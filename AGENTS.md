# Agent instructions

These instructions apply to the entire repository. Read `README.md`,
`SECURITY.md`, and `VALIDATION.md` before changing behavior.

## Purpose and scope

This is a native Hermes Agent plugin for credentials stored in Apple Passwords
on macOS. It mirrors Hermes's built-in 1Password integration: a mapped
SecretSource (`secrets.apple_passwords`), an operator CLI (`setup/status/set/remove/
sync/disable` plus `pair/list/read/run/inject/vault`), an opt-in `browser_vault`
login backend (`vault.apple_passwords`), and a discoverable skill. Document every
difference from 1Password accurately.

The backend uses the unofficial `apwlib` browser bridge. Do not replace it with
generic login Keychain access, a CSV export, or a separate vault and claim
equivalent Apple Passwords support. Passkeys, service accounts, bulk export, and
credential mutation are out of scope. Do not claim those capabilities without
implementation and validation.

## Repository map

- `__init__.py`: Hermes registration; keep imports lazy. Installs the vault wrapper
  only in-process (never inside a plugin host process).
- `plugin.yaml`: plugin metadata and pinned dependency declarations.
- `backend.py`: standalone worker (stdlib + lazy apwlib only) run as
  `python -P backend.py OP [-- VALUES]`; one JSON line on stdout. The protocol and
  error kinds are the contract between it and `bridge.py`; change both together.
- `bridge.py`: Hermes-side launcher. Passes the dependency directories explicitly,
  because Hermes's `run_secret_cli` strips `PYTHONPATH`; pairing runs with
  `PYTHONSAFEPATH=1` and a safe cwd because it can start the long-lived daemon.
- `source.py`: SecretSource with 1Password-parity semantics (override default true,
  per-ref warnings, in-memory cache only) and helpers used by the CLI.
- `cli.py`: `hermes apple-passwords …`. Never use argparse dests `command` or `func`:
  Hermes's `main()` reads `args.command` before dispatch.
- `vault.py`: `LoginBackend` for `browser_vault`. Hermes has no public hook, so it
  wraps `agent.vault_backends.enabled_backends` (package and `base` attributes).
  Keep it defensive: any mismatch must disable only this backend. Origins come from
  one Apple entry only; colliding handles are dropped, never merged.
- `install.py`: source installer; preserve profile selection and overwrite refusal.
  New runtime modules must be added to its copy list.
- `skills/apple-passwords/SKILL.md`: instructions exposed to Hermes users/agents.
- `tests/`: synthetic unit tests and real Hermes loader/orchestrator integration.
- `config.example.yaml`: reference-only configuration example.

## Credential boundaries to preserve

- Never use production credentials in tests, fixtures, screenshots, logs, commits,
  issue reports, or model context. Use synthetic values and disposable profiles.
- Pairing is an explicit operator action in a local terminal using Apple's normal
  authentication flow. Never request a pairing PIN in agent chat or bypass authentication.
- Startup resolution must not prompt, pair, or start a daemon. Preserve closed stdin,
  bounded timeouts, and the allowlisted worker environment.
- Match the exact saved host and username. Reject ambiguous matches; do not silently
  fall back to sibling domains, broader domain matches, or another account.
- Return metadata only from list. Keep backend exceptions and stderr out of agent
  responses; use sanitized errors that cannot contain credential values.
- Keep explicit `--reveal` gating for reads and suppress child output by default.
  Preserve the explicit `--show-output` opt-in.
- Run child commands without a shell and with a minimal environment plus requested
  mappings. Do not inherit unrelated Hermes API keys.
- Template injection must create a new owner-only file (0600), refuse overwrites
  and symlinks, and validate references. Substitution is literal, not format-aware.
- Do not add plaintext credential caches, telemetry containing secrets, clipboard
  transfer, or automatic vault enumeration.
- Preserve 1Password-parity source semantics: `override_existing` defaults to true,
  an unresolved mapping is a warning while the others load, and one-time-code refs
  are refused as startup mappings. Return values through Hermes's secret orchestrator
  rather than changing `os.environ` directly.
- Do not describe environment injection, profile mappings, or a shared same-user
  daemon as a security sandbox or multi-tenant isolation boundary.

## Implementation guidance

Use Python 3.12+ and the public Hermes plugin interfaces. Keep changes focused;
avoid Hermes core patches or speculative integration hooks. Check upstream
interfaces before changing compatibility assumptions. Preserve reference syntax
`applepw://DOMAIN/ENCODED-USERNAME/password|username|otp`.

Review dependency changes deliberately: `apwlib` is trusted credential-handling
code, currently pinned in `plugin.yaml`. Do not silently unpin it. Document
compatibility changes and test the affected bridge behavior. Do not bundle Apple's
extension code or claim the bridge is an official Apple API.

Update the README, configuration example, and user-facing skill when commands or
configuration change. Keep implementation details and development instructions in
this file rather than expanding the user-facing skill unnecessarily.

## Validation

From the repository root, with Python 3.12+, a compatible Hermes checkout, and its
required import dependencies available:

```sh
PYTHONPATH=/absolute/path/to/hermes-agent python -m unittest discover -s tests -v
```

If pytest is installed, the same suite can also be run with:

```sh
PYTHONPATH=/absolute/path/to/hermes-agent python -m pytest tests -q
```

Run single files with `discover -s tests -p test_X.py`, not `tests/test_X.py`: a Hermes
checkout on `PYTHONPATH` has its own `tests` package that shadows this one. Hermes's
managed runtime supplies dependencies through `PYTHONPATH`, so include its
site-packages directory as well when using that interpreter.

Use a separate development environment; do not modify a user's Hermes-managed
environment with raw pip. Use temporary Hermes homes for installation and integration
checks. Do not pair with or read a live vault as part of automated tests.

For behavior changes, add or update focused tests covering the affected credential
boundary and run the relevant suite. Ensure Hermes integration tests actually run;
report skips and missing dependencies rather than treating them as validation.
Documentation-only changes do not require rerunning the code suite.

Linux tests cannot validate Apple's native browser bridge. Before declaring a
release production-ready, complete the real-Mac checklist in `VALIDATION.md`
with synthetic credentials and record macOS, browser, Python, Hermes, and bridge
versions. Keep the experimental status until that evidence exists.

## Completion notes

Summarize what changed, tests actually run, skipped or unexecuted checks, and any
remaining compatibility limitations. Never present the historical test count in
`VALIDATION.md` as a fresh run. Keep published examples free of real credentials
and avoid unrelated changes to user configuration or repository settings.
