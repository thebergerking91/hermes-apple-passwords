# Validation

v0.2.0 is a tested implementation, **pending real macOS acceptance testing with a paired
bridge**. Nothing below has read a live password vault.

## Automated checks (2026-10-18)

**311 tests passed, 0 skipped** with `python -m unittest discover -s tests` on macOS 27.0.1
(arm64), Python 3.14.7 (Hermes's bundled runtime), against Hermes
`d923a5eb487a17c0a68801bba9ef0f56c81040a8`. pytest was not installed in that environment
and was not run.

Coverage, all with synthetic values:

- Worker (`backend.py`): reference parsing, exact saved-host + username matching, username
  narrowing, duplicate → ambiguous, missing → not_found, one row per entry for the vault,
  sibling hosts in `list`, OTP matching, apwlib exception mapping (incl. bare `SessionError`
  with/without a cause), per-ref vs global failures, stdout protected from library prints,
  single-JSON-line protocol in a real subprocess.
- Launcher (`bridge.py`): the real `run_secret_cli` with `PYTHONPATH` removed still lets the
  worker import a dependency (regression for the v0.1 "apwlib unreachable" bug), `-P`,
  `PYTHONSAFEPATH`, safe cwd for pairing, fixed error text, timeouts, malformed output.
- Secret source: 1Password-parity precedence, per-ref warnings, remediation hints,
  in-memory cache/TTL, OTP refs refused for startup, never writes `os.environ`.
- CLI: every subcommand, a Hermes-shaped parser (regression for the v0.1 `run` crash),
  config writes through patched loaders, `run` env denylist, `inject` file safety.
- Vault backend: against the real `agent.vault_backends` and `browser_vault_list`,
  per-entry origins, colliding handles dropped, scope checks, install/uninstall.
- Integration (`tests/test_hermes_integration.py`): install into a temp profile, load through
  Hermes's real `PluginManager`, real `hermes_cli.main` dispatch of `status`/`run` with exit
  codes, real secret orchestrator `apply_all`, real worker importing a synthetic `apwlib`
  through the stripped environment, and real `browser_vault_list` + `backend_for_handle`.

Reproduce from the repository root (the Hermes checkout and its import dependencies on
`PYTHONPATH`; use `discover`, because a Hermes checkout has its own `tests` package):

    PYTHONPATH=/absolute/path/to/hermes-agent:/path/to/hermes/site-packages \
      python -m unittest discover -s tests -v

## Manual smoke test with the real apwlib (no bridge running)

With `apwlib==0.1.2` + `chauffeur==0.14.1` on the import path and a temporary profile,
through Hermes's `main()`: `status` reported `apwlib: installed / Bridge: stopped / not
paired`; `setup`, `set`, `vault add/enable` wrote the expected config; `set` refused an `/otp`
ref; `read`, `list` and startup failed cleanly with the fixed "bridge is not running; run
`hermes apple-passwords pair`" message; the real `browser_vault_list` reported the Apple
Passwords backend with the same message; `~/.apwlib` was never created (nothing started a
daemon). Without apwlib, `status` reported `apwlib: missing` and suggested `hermes pm repair`.

## Required real-Mac checks (not yet executed)

Use a disposable synthetic login in Apple Passwords, never production credentials:

1. `hermes plugins install …` (or `install.py` + `hermes plugins enable`) in a temporary
   profile; confirm `status` shows `apwlib: installed`.
2. `hermes apple-passwords pair` in a local terminal; enter Apple's PIN; `status` shows paired.
   Also test cancelling and a wrong PIN.
3. `list DOMAIN`: only metadata; exact saved hosts shown; `read … --reveal` returns the
   synthetic password; record the format Apple uses for saved sites.
4. `run` with a consumer that checks its variable without printing it; exit code propagates.
5. `inject` into a new file; mode 0600; overwrite refused; delete it.
6. `set` + new session: the value is loaded; `.env` loses unless `override_existing: false`.
7. Stop the bridge / reboot: startup reports "not running" without a PIN prompt; re-pair recovers.
8. Sibling-host and duplicate accounts are not silently selected.
9. OTP: `read …/otp --reveal` immediately; record `OTPEntry.domain`'s format (the parent-domain
   match is unverified).
10. Browser vault: `vault add`/`enable`, new session, have the agent sign in to the synthetic
    site via `browser_vault`; confirm fill refuses a different origin and the transcript never
    contains the password.
11. New session: the `apple-passwords:apple-passwords` skill is discoverable.

Record macOS, browser, Python, Hermes and apwlib versions before calling a release
production-ready.
