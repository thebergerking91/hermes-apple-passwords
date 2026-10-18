# Validation

v0.2.0 is a tested implementation, **pending real macOS acceptance testing with a paired
bridge**. Nothing below has read a live password vault.

## Automated checks (2026-10-18)

**314 tests passed, 0 skipped** with `python -m unittest discover -s tests` on macOS 27.0.1
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

## Live acceptance on a real Mac (2026-10-18)

macOS 27.0.1 (Mac mini, arm64), Google Chrome 155.0.8059.85, Python 3.14.7 (Hermes runtime),
Hermes `d923a5eb48`, apwlib 0.1.2 / chauffeur 0.14.1, installed via `hermes plugins install`
into the operator's default profile. Fixtures were synthetic logins (`hermes-applepw-test`,
`hermes-applepw-sibling` on example.com) plus the published demo account of the public test site
the-internet.herokuapp.com. Values were compared in code and never printed.

| # | Check | Result |
|---|---|---|
| 1 | Install, dependency found | PASS (`apwlib: installed`) |
| 2 | Pair; wrong PIN then retry | PASS (wrong PIN → "rejected the request"; retry paired) |
| 3 | `list` metadata only + exact-host note; `read --reveal` exact value | PASS |
| 4 | `run`: value delivered, child env = 7 base vars + mapping (plus macOS `__CF_USER_TEXT_ENCODING`), exit code 3 propagated, output suppressed / shown with `--show-output` | PASS |
| 5 | `inject`: exact value, 0600, overwrite and symlink refused | PASS |
| 6 | Real startup path: value applied with source label `apple_passwords`; overrides a shell value by default; kept shell value with `override_existing: false`; no value in output | PASS |
| 7 | Bridge stopped: `status` stopped/unpaired; `read` with stdin closed and a real startup failed fast with the pair hint, no PIN prompt, nothing leaked, no daemon restarted; operator re-paired and lookups recovered | PASS |
| 8 | Exact host: parent domain `herokuapp.com` and non-saved host refused | PASS |
| 9 | OTP: `list` marks the login `otp`; `read …/otp` returned a 6-digit code equal to an independently computed TOTP for the public test key; a login without a code is refused. Duplicates: the Passwords app refuses a second login with the same username and site (offers to update instead), so exact duplicates cannot be created there; duplicate rejection stays covered by unit tests | PASS |
| 10 | New Hermes session signed in to the-internet.herokuapp.com through `browser_vault` ("You logged into a secure area!"); fill on another origin → `origin_mismatch`; the password appears 0 times in the session's tool arguments, tool results, replies or reasoning | PASS |
| 11 | New session loaded `apple-passwords:apple-passwords` | PASS |

Findings from the live run:

- Apple stores saved sites as **bare hosts** (`example.com`), not URLs.
- Apple **strips a leading `www.`** on save (a save for `www.example.com` is stored as
  `example.com`) and treats them as one account per username. The vault backend therefore allows
  each saved host's `www.` form as a fill origin (nothing else is widened); references must use the
  host `list` shows.
- One-time-code entries report the same bare saved host (`domain: example.com`, `source: totp`).
  The worker's parent-domain allowance for codes is therefore broader than needed: a
  `www.example.com/…/otp` reference resolves while the matching `/password` reference is refused.
- In both live pairing sessions the first PIN attempt after the bridge started was rejected and
  the immediate retry succeeded (cause not yet determined).
- Saving through apwlib (used only to create fixtures; the plugin never saves) needs a macOS
  approval. apwlib's helper times out after ~30 s, but the save lands once approved, and lookups for
  that site fail until the prompt is answered.

## Real-Mac checklist

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
