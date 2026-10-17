# Validation

This release is a tested implementation, pending real macOS acceptance testing.

## Automated checks

Build result: **24 tests passed**, with no skips, on Python 3.12.14/Linux.
Both unittest discovery and pytest ran successfully. Real macOS acceptance checks
below remain unexecuted.

The suite uses synthetic credentials and covers URI validation, exact saved-host and
account matching, duplicate rejection, OTP selection, metadata filtering, sanitized
errors, explicit reveal gating, child environment isolation, suppressed output, exit
codes, template substitution, private exclusive output, all-or-none startup fetches,
configuration validation, timeout bounds, whitespace/NUL handling, and the real worker
JSON protocol for non-secret status and invalid references on Linux.

An integration test installs into a temporary Hermes profile, loads the plugin through
the actual Hermes loader, verifies skill/command/source registration, and exercises the
real secret orchestrator's precedence behavior with a synthetic subprocess response.
It does not access a live password vault.

Reproduce with Python 3.12+, a Hermes checkout on PYTHONPATH and its import dependencies:

    PYTHONPATH=/absolute/path/to/hermes-agent python -m unittest discover -s tests -v

Reference commits: Hermes e6f57427c198cfd96854522b7a9159eb007e13c2;
apwlib fecfda7005dd49f1856526a80235d38a11a24c15 (package version 0.1.2).

## Required real-Mac checks (not executed here)

Use a disposable synthetic login in Apple Passwords, not production credentials:

1. Install and enable in a temporary Hermes profile using Python 3.12+.
2. Check status, pair in a local terminal, and complete Apple's PIN prompt. Verify
   the supported browser/extension starts and status reports paired.
3. List the exact saved domain and confirm only account metadata appears. Verify an
   explicit read returns the exact synthetic password.
4. Use run with a local consumer that checks its injected variable and exits without
   printing it. Confirm the exit code reaches the shell.
5. Inject into a disposable new file, check its value locally and mode 0600, verify
   overwrite is refused, then delete the file.
6. Configure a startup mapping; verify .env wins unless override_existing is enabled.
7. Restart/stop the bridge; verify startup fails cleanly without a PIN prompt. Re-pair
   locally and verify recovery; also test pairing cancellation.
8. Verify sibling-domain and duplicate accounts are not silently selected. Test an
   OTP immediately before use if the synthetic entry has one.
9. Start a new Hermes conversation and verify the skill is discoverable. Keep test
   values synthetic because explicit reads/visible output may enter transcripts.

Record macOS and browser versions before calling a release production-ready. Passkeys,
service-account authorization and native browser-vault integration are not implemented.
