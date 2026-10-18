# Credential boundaries

- **Pairing** uses Apple's normal macOS PIN flow, typed by the user in a local terminal.
  The plugin never asks for the PIN in chat. Startup, `read`, `run`, `inject`, `list`, and
  the vault backend never start the bridge, prompt, or pair (`apwlib.ApplePasswords(auto_start=False)`).
- **Pairing is a standing unlock.** While the bridge stays paired, any process running as
  your macOS user — including the Hermes agent's terminal tool, another plugin, or code that
  imports apwlib directly — can request any saved login whose site and username it knows,
  without asking you again. Domain mappings, the vault allowlist, and the skill's rules are
  intent controls, not a security boundary. Stop the bridge (or log out) to revoke access.
- **apwlib is trusted code.** It is pinned (`apwlib==0.1.2`, `chauffeur<0.15`), but it drives a
  browser with a downloaded copy of Apple's extension that can change. This is not a full
  dependency audit.
- **Worker isolation.** Each request runs a short-lived worker (`python -P backend.py`) via
  Hermes's `run_secret_cli`: allowlisted environment plus only the dependency path, stdin
  closed, bounded timeouts. Worker stderr and upstream exception text are never relayed;
  every error is a fixed sentence that cannot contain a value.
- **Exact matching.** Lookups narrow by username and require the exact saved host. Sibling
  hosts and duplicate accounts fail closed. One-time codes follow the same exact-host rule.
- **Metadata only from `list`** and the vault list. apwlib's per-site query still loads
  password fields into the worker's memory before they are discarded.
- **No plaintext on disk** from the plugin: the startup cache is in-memory only. `inject`
  writes plaintext deliberately, to a new 0600 file you must delete.
- **Explicit exposure points:** `read --reveal` prints a value; `run --show-output` lets the
  child print; `inject` writes a file. These are not protections against a hostile same-user
  agent or plugin.
- **`run` is not a sandbox.** The child gets a small base environment plus your mappings (it
  cannot override the base variables or `DYLD_*`/`LD_*`), and can still use or send the
  credential however its code allows.
- **Browser vault.** Passwords are resolved server-side and filled by Hermes's
  `browser_vault`, which checks the page's exact origin against the saved hosts. The model
  sees handles, sites and usernames only. The backend is opt-in and limited to the domains
  you add. It wraps Hermes's internal backend list because Hermes has no public hook yet.
  Hermes's `browser_vault action=enter_code` resolves a stored one-time code for a handle
  without re-checking the page origin; Apple items that report a code are reachable there.
- **Profiles** keep separate mappings but share the same macOS user's paired bridge. Not a
  multi-tenant or untrusted-agent isolation layer. Values can appear in memory dumps; Python
  strings cannot be zeroized.
- Passkeys, password creation/deletion, bulk export, clipboard transfer and authentication
  bypass are not implemented.

Use synthetic credentials for testing. Report vulnerabilities privately to the repository
owner; never publish real credentials, PINs, dumps or logs containing them.
