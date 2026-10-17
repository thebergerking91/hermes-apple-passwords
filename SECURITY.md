# Credential boundaries

- User-triggered pairing uses the normal macOS PIN flow in a local terminal.
- The unofficial apwlib browser bridge is trusted code with access to the user's
  saved credentials after pairing. Its version is pinned, but its transitive browser
  dependencies and Apple's extension can change. This is not a full dependency audit.
- Plugin subprocesses receive an allowlisted environment. Startup lookups close stdin,
  have bounded timeouts, and never launch or pair the daemon.
- Exact account and saved-host checks prevent silently selecting another login from
  Apple's broader domain matches. Multiple exact matches fail.
- Backend exception text and stderr are not relayed to the agent. Error messages are
  fixed and values are not cached to disk by this plugin.
- Account listing returns metadata only, but apwlib's per-site password request also
  loads password fields into the short-lived worker's memory before discarding them.
- `read --reveal` exposes values. `run --show-output` can expose values through child
  output. `inject` writes plaintext to a new private file. These are explicit interfaces,
  not guarantees against a hostile same-user agent or another trusted plugin.
- A child given a credential can use it however its code permits; environment injection
  does not constrain network access or provide a sandbox. Credentials can also appear
  in memory dumps. Python strings cannot be reliably zeroized.
- Hermes profiles have separate reference mappings but share the same macOS user's
  paired apwlib daemon. Do not use this as a multi-tenant or untrusted-agent isolation layer.
- Passkeys, password creation/deletion, bulk export, clipboard transfer and authentication
  bypass are not implemented. The plugin does not silently change Passwords entries.

Use synthetic credentials for testing. Report vulnerabilities privately to the repository
owner once hosted; do not publish real credentials, PINs, dumps or logs containing them.
