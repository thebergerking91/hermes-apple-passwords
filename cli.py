"""Operator-only ``hermes apple-passwords ...`` commands.

Mirrors ``hermes secrets onepassword setup|status|set|remove|sync|disable`` and adds
``pair|list|read|run|inject|vault``.  Secret values are displayed only by
``read --reveal``; ``run`` hands them to a child process, ``inject`` writes them to a new
private file.  Error output is always a fixed, value-free sentence.

Hermes owns two argparse destinations on the parent namespace (``command`` and ``func``), so
nothing in this module may use either name as a ``dest`` or default.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__:
    from . import backend, bridge, source
else:  # Allow ``python cli.py`` from the plugin directory.
    import backend  # type: ignore[no-redef]
    import bridge  # type: ignore[no-redef]
    import source  # type: ignore[no-redef]


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_TEMPLATE = re.compile(r"\{\{\s*(applepw://[^\s{}]+)\s*\}\}")
_REFERENCE_OPENER = re.compile(r"\{\{\s*applepw://")
_MAX_TEMPLATE_BYTES = 1024 * 1024
_BASE_ENV = (
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR",
    "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SYSTEMROOT", "WINDIR",
)
_DEFAULT_TIMEOUT = 45
_MAX_TIMEOUT = 120
_DEFAULT_CACHE_TTL = 300
_RESTART_NOTE = "Restart Hermes sessions for vault changes to apply."


class _CliError(Exception):
    """An error message constructed entirely from non-secret CLI literals."""


# ---------------------------------------------------------------------------
# Config access (tests patch these two wrappers)
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    from hermes_cli.config import load_config

    return load_config()


def _save_config(cfg: dict) -> None:
    from hermes_cli.config import save_config

    save_config(cfg)


def _section(cfg: Any, *path: str) -> dict:
    """Read-only walk; returns ``{}`` when any level is missing or not a mapping."""
    node = cfg
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def _section_for_write(cfg: dict, *path: str) -> dict:
    node = cfg
    for key in path:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    return node


def _secrets_section(cfg: Any) -> dict:
    return _section(cfg, "secrets", "apple_passwords")


def _vault_section(cfg: Any) -> dict:
    return _section(cfg, "vault", "apple_passwords")


def _mappings(section: dict) -> dict:
    env = section.get("env")
    return env if isinstance(env, dict) else {}


def _config_timeout(section: dict) -> float:
    raw = section.get("timeout_seconds", _DEFAULT_TIMEOUT)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return float(_DEFAULT_TIMEOUT)
    if not math.isfinite(raw) or raw <= 0:
        return float(_DEFAULT_TIMEOUT)
    return float(min(raw, _MAX_TIMEOUT))


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _yn(flag: bool) -> str:
    return "yes" if flag else "no"


def _clean(text: str) -> str:
    """Escape control characters so metadata cannot forge extra output columns or lines."""
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)


def _bridge_errors() -> tuple[type, ...]:
    classes: list[type] = [bridge.BridgeError]
    other = getattr(backend, "BridgeError", None)
    if isinstance(other, type) and other not in classes:
        classes.append(other)
    return tuple(classes)


def _fixed_message(kind: Any) -> str:
    messages = getattr(bridge, "FIXED_MESSAGES", {})
    text = messages.get(kind) if isinstance(kind, str) else None
    return text if isinstance(text, str) else str(messages.get("internal", "Apple Passwords bridge operation failed."))


def _override_existing(section: dict) -> bool:
    """Same truthiness Hermes uses: ``bool(cfg.get('override_existing', True))`` (null/0 -> False)."""
    return bool(section.get("override_existing", True))


def _env_is_set(name: Any) -> bool:
    """Hermes treats an empty-string variable as not set."""
    return isinstance(name, str) and bool(os.environ.get(name))


def _is_startup_reference(ref: str) -> bool:
    """False for one-time-code references, which must never be exported at startup."""
    checker = getattr(source, "is_startup_reference", None)
    if callable(checker):
        return bool(checker(ref))
    return not ref.endswith("/otp")


def _validate_env_name(name: str) -> None:
    if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
        raise _CliError("environment variable names must match [A-Za-z_][A-Za-z0-9_]*")


def _unique(items) -> list[str]:
    return list(dict.fromkeys(items))


def _resolve_all(refs: list[str], *, timeout: float | None = None) -> dict[str, str]:
    """Resolve unique references in one batch; any failure raises before values are used."""
    if not refs:
        return {}
    if timeout is None:
        values, errors = source.resolve_references(refs)
    else:
        values, errors = source.resolve_references(refs, timeout=timeout)
    for ref in refs:
        kind = errors.get(ref) if isinstance(errors, dict) else None
        if kind:
            raise _CliError(_fixed_message(kind))
        if not isinstance(values, dict) or not isinstance(values.get(ref), str):
            raise _CliError(_fixed_message("internal"))
    return values


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def setup_cli(parser: argparse.ArgumentParser) -> None:
    """Attach the ``hermes apple-passwords`` command tree.

    Never uses the ``command`` or ``func`` destinations: Hermes's main() reads
    ``args.command`` and installs ``func`` itself.
    """
    commands = parser.add_subparsers(dest="applepw_command", required=True, metavar="COMMAND")

    setting_up = commands.add_parser("setup", help="Enable the Apple Passwords secret source")
    setting_up.add_argument(
        "--timeout", type=float, metavar="SECONDS",
        help=f"Startup fetch budget in seconds (0 < N <= {_MAX_TIMEOUT}; default {_DEFAULT_TIMEOUT})",
    )
    override_group = setting_up.add_mutually_exclusive_group()
    override_group.add_argument(
        "--no-override", action="store_true",
        help="Do not replace environment variables that are already set",
    )
    override_group.add_argument(
        "--override", action="store_true",
        help="Replace environment variables that are already set (the default for new configs)",
    )

    commands.add_parser("status", help="Show configuration and local bridge state (no secrets)")

    mapping = commands.add_parser("set", help="Map an env var to an applepw:// reference")
    mapping.add_argument("env_var", metavar="ENV_VAR", help="Environment variable name, e.g. GITHUB_TOKEN")
    mapping.add_argument("reference", metavar="REF", help="applepw://HOST/USERNAME/FIELD")

    removing = commands.add_parser("remove", help="Remove an env-var mapping")
    removing.add_argument("env_var", metavar="ENV_VAR")

    commands.add_parser("sync", help="Dry-run: resolve every mapping and report what would be exported")
    commands.add_parser("disable", help="Turn off the Apple Passwords secret source")
    commands.add_parser("pair", help="Pair the local bridge interactively in a terminal")

    listing = commands.add_parser("list", help="List saved logins for a domain (no passwords)")
    listing.add_argument("domain")

    reading = commands.add_parser("read", help="Reveal one value only with --reveal")
    reading.add_argument("reference", metavar="REF")
    reading.add_argument("--reveal", action="store_true", help="Print the secret to stdout (visible in terminal logs)")

    running = commands.add_parser("run", help="Run a command with resolved environment variables")
    running.add_argument(
        "--env", action="append", default=[], metavar="NAME=REF",
        help="Map an environment variable to an applepw:// reference (repeatable)",
    )
    running.add_argument("--show-output", action="store_true", help="Allow child stdout/stderr; the child may reveal secrets")
    running.add_argument("child_argv", nargs=argparse.REMAINDER, metavar="-- EXECUTABLE [ARGS ...]")

    injecting = commands.add_parser("inject", help="Render a template into a new private file")
    injecting.add_argument("--input", required=True, metavar="FILE")
    injecting.add_argument("--output", required=True, metavar="FILE")

    vault = commands.add_parser("vault", help="Configure the browser_vault login backend")
    vault_commands = vault.add_subparsers(dest="applepw_vault_command", required=True, metavar="ACTION")
    vault_commands.add_parser("status", help="Show vault backend state")
    vault_add = vault_commands.add_parser("add", help="Allow a domain (and its subdomains)")
    vault_add.add_argument("domain")
    vault_remove = vault_commands.add_parser("remove", help="Stop allowing a domain")
    vault_remove.add_argument("domain")
    vault_commands.add_parser("enable", help="Enable the vault backend")
    vault_commands.add_parser("disable", help="Disable the vault backend")


# ---------------------------------------------------------------------------
# setup / status / set / remove / sync / disable
# ---------------------------------------------------------------------------

def _print_status(cfg: Any) -> dict | None:
    """Print config + bridge state; returns the bridge status dict (None if unavailable)."""
    section = _secrets_section(cfg)
    env = _mappings(section)
    vault = _vault_section(cfg)
    domains = _vault_domains(vault)

    print("Apple Passwords secret source")
    print(f"  Enabled: {_yn(section.get('enabled') is True)}")
    print(f"  Mappings: {len(env)}")
    for name in sorted(str(key) for key in env):
        print(f"    {_clean(name)}")
    print(f"  Override existing: {_yn(_override_existing(section))}")
    print(f"  Timeout (s): {_clean(str(section.get('timeout_seconds', _DEFAULT_TIMEOUT)))}")
    print(f"  Cache TTL (s): {_clean(str(section.get('cache_ttl_seconds', _DEFAULT_CACHE_TTL)))}")
    print(f"  Vault backend: {'enabled' if vault.get('enabled') is True else 'disabled'}")
    print(f"  Vault domains: {', '.join(domains) if domains else 'none'}")

    print("Bridge")
    try:
        state = source.bridge_status()
    except Exception:
        print("  Status: unavailable (check failed)")
        return None
    dependency = bool(state.get("dependency", True))
    print(f"  apwlib: {'installed' if dependency else 'missing'}")
    print(f"  Bridge: {'running' if state.get('running') else 'stopped'}")
    print(f"  Pairing: {'paired' if state.get('paired') else 'not paired'}")
    return {key: bool(value) for key, value in state.items()} | {"dependency": dependency}


def _cmd_setup(args: argparse.Namespace) -> int:
    timeout = None
    if args.timeout is not None:
        if not math.isfinite(args.timeout) or not 0 < args.timeout <= _MAX_TIMEOUT:
            raise _CliError(f"--timeout must be greater than 0 and at most {_MAX_TIMEOUT} seconds")
        timeout = int(args.timeout) if float(args.timeout).is_integer() else args.timeout

    cfg = _load_config()
    section = _section_for_write(cfg, "secrets", "apple_passwords")
    section["enabled"] = True
    if not isinstance(section.get("env"), dict):
        section["env"] = {}
    if args.override:
        section["override_existing"] = True
    elif args.no_override:
        section["override_existing"] = False
    else:
        section.setdefault("override_existing", True)  # never flip a deliberate setting
    if timeout is not None:
        section["timeout_seconds"] = timeout
    else:
        section.setdefault("timeout_seconds", _DEFAULT_TIMEOUT)
    section.setdefault("cache_ttl_seconds", _DEFAULT_CACHE_TTL)
    _save_config(cfg)

    print("Apple Passwords secret source enabled.")
    state = _print_status(cfg)
    if state is not None:
        if not state.get("dependency"):
            print("Next: run `hermes pm repair` to install apwlib, then restart Hermes.")
        elif not state.get("paired"):
            print("Next: run `hermes apple-passwords pair` in this terminal.")
    if not section["env"]:
        print("Map credentials with: hermes apple-passwords set ENV_VAR applepw://HOST/USERNAME/password")
    return 0


def _cmd_status(_args: argparse.Namespace) -> int:
    cfg = _load_config()
    _print_status(cfg)
    section = _secrets_section(cfg)
    if section.get("enabled") is not True:
        print("Run `hermes apple-passwords setup` to enable.")
    elif not _mappings(section):
        print("No mappings yet. Add one: hermes apple-passwords set ENV_VAR applepw://HOST/USERNAME/password")
    return 0


def _cmd_set(args: argparse.Namespace) -> int:
    _validate_env_name(args.env_var)
    ref = source.validate_reference(args.reference)
    if not _is_startup_reference(ref):
        raise _CliError(
            "one-time codes can't be startup secrets; "
            "use `hermes apple-passwords run` or `read` instead"
        )
    cfg = _load_config()
    section = _section_for_write(cfg, "secrets", "apple_passwords")
    if not isinstance(section.get("env"), dict):
        section["env"] = {}
    section["env"][args.env_var] = ref
    _save_config(cfg)
    print(f"Mapped {args.env_var} -> {_clean(ref)}")
    if section.get("enabled") is not True:
        print("Note: the integration is disabled. Run `hermes apple-passwords setup` to turn it on.")
    return 0


def _cmd_remove(args: argparse.Namespace) -> int:
    cfg = _load_config()
    env = _mappings(_secrets_section(cfg))
    if args.env_var not in env:
        raise _CliError(f"{_clean(str(args.env_var))} is not mapped")
    del env[args.env_var]
    _save_config(cfg)
    print(f"Removed mapping for {args.env_var}")
    return 0


def _cmd_sync(_args: argparse.Namespace) -> int:
    section = _secrets_section(_load_config())
    if section.get("enabled") is not True:
        raise _CliError("secret source is disabled; run `hermes apple-passwords setup`")
    env = _mappings(section)
    if not env:
        print("No applepw:// references configured. Add one with `hermes apple-passwords set ENV_VAR REF`.")
        return 0

    override = _override_existing(section)
    problems: dict[str, str] = {}  # env name -> fixed message
    valid: dict[str, str] = {}  # env name -> validated reference
    for name in sorted(env, key=str):
        ref = env[name]
        try:
            if not isinstance(name, str) or not _ENV_NAME.fullmatch(name) or not isinstance(ref, str):
                raise bridge.BridgeError("ref_invalid")
            checked = source.validate_reference(ref)
        except _bridge_errors() as exc:
            problems[str(name)] = str(exc)
            continue
        if not _is_startup_reference(checked):
            # Startup skips one-time codes (they expire long before the cache does).
            problems[str(name)] = "one-time codes can't be startup secrets"
            continue
        valid[name] = checked

    values: dict[str, str] = {}
    errors: dict[str, str] = {}
    unique_refs = _unique(valid.values())
    if unique_refs:
        values, errors = source.resolve_references(unique_refs, timeout=_config_timeout(section))

    unresolved = 0
    for name in sorted(env, key=str):
        label = _clean(str(name))
        if name in problems:
            action = f"unresolved: {_clean(problems[name])}"
        else:
            ref = valid[name]
            if ref in errors:
                action = f"unresolved: {_clean(_fixed_message(errors[ref]))}"
            elif ref not in values:
                action = f"unresolved: {_clean(_fixed_message('internal'))}"
            elif _env_is_set(name) and not override:
                action = "skip (already set)"
            else:
                action = "would export"
        if action.startswith("unresolved"):
            unresolved += 1
        print(f"{label}\t{action}")
    print("Dry run only: nothing was exported. References resolve automatically at Hermes startup.")
    return 1 if unresolved else 0


def _cmd_disable(_args: argparse.Namespace) -> int:
    cfg = _load_config()
    section = _section_for_write(cfg, "secrets", "apple_passwords")
    section["enabled"] = False
    _save_config(cfg)
    print("Disabled. applepw:// mappings are kept in config; they are not resolved at startup.")
    return 0


# ---------------------------------------------------------------------------
# pair / list / read
# ---------------------------------------------------------------------------

def _cmd_pair(_args: argparse.Namespace) -> int:
    bridge.pair_interactive()
    print("Pairing complete.")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    domain = backend.normalize_domain(args.domain)
    rows = source.list_accounts(domain)
    if not rows:
        print(f"No saved logins found for {domain}.", file=sys.stderr)
        return 0
    sibling = False
    for row in rows:
        host, username = row.get("host"), row.get("username")
        if not isinstance(host, str) or not isinstance(username, str):
            raise _CliError("bridge returned invalid account metadata")
        hosts = row.get("hosts")
        hosts = [h for h in hosts if isinstance(h, str)] if isinstance(hosts, list) else [host]
        if host != domain or any(h != domain for h in hosts):
            sibling = True
        print(f"{_clean(host)}\t{_clean(username)}\t{'otp' if row.get('has_otp') is True else '-'}")
    if sibling:
        print("References must use the exact saved host shown in the first column.")
    return 0


def _cmd_read(args: argparse.Namespace) -> int:
    if not args.reveal:
        raise _CliError("read requires --reveal")
    source.validate_reference(args.reference)
    print(source.resolve_reference(args.reference))
    return 0


# ---------------------------------------------------------------------------
# run / inject
# ---------------------------------------------------------------------------

def _cmd_run(args: argparse.Namespace) -> int:
    argv = list(args.child_argv or [])
    if argv and argv[0] == "--":
        argv.pop(0)
    if not argv or not argv[0]:
        raise _CliError("run requires -- executable [args ...]")

    mapping: dict[str, str] = {}
    for assignment in args.env:
        name, sep, ref = assignment.partition("=")
        if not sep or not _ENV_NAME.fullmatch(name) or not ref or name in mapping:
            raise _CliError("each --env must be a unique NAME=REF")
        if name in _BASE_ENV or name.startswith(("DYLD_", "LD_")):
            raise _CliError("--env may not override the child's base environment or DYLD_/LD_ variables")
        mapping[name] = source.validate_reference(ref)

    values = _resolve_all(_unique(mapping.values()))
    environment = {key: os.environ[key] for key in _BASE_ENV if key in os.environ}
    environment.update({name: values[ref] for name, ref in mapping.items()})
    output = None if args.show_output else subprocess.DEVNULL
    try:
        code = subprocess.run(argv, env=environment, stdout=output, stderr=output, check=False).returncode
    except OSError:
        raise _CliError("could not execute the requested command") from None
    return 128 - code if code < 0 else code


def _cmd_inject(args: argparse.Namespace) -> int:
    if args.input == "-" or args.output == "-":
        raise _CliError("inject requires file paths")
    try:
        with open(args.input, "rb") as handle:
            raw = handle.read(_MAX_TEMPLATE_BYTES + 1)
        if len(raw) > _MAX_TEMPLATE_BYTES:
            raise _CliError("template exceeds 1 MiB")
        template = raw.decode("utf-8")
    except (OSError, UnicodeError):
        raise _CliError("could not read a UTF-8 template") from None
    # An incomplete reference must not be copied literally into the result.
    if _REFERENCE_OPENER.search(_TEMPLATE.sub("", template)):
        raise _CliError("template contains a malformed Apple Passwords placeholder")
    refs = _unique(source.validate_reference(match.group(1)) for match in _TEMPLATE.finditer(template))
    values = _resolve_all(refs)  # any failure aborts before the output file exists
    rendered = _TEMPLATE.sub(lambda match: values[match.group(1)], template)

    output_path = Path(args.output)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = None
    created = False
    try:
        fd = os.open(output_path, flags, 0o600)
        created = True
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(rendered)
    except Exception:
        if fd is not None:
            os.close(fd)
        if created:
            output_path.unlink(missing_ok=True)
        raise _CliError("could not create the output file") from None
    print(f"Created {output_path}")
    return 0


# ---------------------------------------------------------------------------
# vault
# ---------------------------------------------------------------------------

def _vault_domains(section: dict) -> list[str]:
    raw = section.get("domains")
    found: set[str] = set()
    for item in raw if isinstance(raw, list) else []:
        try:
            found.add(backend.normalize_domain(item))
        except _bridge_errors():
            continue
    return sorted(found)


def _cmd_vault(args: argparse.Namespace) -> int:
    action = args.applepw_vault_command
    cfg = _load_config()
    section = _vault_section(cfg)
    domains = _vault_domains(section)

    if action == "status":
        print(f"Vault backend: {'enabled' if section.get('enabled') is True else 'disabled'}")
        print(f"Domains: {', '.join(domains) if domains else 'none'}")
        print(_RESTART_NOTE)
        return 0

    if action in ("add", "remove"):
        domain = backend.normalize_domain(args.domain)
        if action == "add":
            domains = sorted({*domains, domain})
        elif domain not in domains:
            raise _CliError(f"{domain} is not configured")
        else:
            domains = [d for d in domains if d != domain]
    target = _section_for_write(cfg, "vault", "apple_passwords")
    if action in ("add", "remove"):
        target["domains"] = domains
        message = f"{'Added' if action == 'add' else 'Removed'} {domain}."
    else:
        target["enabled"] = action == "enable"
        target.setdefault("domains", domains)
        message = f"Vault backend {'enabled' if action == 'enable' else 'disabled'}."
    _save_config(cfg)
    print(message)
    if action == "enable" and not domains:
        print("Warning: no domains configured; the backend stays inactive until you run "
              "`hermes apple-passwords vault add DOMAIN`.")
    print(_RESTART_NOTE)
    return 0


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

_HANDLERS = {
    "setup": _cmd_setup,
    "status": _cmd_status,
    "set": _cmd_set,
    "remove": _cmd_remove,
    "sync": _cmd_sync,
    "disable": _cmd_disable,
    "pair": _cmd_pair,
    "list": _cmd_list,
    "read": _cmd_read,
    "run": _cmd_run,
    "inject": _cmd_inject,
    "vault": _cmd_vault,
}


def handle_cli(args: argparse.Namespace) -> int:
    try:
        handler = _HANDLERS.get(getattr(args, "applepw_command", None))
        if handler is None:
            raise _CliError("unknown Apple Passwords command")
        return handler(args)
    except KeyboardInterrupt:
        print("Apple Passwords: interrupted", file=sys.stderr)
        return 130
    except _CliError as exc:
        print(f"Apple Passwords: {exc}", file=sys.stderr)
    except Exception as exc:
        try:
            known = isinstance(exc, _bridge_errors())
        except Exception:
            known = False
        message = str(exc) if known else "operation failed"
        print(f"Apple Passwords: {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apple-passwords", description="Hermes Apple Passwords operator commands")
    setup_cli(parser)
    return handle_cli(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
