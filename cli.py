"""Operator-only Apple Passwords commands for Hermes.

Secrets are displayed only by ``read --reveal``.  Template injection writes a
new private file; child process output is suppressed unless requested.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

if __package__:
    from . import backend, source
else:  # Allow ``python cli.py`` from the plugin directory.
    import backend  # type: ignore[no-redef]
    import source  # type: ignore[no-redef]


_SAFE_BRIDGE_ERRORS = (backend.BridgeError, getattr(source, "BridgeError", backend.BridgeError))
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z", re.ASCII)
_TEMPLATE = re.compile(r"\{\{\s*(applepw://[^\s{}]+)\s*\}\}")
_REFERENCE_OPENER = re.compile(r"\{\{\s*applepw://")
_MAX_TEMPLATE_BYTES = 1024 * 1024
_BASE_ENV = ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SYSTEMROOT", "WINDIR")


class _CliError(Exception):
    """An error message constructed entirely from non-secret CLI literals."""


def setup_cli(parser: argparse.ArgumentParser) -> None:
    """Attach the ``hermes apple-passwords`` command tree."""
    commands = parser.add_subparsers(dest="applepw_command", required=True)
    commands.add_parser("status", help="Check whether the local bridge is running and paired")
    commands.add_parser("pair", help="Pair the local bridge interactively in a terminal")
    listing = commands.add_parser("list", help="List account names for one domain (no passwords)")
    listing.add_argument("domain")
    reading = commands.add_parser("read", help="Reveal one value only with --reveal")
    reading.add_argument("reference", metavar="REF")
    reading.add_argument("--reveal", action="store_true", help="Print the secret to stdout (visible in terminal logs)")
    running = commands.add_parser("run", help="Run a command with resolved environment variables")
    running.add_argument("--env", action="append", default=[], metavar="NAME=REF", help="Map an environment variable to an applepw:// reference (repeatable)")
    running.add_argument("--show-output", action="store_true", help="Allow child stdout/stderr; the child may reveal secrets")
    running.add_argument("command", nargs=argparse.REMAINDER, help="-- executable [args ...]")
    injecting = commands.add_parser("inject", help="Render a template into a new private file")
    injecting.add_argument("--input", required=True, metavar="FILE")
    injecting.add_argument("--output", required=True, metavar="FILE")
    parser.set_defaults(func=handle_cli)


def _run(args: argparse.Namespace) -> int:
    command = args.applepw_command
    if command == "status":
        status = source.bridge_status()
        print(f"Bridge: {'running' if status.get('running') else 'stopped'}")
        print(f"Pairing: {'paired' if status.get('paired') else 'not paired'}")
        return 0
    if command == "pair":
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise _CliError("pair requires an interactive terminal")
        source.pair_interactive()
        print("Pairing complete.")
        return 0
    if command == "list":
        # Keep the output to account metadata, even if the bridge adds fields later.
        for account in source.list_accounts(args.domain):
            if isinstance(account, dict):
                domain, username = account.get("domain"), account.get("username")
            else:
                domain, username = getattr(account, "domain", None), getattr(account, "username", None)
            if not isinstance(domain, str) or not isinstance(username, str):
                raise _CliError("bridge returned invalid account metadata")
            print(f"{domain}\t{username}")
        return 0
    if command == "read":
        if not args.reveal:
            raise _CliError("read requires --reveal")
        backend.parse_reference(args.reference)
        print(source.resolve_reference(args.reference))
        return 0
    if command == "run":
        argv = list(args.command)
        if not argv or argv.pop(0) != "--" or not argv:
            raise _CliError("run requires -- executable [args ...]")
        mapping: dict[str, str] = {}
        for assignment in args.env:
            name, sep, ref = assignment.partition("=")
            if not sep or not _ENV_NAME.fullmatch(name) or not ref or name in mapping:
                raise _CliError("each --env must be a unique NAME=REF")
            backend.parse_reference(ref)
            mapping[name] = ref
        values = source.fetch_values(mapping) if mapping else {}
        environment = {key: os.environ[key] for key in _BASE_ENV if key in os.environ}
        environment.update(values)
        output = None if args.show_output else subprocess.DEVNULL
        try:
            return subprocess.run(argv, env=environment, stdout=output, stderr=output, check=False).returncode
        except OSError:
            raise _CliError("could not execute the requested command") from None
    if command == "inject":
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
        matches = list(_TEMPLATE.finditer(template))
        # An incomplete reference must not be copied literally into the result.
        if _REFERENCE_OPENER.search(_TEMPLATE.sub("", template)):
            raise _CliError("template contains a malformed Apple Passwords placeholder")
        mapping = {str(index): match.group(1) for index, match in enumerate(matches)}
        for ref in mapping.values():
            backend.parse_reference(ref)
        values = source.fetch_values(mapping) if mapping else {}
        replacements = iter(values[str(index)] for index in range(len(matches)))
        rendered = _TEMPLATE.sub(lambda _match: next(replacements), template)
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
    raise _CliError("unknown Apple Passwords command")


def handle_cli(args: argparse.Namespace) -> int:
    try:
        return _run(args)
    except _SAFE_BRIDGE_ERRORS as exc:
        print(f"Apple Passwords: {exc}", file=sys.stderr)
    except _CliError as exc:
        print(f"Apple Passwords: {exc}", file=sys.stderr)
    except Exception:
        print("Apple Passwords: operation failed", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes Apple Passwords operator commands")
    setup_cli(parser)
    return handle_cli(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
