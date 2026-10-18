"""Hermes-side launcher for the Apple Passwords worker (``backend.py``).

The worker runs as a separate, clean interpreter. Hermes launches helper CLIs
with a stripped environment (``run_secret_cli`` drops ``PYTHONPATH``), so the
directories that provide ``apwlib`` and its dependencies in *this* process are
passed to the worker explicitly through ``extra_env``.

Failures are reduced to a fixed vocabulary of kinds with fixed, value-free
messages. Worker stderr and upstream exception text are never read or forwarded.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from agent.secret_sources.base import run_secret_cli


WORKER = Path(__file__).with_name("backend.py")

_DEPENDENCY_MODULES = ("apwlib", "chauffeur", "websockets")
_MIN_TIMEOUT = 0.1
_MAX_TIMEOUT = 60.0
_DEFAULT_TIMEOUT = 30.0
_PAIR_TIMEOUT = 240
_PAIR_ENV_ALLOWLIST = ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR",
                       "LANG", "LC_ALL", "LC_CTYPE", "TERM")

FIXED_MESSAGES: dict[str, str] = {
    "ref_invalid": "Invalid Apple Passwords reference or request.",
    "not_found": "No matching Apple Passwords login was found.",
    "ambiguous": "More than one Apple Passwords login matches; use the exact saved host and username.",
    "not_paired": "Apple Passwords is not paired; run `hermes apple-passwords pair` in a local terminal.",
    "not_running": "The Apple Passwords bridge is not running; run `hermes apple-passwords pair` in a local terminal.",
    "connection_lost": "The connection to the Apple Passwords bridge was lost.",
    "dependency_missing": "The apwlib dependency is not installed for Hermes; run `hermes pm repair`.",
    "unsupported_platform": "Apple Passwords is only supported on macOS.",
    "empty_value": "Apple Passwords returned an empty value.",
    "auth_failed": "Apple Passwords rejected the request; run `hermes apple-passwords pair` in a local terminal.",
    "internal": "Apple Passwords bridge operation failed.",
    "timeout": "Apple Passwords bridge request timed out.",
}


class BridgeError(RuntimeError):
    """Sanitized bridge failure. ``str(exc)`` is a fixed message for ``kind``."""

    def __init__(self, kind: str, message: str | None = None):
        self.kind = kind if isinstance(kind, str) and kind in FIXED_MESSAGES else "internal"
        super().__init__(message if message is not None else FIXED_MESSAGES[self.kind])


def dependency_paths() -> list[str]:
    """Parent dirs of the import locations of the worker's dependencies (this process)."""
    paths: list[str] = []
    for name in _DEPENDENCY_MODULES:
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError, AttributeError):
            continue
        if spec is None:
            continue
        locations: list[str] = []
        if spec.submodule_search_locations:
            locations = [os.path.dirname(os.path.abspath(p)) for p in spec.submodule_search_locations]
        elif spec.origin and getattr(spec, "has_location", False):
            locations = [os.path.dirname(os.path.abspath(spec.origin))]
        for location in locations:
            if location and os.pathsep not in location and location not in paths:
                paths.append(location)
    return paths


def dependency_available() -> bool:
    try:
        return importlib.util.find_spec("apwlib") is not None
    except (ImportError, ValueError, AttributeError):
        return False


def worker_extra_env() -> dict[str, str]:
    paths = dependency_paths()
    return {"PYTHONPATH": os.pathsep.join(paths)} if paths else {}


def _safe_cwd() -> str:
    """A fixed, non-attacker-controlled working directory (never the current one)."""
    home = os.path.expanduser("~")
    return home if home and os.path.isabs(home) and os.path.isdir(home) else "/"


def _clamp_timeout(timeout: Any) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError, OverflowError):
        return _DEFAULT_TIMEOUT
    if not math.isfinite(value):
        return _DEFAULT_TIMEOUT
    return max(_MIN_TIMEOUT, min(value, _MAX_TIMEOUT))


def _parse_payload(stdout: Any, returncode: Any = 0) -> Any:
    """Decode the worker's single JSON line; raise BridgeError for any failure."""
    try:
        payload = json.loads(stdout.strip() if isinstance(stdout, str) else "")
    except (ValueError, TypeError):
        raise BridgeError("internal") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("ok"), bool):
        raise BridgeError("internal")
    if not payload["ok"]:
        kind = payload.get("kind")
        raise BridgeError(kind if isinstance(kind, str) and kind in FIXED_MESSAGES else "internal")
    if isinstance(returncode, int) and returncode != 0:
        raise BridgeError("internal")
    return payload.get("result")


def run_worker(op: str, values: Sequence[str] = (), *, timeout: float = _DEFAULT_TIMEOUT) -> Any:
    """Run one worker operation and return its JSON ``result``; raise BridgeError on failure."""
    if not isinstance(op, str) or not op:
        raise BridgeError("ref_invalid")
    values = list(values)
    if any(not isinstance(v, str) or "\0" in v for v in values):
        raise BridgeError("ref_invalid")
    argv = [sys.executable, "-P", str(WORKER), op]
    if values:
        argv += ["--", *values]
    try:
        extra_env = {**worker_extra_env(), "PYTHONSAFEPATH": "1"}
        proc = run_secret_cli(argv, extra_env=extra_env, timeout=_clamp_timeout(timeout))
    except subprocess.TimeoutExpired:
        raise BridgeError("timeout") from None
    except RuntimeError as exc:
        # The shared helper's text can include paths/subprocess detail: classify, never forward.
        raise BridgeError("timeout" if "timed out" in str(exc).lower() else "dependency_missing") from None
    except OSError:
        raise BridgeError("dependency_missing") from None
    except Exception:
        raise BridgeError("internal") from None
    # stderr is deliberately never read.
    return _parse_payload(getattr(proc, "stdout", None), getattr(proc, "returncode", 0))


def pair_interactive() -> None:
    """Run the worker's pairing flow with the operator's terminal attached."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise BridgeError("internal", "Pairing requires an interactive local terminal.")
    env = {key: os.environ[key] for key in _PAIR_ENV_ALLOWLIST if key in os.environ}
    env.update(worker_extra_env())
    # The worker's apwlib Daemon.start() spawns a detached `python -m apwlib.daemon` that
    # inherits this env and cwd; `-m` would otherwise import from the current directory.
    env["PYTHONSAFEPATH"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, "-P", str(WORKER), "pair"],
            env=env, cwd=_safe_cwd(), stdin=None, stdout=subprocess.PIPE, stderr=None,
            text=True, encoding="utf-8", errors="replace",
            timeout=_PAIR_TIMEOUT, check=False,
        )
    except subprocess.TimeoutExpired:
        raise BridgeError("timeout") from None
    except OSError:
        raise BridgeError("dependency_missing") from None
    except Exception:
        raise BridgeError("internal") from None
    _parse_payload(proc.stdout, proc.returncode)
