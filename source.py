"""Hermes secret-source adapter for the local Apple Passwords bridge.

The bridge is invoked as a separate Python process for each operation. Secret
values are returned only to the caller and are never logged or cached here.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:  # Package plugin load and direct ``python cli.py`` execution are both supported.
    from . import backend
except ImportError:  # pragma: no cover - exercised by direct plugin CLI invocation
    import backend  # type: ignore[no-redef]

from agent.secret_sources.base import (
    SECRET_SOURCE_API_VERSION,
    ErrorKind,
    FetchResult,
    SecretSource,
    run_secret_cli,
)


_BACKEND = Path(__file__).with_name("backend.py")
_DEFAULT_TOTAL_TIMEOUT = 45.0
_MAX_TOTAL_TIMEOUT = 120.0
_DEFAULT_CALL_TIMEOUT = 20.0
_MAX_CALL_TIMEOUT = 30.0
_FIXED_ERRORS = {
    "not_configured": "Apple Passwords bridge is not configured.",
    "binary_missing": "Apple Passwords bridge is unavailable.",
    "auth_failed": "Apple Passwords rejected the request.",
    "auth_expired": "Apple Passwords pairing has expired; pair again.",
    "ref_invalid": "Invalid Apple Passwords reference.",
    "network": "Could not reach the Apple Passwords bridge.",
    "empty_value": "Apple Passwords returned an empty value.",
    "timeout": "Apple Passwords bridge request timed out.",
    "internal": "Apple Passwords bridge operation failed.",
}


class BridgeError(RuntimeError):
    """Sanitized bridge failure exposed to operator callers."""

    def __init__(self, kind: ErrorKind, message: str):
        super().__init__(message)
        self.kind = kind


def _error_kind(value: Any) -> ErrorKind:
    if isinstance(value, ErrorKind):
        return value
    value = getattr(value, "value", value)
    try:
        return ErrorKind(value if isinstance(value, str) else str(value))
    except ValueError:
        return ErrorKind.INTERNAL


def _fixed_message(kind: ErrorKind) -> str:
    return _FIXED_ERRORS.get(kind.value, _FIXED_ERRORS["internal"])


def _validate_ref(reference: Any) -> str:
    if not isinstance(reference, str) or not reference or len(reference) > 2048:
        raise BridgeError(ErrorKind.REF_INVALID, _fixed_message(ErrorKind.REF_INVALID))
    try:
        parsed = backend.parse_reference(reference)
    except Exception as exc:
        kind = _error_kind(getattr(exc, "kind", "ref_invalid")) if isinstance(
            exc, getattr(backend, "BridgeError", ())) else ErrorKind.REF_INVALID
        raise BridgeError(kind, _fixed_message(kind)) from None
    # The backend parser is authoritative. Guard against a permissive/buggy parser returning
    # a falsey result for malformed input.
    if parsed is None or parsed is False:
        raise BridgeError(ErrorKind.REF_INVALID, _fixed_message(ErrorKind.REF_INVALID))
    return reference


def _run(operation: str, *arguments: str, timeout: float = _DEFAULT_CALL_TIMEOUT) -> Any:
    """Run backend's JSON protocol and discard all untrusted subprocess diagnostics."""
    try:
        proc = run_secret_cli(
            [sys.executable, str(_BACKEND), operation, *arguments],
            timeout=max(0.1, min(float(timeout), _MAX_CALL_TIMEOUT)),
        )
    except subprocess.TimeoutExpired:
        raise BridgeError(ErrorKind.TIMEOUT, _fixed_message(ErrorKind.TIMEOUT)) from None
    except RuntimeError as exc:
        # The shared helper's error text can contain platform paths or subprocess details.
        kind = ErrorKind.TIMEOUT if "timed out" in str(exc).lower() else ErrorKind.BINARY_MISSING
        raise BridgeError(kind, _fixed_message(kind)) from None
    except Exception:
        raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL)) from None

    try:
        payload = json.loads(proc.stdout or "")
    except (json.JSONDecodeError, TypeError):
        raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL)) from None
    if not isinstance(payload, dict) or not isinstance(payload.get("ok"), bool):
        raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL))
    if proc.returncode != 0 or not payload["ok"]:
        kind = _error_kind(payload.get("kind", "internal"))
        raise BridgeError(kind, _fixed_message(kind))
    return payload.get("result")


def _resolve_mapping(mapping: dict[str, str], *, total_timeout: float) -> dict[str, str]:
    """Resolve refs all-or-none under one bounded deadline."""
    validated: dict[str, str] = {}
    for key, reference in mapping.items():
        if not isinstance(key, str):
            raise BridgeError(ErrorKind.REF_INVALID, _fixed_message(ErrorKind.REF_INVALID))
        validated[key] = _validate_ref(reference)

    deadline = time.monotonic() + max(0.1, min(total_timeout, _MAX_TOTAL_TIMEOUT))
    values: dict[str, str] = {}
    for key, reference in validated.items():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BridgeError(ErrorKind.TIMEOUT, _fixed_message(ErrorKind.TIMEOUT))
        value = _run("resolve", reference, timeout=min(_MAX_CALL_TIMEOUT, remaining))
        if not isinstance(value, str) or not value or "\0" in value:
            raise BridgeError(ErrorKind.EMPTY_VALUE, _fixed_message(ErrorKind.EMPTY_VALUE))
        values[key] = value
    return values


def resolve_reference(reference: str) -> str:
    """Resolve one reference. The secret value is returned only to the caller."""
    return _resolve_mapping({"value": reference}, total_timeout=_DEFAULT_TOTAL_TIMEOUT)["value"]


def fetch_values(mapping: dict[str, str]) -> dict[str, str]:
    """Resolve arbitrary caller keys to values; suitable for CLI templates/injection."""
    if not isinstance(mapping, dict):
        raise BridgeError(ErrorKind.REF_INVALID, _fixed_message(ErrorKind.REF_INVALID))
    return _resolve_mapping(mapping, total_timeout=_DEFAULT_TOTAL_TIMEOUT)


def bridge_status() -> dict[str, Any]:
    result = _run("status")
    if not isinstance(result, dict):
        raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL))
    return {key: result[key] for key in ("running", "bridge", "paired")
            if isinstance(result.get(key), bool)}


def list_accounts(domain: str) -> list[dict[str, str]]:
    if not isinstance(domain, str) or not domain:
        raise BridgeError(ErrorKind.REF_INVALID, _fixed_message(ErrorKind.REF_INVALID))
    try:
        normalized = backend.normalize_domain(domain)
    except Exception as exc:
        kind = _error_kind(getattr(exc, "kind", "ref_invalid")) if isinstance(
            exc, getattr(backend, "BridgeError", ())) else ErrorKind.REF_INVALID
        raise BridgeError(kind, _fixed_message(kind)) from None
    if not isinstance(normalized, str) or not normalized or len(normalized) > 253:
        raise BridgeError(ErrorKind.REF_INVALID, _fixed_message(ErrorKind.REF_INVALID))
    result = _run("list", normalized)
    accounts = result
    if not isinstance(accounts, list):
        raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL))
    clean: list[dict[str, str]] = []
    for account in accounts:
        if not isinstance(account, dict):
            raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL))
        item_domain, username = account.get("domain"), account.get("username")
        if not isinstance(item_domain, str) or not isinstance(username, str):
            raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL))
        clean.append({"domain": item_domain, "username": username})
    return clean


def pair_interactive() -> Any:
    """Run pairing in a clean child process with the user's terminal attached."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise BridgeError(ErrorKind.NOT_CONFIGURED, "Pairing requires an interactive terminal.")
    keep = ("PATH", "HOME", "USER", "USERPROFILE", "LOGNAME", "SHELL", "TMPDIR", "TEMP",
            "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR")
    child_env = {key: os.environ[key] for key in keep if key in os.environ}
    try:
        proc = subprocess.run([sys.executable, str(_BACKEND), "pair"], env=child_env,
                              stdin=None, stdout=None, stderr=None, timeout=240, check=False)
    except subprocess.TimeoutExpired:
        raise BridgeError(ErrorKind.TIMEOUT, _fixed_message(ErrorKind.TIMEOUT)) from None
    except Exception:
        raise BridgeError(ErrorKind.INTERNAL, _fixed_message(ErrorKind.INTERNAL)) from None
    if proc.returncode != 0:
        raise BridgeError(ErrorKind.AUTH_FAILED, _fixed_message(ErrorKind.AUTH_FAILED))
    return {"paired": True}


class ApplePasswordsSource(SecretSource):
    """Explicit env-var → ``applepw://`` reference mapping backed by Apple Passwords."""

    api_version = SECRET_SOURCE_API_VERSION
    name = "apple_passwords"
    label = "Apple Passwords"
    shape = "mapped"
    scheme = "applepw"
    override_existing_default = False
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: "Run `hermes apple-passwords status` and pair with `hermes apple-passwords pair`.",
        ErrorKind.AUTH_FAILED: "Run `hermes apple-passwords pair` to refresh the local pairing.",
        ErrorKind.AUTH_EXPIRED: "Run `hermes apple-passwords pair` to refresh the local pairing.",
        ErrorKind.BINARY_MISSING: "Run `hermes apple-passwords status` to check the local bridge installation.",
    }

    def is_enabled(self, cfg: dict) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("enabled") is True)

    def override_existing(self, cfg: dict) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("override_existing") is True)

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        raw = cfg.get("timeout_seconds", _DEFAULT_TOTAL_TIMEOUT) if isinstance(cfg, dict) else _DEFAULT_TOTAL_TIMEOUT
        try:
            value = float(raw)
        except (TypeError, ValueError, OverflowError):
            value = _DEFAULT_TOTAL_TIMEOUT
        if not math.isfinite(value) or value <= 0:
            value = _DEFAULT_TOTAL_TIMEOUT
        return min(value, _MAX_TOTAL_TIMEOUT)

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Resolve configured Apple Passwords references", "default": False},
            "env": {"description": "Map environment variable names to applepw:// references", "default": {}},
            "timeout_seconds": {"description": "Total bridge-fetch deadline (maximum 120 seconds)", "default": _DEFAULT_TOTAL_TIMEOUT},
            "override_existing": {"description": "Allow values to replace existing environment values", "default": False},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        del home_path  # The bridge has a fixed local user pairing; no per-Hermes-home state.
        result = FetchResult()
        if not isinstance(cfg, dict):
            return result.fail("Apple Passwords configuration is invalid.", ErrorKind.NOT_CONFIGURED)
        if "enabled" in cfg and not isinstance(cfg["enabled"], bool):
            return result.fail("Apple Passwords enabled setting must be true or false.",
                               ErrorKind.NOT_CONFIGURED)
        if not self.is_enabled(cfg):
            return result
        mapping = cfg.get("env")
        if not isinstance(mapping, dict) or not mapping:
            return result.fail("Add environment-variable to applepw:// reference mappings.",
                               ErrorKind.NOT_CONFIGURED)
        for name, reference in mapping.items():
            if (not isinstance(name, str)
                    or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name, flags=re.ASCII)):
                return result.fail("Apple Passwords mapping contains an invalid environment variable name.",
                                   ErrorKind.REF_INVALID)
            try:
                _validate_ref(reference)
            except BridgeError as exc:
                return result.fail(str(exc), exc.kind)

        timeout = self.fetch_timeout_seconds(cfg)
        try:
            result.secrets = _resolve_mapping(mapping, total_timeout=timeout)
        except BridgeError as exc:
            # All-or-none: discard any values resolved before an error.
            result.secrets.clear()
            return result.fail(str(exc), exc.kind)
        except Exception:
            result.secrets.clear()
            return result.fail(_fixed_message(ErrorKind.INTERNAL), ErrorKind.INTERNAL)
        return result
