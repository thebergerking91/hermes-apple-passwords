"""Hermes secret-source adapter for the local Apple Passwords bridge.

Mirrors Hermes's built-in 1Password source: ``secrets.apple_passwords.env`` maps
env-var names to ``applepw://`` references, resolved in ONE worker call. Invalid
entries and per-reference failures become warnings; only a pull that resolves
nothing is a failure. Values are cached in memory only (never on disk), and
this module never writes ``os.environ`` — the orchestrator applies results.
"""

from __future__ import annotations

import math
import re
import threading
import time
from pathlib import Path
from typing import Any, Sequence

try:  # Package plugin load and direct script execution are both supported.
    from . import backend, bridge
except ImportError:  # pragma: no cover - exercised by direct plugin CLI invocation
    import backend  # type: ignore[no-redef]
    import bridge  # type: ignore[no-redef]

from agent.secret_sources.base import (
    SECRET_SOURCE_API_VERSION,
    ErrorKind,
    FetchResult,
    SecretSource,
    coerce_float,
)


BridgeError = bridge.BridgeError
FIXED_MESSAGES = bridge.FIXED_MESSAGES

_DEFAULT_TIMEOUT = 45.0
_MAX_TIMEOUT = 120.0
_MAX_CALL_TIMEOUT = 30.0
_DEFAULT_CACHE_TTL = 300.0
_MAX_REF_LENGTH = 2048
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)

_KIND_MAP = {
    "not_paired": ErrorKind.AUTH_EXPIRED,
    "not_running": ErrorKind.NOT_CONFIGURED,
    "connection_lost": ErrorKind.NETWORK,
    "dependency_missing": ErrorKind.BINARY_MISSING,
    "unsupported_platform": ErrorKind.NOT_CONFIGURED,
    "ref_invalid": ErrorKind.REF_INVALID,
    "not_found": ErrorKind.REF_INVALID,
    "ambiguous": ErrorKind.REF_INVALID,
    "empty_value": ErrorKind.EMPTY_VALUE,
    "auth_failed": ErrorKind.AUTH_FAILED,
    "timeout": ErrorKind.TIMEOUT,
}

_PAIR_HINT = "Run `hermes apple-passwords pair` in a local terminal."

# (str(home_path), sorted mapping items) -> (monotonic expiry, secrets)
_CACHE: dict[tuple[str, tuple[tuple[str, str], ...]], tuple[float, dict[str, str]]] = {}
_CACHE_LOCK = threading.Lock()


def to_error_kind(kind: str) -> ErrorKind:
    """Map a worker/bridge kind onto Hermes's ErrorKind taxonomy."""
    return _KIND_MAP.get(kind, ErrorKind.INTERNAL) if isinstance(kind, str) else ErrorKind.INTERNAL


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def _message(kind: Any) -> str:
    return FIXED_MESSAGES.get(kind, FIXED_MESSAGES["internal"]) if isinstance(kind, str) else FIXED_MESSAGES["internal"]


def _safe_kind(kind: Any) -> str:
    return kind if isinstance(kind, str) and kind in FIXED_MESSAGES else "internal"


# --- public helpers (used by the CLI) ---------------------------------------------------------


def validate_reference(ref: Any) -> str:
    """Return ``ref`` if it is a valid ``applepw://`` reference; else raise BridgeError(ref_invalid)."""
    if not isinstance(ref, str) or not ref or len(ref) > _MAX_REF_LENGTH:
        raise BridgeError("ref_invalid")
    try:
        parsed = backend.parse_reference(ref)
    except Exception:
        raise BridgeError("ref_invalid") from None
    if parsed is None or parsed is False:
        raise BridgeError("ref_invalid")
    return ref


def is_startup_reference(ref: Any) -> bool:
    """True if ``ref`` is a valid reference usable as a startup (cached) mapping.

    One-time codes (``otp`` field) expire in ~30s but startup values are cached for minutes,
    so they are only usable via ``read``/``run``/``inject``.
    """
    try:
        parsed = backend.parse_reference(validate_reference(ref))
    except Exception:
        return False
    return getattr(parsed, "field", None) != "otp"


def _resolve(refs: Sequence[str], timeout: float) -> tuple[dict[str, str], dict[str, str]]:
    """One batched worker call for already-validated, unique refs."""
    result = bridge.run_worker("resolve", list(refs), timeout=timeout)
    if (not isinstance(result, dict) or not isinstance(result.get("values"), dict)
            or not isinstance(result.get("errors"), dict)):
        raise BridgeError("internal")
    raw_values, raw_errors = result["values"], result["errors"]
    values: dict[str, str] = {}
    errors: dict[str, str] = {}
    for ref in refs:
        value = raw_values.get(ref)
        if ref in raw_errors:
            errors[ref] = _safe_kind(raw_errors[ref])
        elif value is None and ref not in raw_values:
            errors[ref] = "internal"
        elif not isinstance(value, str) or not value or "\0" in value:
            errors[ref] = "empty_value"
        else:
            values[ref] = value
    return values, errors


def resolve_references(refs: Sequence[str], *,
                       timeout: float = _DEFAULT_TIMEOUT) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve refs in one worker call: ``(values by ref, error kind by ref)``.

    Validates every ref first; raises BridgeError on a global failure.
    """
    unique = list(dict.fromkeys(validate_reference(ref) for ref in refs))
    if not unique:
        return {}, {}
    return _resolve(unique, timeout)


def resolve_reference(ref: str) -> str:
    """Resolve one reference; the value is returned only to the caller."""
    values, errors = resolve_references([ref])
    if ref in errors:
        raise BridgeError(errors[ref])
    value = values.get(ref)
    if not isinstance(value, str):
        raise BridgeError("internal")
    return value


def bridge_status() -> dict[str, bool]:
    """Strict-bool ``dependency/running/bridge/paired`` flags; no spawn when apwlib is missing."""
    keys = ("dependency", "running", "bridge", "paired")
    if not bridge.dependency_available():
        return {key: False for key in keys}
    result = bridge.run_worker("status")
    if not isinstance(result, dict):
        raise BridgeError("internal")
    return {key: result.get(key) is True for key in keys}


def list_accounts(domain: str) -> list[dict[str, Any]]:
    """Metadata-only rows (host, hosts, username, has_otp) for Apple's matches of ``domain``."""
    try:
        normalized = backend.normalize_domain(domain)
    except Exception:
        raise BridgeError("ref_invalid") from None
    if not isinstance(normalized, str) or not normalized:
        raise BridgeError("ref_invalid")
    rows = bridge.run_worker("list", [normalized])
    if not isinstance(rows, list):
        raise BridgeError("internal")
    clean: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise BridgeError("internal")
        host, username = row.get("host"), row.get("username")
        if not isinstance(host, str) or not host or not isinstance(username, str):
            raise BridgeError("internal")
        hosts = row.get("hosts")
        hosts = [h for h in hosts if isinstance(h, str) and h] if isinstance(hosts, list) else []
        clean.append({"host": host, "hosts": hosts or [host], "username": username,
                      "has_otp": row.get("has_otp") is True})
    return clean


# --- secret source ----------------------------------------------------------------------------


def _validate_mapping(env_map: Any) -> tuple[dict[str, str], list[str]]:
    """``(valid env→ref, warnings)``; invalid entries are skipped, never fatal."""
    valid: dict[str, str] = {}
    warnings: list[str] = []
    if not isinstance(env_map, dict):
        return valid, warnings
    for name, ref in env_map.items():
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            warnings.append(f"Skipping {name!r}: not a valid env-var name")
            continue
        try:
            checked = validate_reference(ref)
        except BridgeError:
            warnings.append(f"Skipping {name!r}: not a valid applepw:// reference")
            continue
        if not is_startup_reference(checked):
            warnings.append(f"Skipping {name}: one-time codes can't be startup secrets; "
                            "use `hermes apple-passwords run` or `read` instead")
            continue
        valid[name] = checked
    return valid, warnings


def _cache_ttl(cfg: dict) -> float:
    ttl = coerce_float(cfg.get("cache_ttl_seconds", _DEFAULT_CACHE_TTL), _DEFAULT_CACHE_TTL)
    return ttl if math.isfinite(ttl) else _DEFAULT_CACHE_TTL


class ApplePasswordsSource(SecretSource):
    """Explicit env-var → ``applepw://`` reference mapping backed by Apple Passwords."""

    api_version = SECRET_SOURCE_API_VERSION
    name = "apple_passwords"
    label = "Apple Passwords"
    shape = "mapped"
    scheme = "applepw"
    # An explicit VAR→applepw:// binding is the strongest user intent (1Password parity).
    override_existing_default = True
    remediation_hints = {
        ErrorKind.AUTH_EXPIRED: _PAIR_HINT,
        ErrorKind.NOT_CONFIGURED: _PAIR_HINT,
        ErrorKind.AUTH_FAILED: _PAIR_HINT,
        ErrorKind.BINARY_MISSING: "apwlib is not installed for Hermes — run `hermes pm repair`, then restart Hermes.",
        ErrorKind.REF_INVALID: "Run `hermes apple-passwords list DOMAIN` to find the exact saved host and username.",
    }

    def is_enabled(self, cfg: dict) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("enabled") is True)

    def remediation(self, kind: ErrorKind | None, cfg: dict) -> str:
        # NOT_CONFIGURED covers both "no mappings yet" and "bridge not running"; only the
        # latter is fixed by pairing.
        if kind is ErrorKind.NOT_CONFIGURED and isinstance(cfg, dict) and not _validate_mapping(cfg.get("env"))[0]:
            return "Map a credential with `hermes apple-passwords set ENV_VAR applepw://HOST/USERNAME/password`."
        return super().remediation(kind, cfg)

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        raw = cfg.get("timeout_seconds", _DEFAULT_TIMEOUT) if isinstance(cfg, dict) else _DEFAULT_TIMEOUT
        if isinstance(raw, bool):
            return _DEFAULT_TIMEOUT
        value = coerce_float(raw, _DEFAULT_TIMEOUT)
        if not math.isfinite(value) or value <= 0:
            return _DEFAULT_TIMEOUT
        return min(value, _MAX_TIMEOUT)

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Resolve configured Apple Passwords references", "default": False},
            "env": {"description": "Map of ENV_VAR -> applepw://HOST/USERNAME/FIELD reference", "default": {}},
            "override_existing": {"description": "Resolved values overwrite .env/shell values", "default": True},
            "timeout_seconds": {"description": "Total fetch deadline (maximum 120 seconds)",
                                "default": int(_DEFAULT_TIMEOUT)},
            "cache_ttl_seconds": {"description": "In-memory cache TTL; 0 disables",
                                  "default": int(_DEFAULT_CACHE_TTL)},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        try:
            return self._fetch(cfg, home_path, result)
        except Exception:
            result.secrets = {}
            return result.fail(FIXED_MESSAGES["internal"], ErrorKind.INTERNAL)

    def _fetch(self, cfg: dict, home_path: Path, result: FetchResult) -> FetchResult:
        if not isinstance(cfg, dict):
            return result.fail("secrets.apple_passwords configuration is invalid.", ErrorKind.NOT_CONFIGURED)
        if "enabled" in cfg and not isinstance(cfg["enabled"], bool):
            return result.fail("secrets.apple_passwords.enabled must be true or false.",
                               ErrorKind.NOT_CONFIGURED)
        if not self.is_enabled(cfg):
            return result

        valid, warnings = _validate_mapping(cfg.get("env"))
        result.warnings.extend(warnings)
        if not valid:
            return result.fail("secrets.apple_passwords.enabled is true but no valid mappings are configured. "
                               "Add ENV_VAR → applepw:// mappings with `hermes apple-passwords set`.",
                               ErrorKind.NOT_CONFIGURED)

        if not bridge.dependency_available():
            return result.fail(FIXED_MESSAGES["dependency_missing"], ErrorKind.BINARY_MISSING)

        ttl = _cache_ttl(cfg)
        cache_key = (str(home_path), tuple(sorted(valid.items())))
        if ttl > 0:
            with _CACHE_LOCK:
                hit = _CACHE.get(cache_key)
                if hit is not None and hit[0] <= time.monotonic():
                    del _CACHE[cache_key]
                    hit = None
            if hit is not None:
                result.secrets = dict(hit[1])
                return result

        budget = self.fetch_timeout_seconds(cfg)
        unique_refs = list(dict.fromkeys(valid.values()))
        try:
            values, errors = _resolve(unique_refs, min(_MAX_CALL_TIMEOUT, budget))
        except BridgeError as exc:
            return result.fail(str(exc), to_error_kind(exc.kind))

        secrets: dict[str, str] = {}
        first_error: tuple[str, str] | None = None
        error_count = 0
        for env_name in sorted(valid):
            ref = valid[env_name]
            if ref in values:
                secrets[env_name] = values[ref]
                continue
            kind = errors.get(ref, "internal")
            error_count += 1
            message = _message(kind)
            result.warnings.append(f"{env_name}: {message}")
            if first_error is None:
                first_error = (kind, f"{env_name}: {message}")

        if not secrets and first_error is not None:
            return result.fail(first_error[1], to_error_kind(first_error[0]))

        result.secrets = secrets
        if ttl > 0 and not error_count and secrets:
            with _CACHE_LOCK:
                now = time.monotonic()
                for key in [k for k, (expiry, _) in _CACHE.items() if expiry <= now]:
                    del _CACHE[key]
                _CACHE[cache_key] = (now + ttl, dict(secrets))
        return result
