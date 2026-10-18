"""Apple Passwords as a Hermes ``browser_vault`` login backend (opt-in, domain-scoped).

Hermes has no public hook for login backends (``external_backend_classes`` is
hard-coded), so :func:`install` wraps ``enabled_backends`` with a guarded,
idempotent shim that appends an Apple Passwords backend when
``vault.apple_passwords.enabled`` is ``true`` and at least one valid domain is
configured. The backend lists metadata only and resolves one password (or OTP)
server-side at fill time through the local worker; secret values are never
logged, cached, or placed in exception text.
"""

from __future__ import annotations

import dataclasses
import functools
import importlib
import logging
import threading
from typing import Any, Callable, Optional
from urllib.parse import quote, unquote

try:  # Package plugin load and direct execution are both supported.
    from . import backend, bridge
except ImportError:  # pragma: no cover - direct script execution
    import backend  # type: ignore[no-redef]
    import bridge  # type: ignore[no-redef]


logger = logging.getLogger(__name__)

BACKEND_NAME = "apple_passwords"
DISPLAY_NAME = "Apple Passwords"
PREFIX = "applepw:"

_MSG_DEPENDENCY = "apwlib is not installed for Hermes — run `hermes pm repair`, then restart Hermes."
_MSG_NOT_PAIRED = "Apple Passwords is not paired. Run `hermes apple-passwords pair` in a local terminal."
_MSG_GENERIC = "Apple Passwords lookup failed."
_MSG_BAD_HANDLE = "Invalid Apple Passwords handle."
_MSG_OUT_OF_SCOPE = "Apple Passwords item is outside the configured vault domains."
_KIND_OVERRIDES = {"not_paired": _MSG_NOT_PAIRED, "dependency_missing": _MSG_DEPENDENCY}

_MAX_USERNAME = 512
_REQUIRED_META_FIELDS = (
    "id", "kind", "label", "origin", "created_at",
    "identifier_type", "identifier", "has_otp", "allowed_origins",
)

_lock = threading.RLock()
_installed = False                       # wrappers installed by us are live
_patched: list[tuple[Any, str, Any, Any]] = []   # (module, attr, original, wrapper)
_backend_cls: Optional[type] = None


# ── configuration ──────────────────────────────────────────────────────────

def vault_config() -> dict:
    """``vault.apple_passwords`` from the read-only Hermes config (``{}`` when absent)."""
    from hermes_cli.config import load_config_readonly
    vault = (load_config_readonly() or {}).get("vault") or {}
    section = vault.get("apple_passwords") if isinstance(vault, dict) else None
    return section if isinstance(section, dict) else {}


def _configured_domains(section: Any) -> list[str]:
    """Sorted unique normalized domains; invalid entries are dropped (never widened)."""
    raw = section.get("domains") if isinstance(section, dict) else None
    if not isinstance(raw, (list, tuple)):
        return []
    out: set[str] = set()
    for value in raw:
        try:
            out.add(backend.normalize_domain(value))
        except Exception:
            continue
    return sorted(out)


def backend_enabled(section: Any) -> bool:
    return (isinstance(section, dict) and section.get("enabled") is True
            and bool(_configured_domains(section)))


# ── handle + scope helpers ─────────────────────────────────────────────────

def _in_scope(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _origins_for(hosts: list[str]) -> tuple:
    """Exact fill origins for one Apple entry's saved hosts.

    Apple Passwords strips a leading ``www.`` when it saves a login (verified live: a save
    for www.example.com is stored as example.com) and autofills it on both. So each saved
    host also allows its ``www.`` form, exactly as Apple does; nothing else is inferred.
    """
    out: list[str] = []
    for host in hosts:
        for candidate in (host, host if host.startswith("www.") else f"www.{host}"):
            origin = f"https://{candidate}"
            if origin not in out:
                out.append(origin)
    return tuple(out)


def _make_handle(host: str, username: str) -> str:
    return f"{PREFIX}{host}/{quote(username, safe='')}"


def _parse_handle(handle: Any) -> tuple[str, str]:
    """``applepw:HOST/ENCODED-USER`` → (host, username); ValueError when malformed."""
    if not isinstance(handle, str) or not handle.startswith(PREFIX):
        raise ValueError("prefix")
    host, sep, encoded = handle[len(PREFIX):].partition("/")
    if not sep or not encoded or "/" in encoded:
        raise ValueError("shape")
    try:
        if backend.normalize_domain(host) != host:
            raise ValueError("host")
        username = unquote(encoded, errors="strict")
    except ValueError:
        raise
    except Exception:
        raise ValueError("host") from None
    if (not username or len(username) > _MAX_USERNAME
            or any(ord(c) < 32 or ord(c) == 127 for c in username)
            or quote(username, safe="").upper() != encoded.upper()):
        raise ValueError("username")
    return host, username


def _message_for_kind(kind: Any) -> str:
    if isinstance(kind, str):
        if kind in _KIND_OVERRIDES:
            return _KIND_OVERRIDES[kind]
        fixed = getattr(bridge, "FIXED_MESSAGES", None)
        if isinstance(fixed, dict) and isinstance(fixed.get(kind), str):
            return fixed[kind]
    return _MSG_GENERIC


def _message_for_exception(exc: BaseException) -> str:
    if isinstance(exc, getattr(bridge, "BridgeError", ())):
        kind = getattr(exc, "kind", None)
        if kind in _KIND_OVERRIDES:
            return _KIND_OVERRIDES[kind]
        return str(exc) or _message_for_kind(kind)
    return _MSG_GENERIC


# ── backend ────────────────────────────────────────────────────────────────

def _backend_class() -> type:
    """Create the LoginBackend subclass lazily (Hermes may not be importable at plugin load)."""
    global _backend_cls
    with _lock:
        if _backend_cls is not None:
            return _backend_cls
        from agent.vault_backends.base import LoginBackend
        from agent.vault_store import VaultItemMeta

        class ApplePasswordsLoginBackend(LoginBackend):
            name = BACKEND_NAME
            display_name = DISPLAY_NAME
            prefix = PREFIX
            needs_unlock = False

            def __init__(self, domains: list[str]):
                self.domains = list(domains)

            # -- listing (metadata only) --
            def _rows(self, domains: list[str]) -> list[VaultItemMeta]:
                if not bridge.dependency_available():
                    raise RuntimeError(_MSG_DEPENDENCY)
                try:
                    rows = bridge.run_worker("vault-list", list(domains))
                except Exception as exc:
                    raise RuntimeError(_message_for_exception(exc)) from None
                if not isinstance(rows, list):
                    raise RuntimeError(_MSG_GENERIC)
                # One worker row per Apple entry. Rows that map to the same handle
                # (same first in-scope host + username) are different entries whose
                # origin sets may differ and which resolve as ambiguous: never merge
                # them or pick one — drop every colliding row from the listing.
                items: dict[str, VaultItemMeta] = {}
                collided: set[str] = set()
                for row in rows:
                    meta = self._meta_from_row(row)
                    if meta is None:
                        continue
                    if meta.id in items or meta.id in collided:
                        collided.add(meta.id)
                        items.pop(meta.id, None)
                        continue
                    items[meta.id] = meta
                return list(items.values())

            def _meta_from_row(self, row: Any) -> Optional[VaultItemMeta]:
                if not isinstance(row, dict):
                    return None
                username = row.get("username")
                if (not isinstance(username, str) or not username or len(username) > _MAX_USERNAME
                        or any(ord(c) < 32 or ord(c) == 127 for c in username)):
                    return None
                candidates = [row.get("host")]
                hosts = row.get("hosts")
                if isinstance(hosts, (list, tuple)):
                    candidates.extend(hosts)
                # Only THIS row's own in-scope hosts may become allowed origins, and the
                # handle host must be one of them (resolve is keyed by handle host).
                found: set[str] = set()
                for value in candidates:
                    try:
                        host = backend.normalize_domain(value)
                    except Exception:
                        continue
                    if _in_scope(host, self.domains):
                        found.add(host)
                if not found:
                    return None
                scoped = sorted(found)
                host = scoped[0]
                return VaultItemMeta(
                    id=_make_handle(host, username), kind="login", label=f"{host} ({username})",
                    origin=f"https://{host}", created_at="",
                    identifier_type="email" if "@" in username else "username",
                    identifier=username, has_otp=row.get("has_otp") is True,
                    allowed_origins=_origins_for(scoped))

            def list_items(self) -> list[VaultItemMeta]:
                return self._rows(self.domains)

            def get_meta(self, handle: str) -> Optional[VaultItemMeta]:
                try:
                    host, username = _parse_handle(handle)
                except ValueError:
                    return None
                if not _in_scope(host, self.domains):
                    return None
                narrowed = [d for d in self.domains if host == d or host.endswith("." + d)]
                wanted = _make_handle(host, username)
                return next((m for m in self._rows(narrowed) if m.id == wanted), None)

            # -- secrets (server-side only) --
            def _resolve(self, handle: str, field: str) -> str:
                try:
                    host, username = _parse_handle(handle)
                except ValueError:
                    raise RuntimeError(_MSG_BAD_HANDLE) from None
                if not _in_scope(host, self.domains):
                    raise RuntimeError(_MSG_OUT_OF_SCOPE)
                ref = f"applepw://{host}/{quote(username, safe='')}/{field}"
                try:
                    result = bridge.run_worker("resolve", [ref])
                except Exception as exc:
                    raise RuntimeError(_message_for_exception(exc)) from None
                values = result.get("values") if isinstance(result, dict) else None
                errors = result.get("errors") if isinstance(result, dict) else None
                if isinstance(errors, dict) and ref in errors:
                    raise RuntimeError(_message_for_kind(errors.get(ref)))
                value = values.get(ref) if isinstance(values, dict) else None
                if not isinstance(value, str) or not value or "\x00" in value:
                    raise RuntimeError(_MSG_GENERIC)
                return value

            def resolve_password(self, handle: str) -> str:
                return self._resolve(handle, "password")

            def resolve_otp(self, handle: str) -> Optional[str]:
                try:
                    code = self._resolve(handle, "otp").strip()
                except Exception:
                    return None
                return code or None

        _backend_cls = ApplePasswordsLoginBackend
        return _backend_cls


def make_backend(section: Any):
    return _backend_class()(_configured_domains(section))


# ── install / uninstall ────────────────────────────────────────────────────

def _wrap(original: Callable[[], list]) -> Callable[[], list]:
    @functools.wraps(original)
    def enabled_backends() -> list:
        out = original()
        if not _installed:
            return out
        try:
            section = vault_config()
            if backend_enabled(section) and not any(
                    getattr(b, "name", None) == BACKEND_NAME for b in out):
                out.append(make_backend(section))
        except Exception as exc:  # never break the built-in backends
            logger.debug("Apple Passwords vault backend skipped: %s", type(exc).__name__)
        return out

    enabled_backends._applepw_wrapped = True  # type: ignore[attr-defined]
    return enabled_backends


def install() -> bool:
    """Wrap Hermes's ``enabled_backends`` (module + package). Idempotent; never raises."""
    global _installed
    try:
        with _lock:
            pkg = importlib.import_module("agent.vault_backends")
            base = importlib.import_module("agent.vault_backends.base")
            store = importlib.import_module("agent.vault_store")
            if not isinstance(getattr(base, "LoginBackend", None), type):
                raise AttributeError("LoginBackend")
            meta_cls = getattr(store, "VaultItemMeta", None)
            if not dataclasses.is_dataclass(meta_cls):
                raise AttributeError("VaultItemMeta")
            missing = set(_REQUIRED_META_FIELDS) - {f.name for f in dataclasses.fields(meta_cls)}
            if missing:
                raise AttributeError("VaultItemMeta." + ",".join(sorted(missing)))
            targets = []
            for module in (base, pkg):
                current = getattr(module, "enabled_backends", None)
                if not callable(current):
                    raise AttributeError("enabled_backends")
                targets.append((module, current))
            for module, current in targets:  # validated above → mutate atomically-ish
                if getattr(current, "_applepw_wrapped", False):
                    continue
                wrapper = _wrap(current)
                setattr(module, "enabled_backends", wrapper)
                _patched.append((module, "enabled_backends", current, wrapper))
            _installed = True
            return True
    except Exception as exc:
        logger.debug("Apple Passwords vault backend not installed: %s", type(exc).__name__)
        return False


def uninstall() -> None:
    """Restore the original ``enabled_backends`` functions (used by tests)."""
    global _installed, _backend_cls
    with _lock:
        _installed = False  # a wrapper someone else stacked on top degrades to pass-through
        for module, attr, original, wrapper in reversed(_patched):
            if getattr(module, attr, None) is wrapper:
                setattr(module, attr, original)
        _patched.clear()
        _backend_cls = None
