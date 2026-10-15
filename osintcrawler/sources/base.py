"""Base class and shared helpers for OSINT sources."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

import httpx

from ..config import Settings
from ..models import Indicator, IType, SourceResult, Status

# Process-wide cache for large, slow-changing feeds (CISA KEV, Tor exits, cloud
# ranges). Survives between requests on a warm serverless instance.
_GLOBAL_CACHE: dict[str, tuple[float, Any]] = {}
_GLOBAL_LOCKS: dict[str, asyncio.Lock] = {}


class SourceError(Exception):
    """A clean, user-facing error (never contains secrets)."""


class Context:
    """Per-run state handed to every source."""

    def __init__(self, client: httpx.AsyncClient, settings: Settings):
        self.client = client
        self.settings = settings
        self._cache: dict[str, Any] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def key(self, name: str | None) -> str | None:
        return self.settings.key(name)

    async def cached(self, key: str, factory: Callable[[], Awaitable[Any]], ttl: float | None = None) -> Any:
        """Memoise ``factory()``. With ``ttl`` the value is shared process-wide."""
        if ttl is not None:
            hit = _GLOBAL_CACHE.get(key)
            if hit and hit[0] > time.monotonic():
                return hit[1]
            lock = _GLOBAL_LOCKS.setdefault(key, asyncio.Lock())
            async with lock:
                hit = _GLOBAL_CACHE.get(key)
                if hit and hit[0] > time.monotonic():
                    return hit[1]
                value = await factory()
                _GLOBAL_CACHE[key] = (time.monotonic() + ttl, value)
                return value
        if key in self._cache:
            return self._cache[key]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key not in self._cache:
                self._cache[key] = await factory()
        return self._cache[key]


def check(resp: httpx.Response, *, key_name: str | None = None, not_found: tuple[int, ...] = (404,)) -> httpx.Response | None:
    """Return ``resp`` on success, ``None`` for 'not found', raise SourceError otherwise."""
    code = resp.status_code
    if code in not_found:
        return None
    if 200 <= code < 300:
        return resp
    if code in (401, 403):
        hint = f" - check {key_name}" if key_name else ""
        raise SourceError(f"HTTP {code}: authentication/authorisation failed{hint}")
    if code == 429:
        raise SourceError("HTTP 429: rate limited / quota exhausted")
    if code >= 500:
        raise SourceError(f"HTTP {code}: upstream service error")
    raise SourceError(f"HTTP {code}: unexpected response")


class Source:
    """Subclass and implement :meth:`query`."""

    name: str = ""
    types: frozenset[IType] = frozenset()
    key_env: str | None = None
    key_required: bool = True       # False => runs keyless (limited) when no key set
    timeout: float | None = None    # override the global per-source timeout
    homepage: str = ""
    description: str = ""

    def supports(self, ind: Indicator) -> bool:
        if ind.type not in self.types:
            return False
        # Never send private/reserved IPs to third parties.
        if ind.type is IType.IP and ind.meta.get("is_private"):
            return self.local_only
        return True

    #: True for sources that don't send the indicator anywhere (offline parsing).
    local_only: bool = False

    def configured(self, settings: Settings) -> bool:
        return not self.key_env or not self.key_required or settings.has(self.key_env)

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:  # pragma: no cover
        raise NotImplementedError

    # -- result helpers -------------------------------------------------
    def ok(self, **kw: Any) -> SourceResult:
        return SourceResult(source=self.name, status=Status.OK, **kw)

    def not_found(self, message: str = "No record found", **kw: Any) -> SourceResult:
        kw.setdefault("findings", [message])
        return SourceResult(source=self.name, status=Status.NOT_FOUND, **kw)

    def skipped(self, reason: str) -> SourceResult:
        return SourceResult(source=self.name, status=Status.SKIPPED, error=reason)

    def error(self, message: str) -> SourceResult:
        return SourceResult(source=self.name, status=Status.ERROR, error=message)
