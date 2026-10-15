"""Runs every applicable source for every indicator, concurrently."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Callable, Iterable

import httpx

from . import __version__
from .config import Settings
from .detect import DetectionError, detect
from .models import Indicator, IndicatorReport, IType, Report, SourceResult, Status
from .scoring import score_report
from .sources import all_sources
from .sources.base import Context, Source, SourceError

ProgressCB = Callable[[Indicator, SourceResult], None]


def _scrub(msg: str, settings: Settings) -> str:
    """Remove any configured secret from an error message (e.g. keys in URLs)."""
    for secret in settings.keys.values():
        if secret and len(secret) >= 6:
            msg = msg.replace(secret, "***")
    return msg[:300]


def parse_indicators(
    values: Iterable[str], settings: Settings, forced: IType | None = None
) -> tuple[list[Indicator], list[str]]:
    indicators: list[Indicator] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for raw in values:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            ind = detect(raw, forced=forced, phone_region=settings.default_phone_region)
        except DetectionError as e:
            warnings.append(str(e))
            continue
        k = (ind.type.value, ind.value)
        if k not in seen:
            seen.add(k)
            indicators.append(ind)
    return indicators, warnings


def select_sources(only: Iterable[str] | None = None, exclude: Iterable[str] | None = None) -> list[Source]:
    def norm(s: str) -> str:
        return "".join(ch for ch in s.lower() if ch.isalnum())

    only_n = {norm(s) for s in only or [] if s.strip()}
    excl_n = {norm(s) for s in exclude or [] if s.strip()}
    out = []
    for src in all_sources():
        n = norm(src.name)
        if only_n and n not in only_n:
            continue
        if n in excl_n:
            continue
        out.append(src)
    return out


async def _run_one(src: Source, ind: Indicator, ctx: Context, sem: asyncio.Semaphore, timeout: float) -> SourceResult:
    async with sem:
        start = time.perf_counter()
        try:
            res = await asyncio.wait_for(src.query(ind, ctx), timeout=src.timeout or timeout)
        except asyncio.TimeoutError:
            res = src.error(f"timed out after {src.timeout or timeout:.0f}s")
        except SourceError as e:
            res = src.error(_scrub(str(e), ctx.settings))
        except httpx.HTTPError as e:
            res = src.error(_scrub(f"{type(e).__name__}: {e}", ctx.settings))
        except Exception as e:  # a bug or unexpected payload in one source must not kill the run
            res = src.error(_scrub(f"{type(e).__name__}: {e}", ctx.settings))
        res.elapsed_ms = int((time.perf_counter() - start) * 1000)
        return res


async def investigate_indicators(
    indicators: list[Indicator],
    settings: Settings,
    *,
    sources: list[Source] | None = None,
    timeout: float | None = None,
    progress: ProgressCB | None = None,
    warnings: list[str] | None = None,
) -> Report:
    sources = sources if sources is not None else all_sources()
    timeout = timeout or settings.http_timeout
    report = Report(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        tool_version=__version__,
        warnings=list(warnings or []),
    )
    sem = asyncio.Semaphore(settings.max_concurrency)
    async with httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent},
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
    ) as client:
        ctx = Context(client, settings)
        jobs: list[tuple[IndicatorReport, asyncio.Task[SourceResult] | SourceResult]] = []
        for ind in indicators:
            rep = IndicatorReport(indicator=ind)
            report.indicators.append(rep)
            if ind.type is IType.IP and ind.meta.get("is_private"):
                report.warnings.append(f"{ind.value} is a private/reserved address - external lookups skipped.")
            for src in sources:
                if not src.supports(ind):
                    continue
                if not src.configured(settings):
                    jobs.append((rep, src.skipped(f"set {src.key_env} to enable")))
                    continue
                jobs.append((rep, asyncio.create_task(_run_one(src, ind, ctx, sem, timeout))))

        for rep, job in jobs:
            res = await job if isinstance(job, asyncio.Task) else job
            rep.results.append(res)
            if progress:
                progress(rep.indicator, res)

    for rep in report.indicators:
        rep.results.sort(key=lambda r: (_STATUS_ORDER[r.status], -(r.score or -1), r.source))
        score_report(rep)
    return report


_STATUS_ORDER = {Status.OK: 0, Status.NOT_FOUND: 1, Status.ERROR: 2, Status.SKIPPED: 3}


async def investigate(
    values: Iterable[str],
    settings: Settings,
    *,
    forced: IType | None = None,
    only: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    timeout: float | None = None,
    progress: ProgressCB | None = None,
) -> Report:
    indicators, warnings = parse_indicators(values, settings, forced)
    return await investigate_indicators(
        indicators,
        settings,
        sources=select_sources(only, exclude),
        timeout=timeout,
        progress=progress,
        warnings=warnings,
    )
