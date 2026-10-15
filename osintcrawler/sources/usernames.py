"""Sherlock-style username presence checks across social / dev platforms.

Site definitions live in ``data/username_sites.json``. Methods:

- ``status``        200 => exists, 404/410 => absent
- ``json_nonempty`` JSON array/object non-empty => exists
- ``json_nonnull``  JSON body not ``null`` => exists
- ``keybase``       Keybase lookup API
- ``present_text``  200 and ``text`` in body => exists
- ``absent_text``   200 and ``text`` NOT in body => exists
- ``manual``        platform blocks unauthenticated checks; a link is provided
"""

from __future__ import annotations

import asyncio
import json
import re
from functools import lru_cache
from importlib import resources
from typing import Any

import httpx

from ..models import Indicator, IType, SourceResult
from .base import Context, Source

FOUND, ABSENT, UNKNOWN, MANUAL = "found", "absent", "unknown", "manual"
_CHALLENGE = re.compile(r"<title>\s*(Client Challenge|Just a moment|Attention Required|Access denied)", re.I)


@lru_cache(maxsize=1)
def load_sites() -> list[dict[str, Any]]:
    text = resources.files("osintcrawler.data").joinpath("username_sites.json").read_text(encoding="utf-8")
    return json.loads(text)


async def _check_site(site: dict[str, Any], user: str, client: httpx.AsyncClient) -> dict[str, Any]:
    profile = site["profile"].format(u=user)
    out = {"site": site["name"], "category": site.get("category"), "url": profile}
    method = site.get("method", "status")
    if method == "manual":
        return out | {"result": MANUAL}
    url = site.get("check", site["profile"]).format(u=user)
    headers = {"Accept": "application/json, text/html;q=0.9"}
    if site.get("cookies"):
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in site["cookies"].items())
    try:
        resp = await client.get(url, headers=headers, timeout=12)
    except httpx.HTTPError as e:
        return out | {"result": UNKNOWN, "note": type(e).__name__}
    code = resp.status_code
    if code in (404, 410) or (method == "status" and code == 400):
        return out | {"result": ABSENT}
    if code != 200:
        return out | {"result": UNKNOWN, "note": f"HTTP {code}"}
    # Redirected to a consent / login / bot-challenge page on another host => can't tell.
    if resp.url.host != httpx.URL(url).host:
        return out | {"result": UNKNOWN, "note": f"redirected to {resp.url.host}"}
    if "text/html" in resp.headers.get("content-type", "") and _CHALLENGE.search(resp.text[:5000]):
        return out | {"result": UNKNOWN, "note": "bot challenge"}
    try:
        if method == "status":
            res = FOUND
        elif method == "json_nonempty":
            res = FOUND if resp.json() else ABSENT
        elif method == "json_nonnull":
            res = FOUND if resp.json() is not None else ABSENT
        elif method == "keybase":
            them = resp.json().get("them") or []
            res = FOUND if them and them[0] else ABSENT
        elif method == "present_text":
            res = FOUND if site["text"] in resp.text else ABSENT
        elif method == "absent_text":
            res = ABSENT if site["text"] in resp.text else FOUND
        else:
            res = UNKNOWN
    except ValueError:
        res = UNKNOWN
    return out | {"result": res}


class Usernames(Source):
    name = "Username search"
    types = frozenset({IType.USERNAME})
    timeout = 30
    homepage = "https://github.com/sherlock-project/sherlock"
    description = "Account presence on social, dev and gaming platforms"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        sem = asyncio.Semaphore(8)

        async def run(site: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                return await _check_site(site, ind.value, ctx.client)

        results = await asyncio.gather(*(run(s) for s in load_sites()))
        groups: dict[str, list[dict[str, Any]]] = {FOUND: [], ABSENT: [], UNKNOWN: [], MANUAL: []}
        for r in results:
            groups[r["result"]].append(r)
        findings = [f"Found on {len(groups[FOUND])} site(s): "
                    + (", ".join(r["site"] for r in groups[FOUND]) or "none")]
        if groups[MANUAL]:
            findings.append(f"{len(groups[MANUAL])} platform(s) need a manual check (links in details)")
        if groups[UNKNOWN]:
            findings.append("Inconclusive: " + ", ".join(r["site"] for r in groups[UNKNOWN]))
        return self.ok(
            findings=findings,
            data={"found": groups[FOUND], "absent": [r["site"] for r in groups[ABSENT]],
                  "inconclusive": groups[UNKNOWN], "manual_check": groups[MANUAL]},
        )
