"""Token-protected web UI + JSON API (FastAPI). Deployable on Vercel.

Security model
- Fails closed: without ACCESS_TOKEN (>= 16 chars) no lookups are served.
- Browser sessions: HttpOnly, Secure, SameSite=Strict cookie holding an HMAC of
  the token (the token itself is never stored client-side).
- API: ``Authorization: Bearer <ACCESS_TOKEN>``.
- Per-IP rate limiting (in-memory, per instance), Origin check on POSTs,
  strict CSP with per-response nonce, no-store caching.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..config import Settings
from ..engine import investigate
from ..models import IType
from ..report import render_template, to_html

COOKIE = "oc_session"
SESSION_TTL = 12 * 3600
MAX_INDICATORS = 20
WEB_TIMEOUT = 20.0

app = FastAPI(title="OSINTCrawler", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------- helpers
def _token() -> str:
    return (os.environ.get("ACCESS_TOKEN") or "").strip()


def _configured() -> bool:
    return len(_token()) >= 16


def _session_value(issued: int) -> str:
    sig = hmac.new(_token().encode(), f"oc-session:{issued}".encode(), hashlib.sha256).hexdigest()
    return f"{issued}.{sig}"


def _valid_session(value: str | None) -> bool:
    if not value or not _configured() or "." not in value:
        return False
    issued_s, _ = value.split(".", 1)
    if not issued_s.isdigit() or time.time() - int(issued_s) > SESSION_TTL:
        return False
    return hmac.compare_digest(value, _session_value(int(issued_s)))


def _bearer_ok(request: Request) -> bool:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer ") or not _configured():
        return False
    return hmac.compare_digest(auth[7:].strip().encode(), _token().encode())


def _authed(request: Request) -> bool:
    return _bearer_ok(request) or _valid_session(request.cookies.get(COOKIE))


def _client_ip(request: Request) -> str:
    # Vercel sets x-forwarded-for / x-real-ip at its edge.
    fwd = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0]
    return fwd.strip() or (request.client.host if request.client else "unknown")


_hits: dict[str, deque[float]] = defaultdict(deque)


def _rate_limited(request: Request, bucket: str, per_minute: int | None = None) -> bool:
    limit = per_minute or int(os.environ.get("RATE_LIMIT_PER_MINUTE", "20") or 20)
    key = f"{bucket}:{_client_ip(request)}"
    now = time.monotonic()
    q = _hits[key]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    # No Origin (non-browser clients) or "null" (opaque origin, e.g. a form post that
    # followed a cross-site redirect such as Vercel's sign-in). The session cookie is
    # SameSite=Strict, so browsers never attach it to cross-site requests, and login
    # still requires the secret token.
    if not origin or origin == "null":
        return True
    # Compare with the Host header the browser actually addressed. Proxies such as
    # Vercel can rewrite X-Forwarded-Host to an internal name, which broke this check.
    host = request.headers.get("host") or request.headers.get("x-forwarded-host", "")
    return origin.split("://", 1)[-1].lower() == host.lower()


def _secure(request: Request) -> bool:
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def _html(content: str, nonce: str, status: int = 200) -> HTMLResponse:
    resp = HTMLResponse(content, status_code=status)
    resp.headers["Content-Security-Policy"] = (
        # style-src needs 'unsafe-inline' for style attributes (risk bars); all content is autoescaped.
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; "
        "img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return resp


def _index(request: Request, *, error: str | None = None, indicators: str = "", status: int = 200) -> HTMLResponse:
    nonce = secrets.token_urlsafe(16)
    settings = Settings.from_env()
    html = render_template(
        "index.html.j2", nonce=nonce, configured=_configured(), authed=_authed(request), error=error,
        indicators=indicators, types=[t.value for t in IType], max_indicators=MAX_INDICATORS,
        ai_available=settings.has("ANTHROPIC_API_KEY"),
    )
    return _html(html, nonce, status)


@app.middleware("http")
async def security_headers(request: Request, call_next: Any) -> Response:
    resp: Response = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if _secure(request):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


async def _run(values: list[str], itype: str | None, ai: bool) -> Any:
    settings = Settings.from_env()
    forced = IType(itype) if itype else None
    rep = await investigate(values, settings, forced=forced, timeout=min(settings.http_timeout, WEB_TIMEOUT))
    if ai and settings.has("ANTHROPIC_API_KEY") and rep.indicators:
        from ..ai_summary import summarise

        try:
            rep.ai_summary = await asyncio.to_thread(summarise, rep, settings)
        except RuntimeError as e:
            rep.warnings.append(f"AI summary skipped: {e}")
    return rep


# ---------------------------------------------------------------- routes
@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"ok": True, "configured": _configured(), "version": __version__}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return _index(request, status=200 if _configured() else 503)


@app.post("/login")
async def login(request: Request, token: str = Form("")) -> Response:
    if not _configured():
        return _index(request, status=503)
    if not _same_origin(request):
        return _index(request, error="Cross-origin request blocked.", status=403)
    if _rate_limited(request, "login", per_minute=5):
        return _index(request, error="Too many attempts. Wait a minute.", status=429)
    if not hmac.compare_digest(token.strip().encode(), _token().encode()):
        return _index(request, error="Invalid token.", status=401)
    resp = RedirectResponse("./", status_code=303)
    resp.set_cookie(COOKIE, _session_value(int(time.time())), max_age=SESSION_TTL, httponly=True,
                    secure=_secure(request), samesite="strict", path="/")
    return resp


@app.post("/logout")
async def logout() -> Response:
    resp = RedirectResponse("./", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.post("/lookup")
async def lookup(
    request: Request, indicators: str = Form(""), type: str = Form(""), ai_summary: str = Form("")
) -> Response:
    if not _configured():
        return _index(request, status=503)
    if not _authed(request):
        return RedirectResponse("./", status_code=303)
    if not _same_origin(request):
        return _index(request, error="Cross-origin request blocked.", status=403)
    if _rate_limited(request, "lookup"):
        return _index(request, error="Rate limit reached. Try again in a minute.", indicators=indicators, status=429)
    values = [v for v in indicators.splitlines() if v.strip()]
    if not values:
        return _index(request, error="Enter at least one indicator.", status=400)
    if len(values) > MAX_INDICATORS:
        return _index(request, error=f"Maximum {MAX_INDICATORS} indicators per request.", indicators=indicators,
                      status=400)
    if type and type not in {t.value for t in IType}:
        return _index(request, error="Unknown type.", indicators=indicators, status=400)
    rep = await _run(values, type or None, ai_summary == "1")
    if not rep.indicators:
        return _index(request, error="; ".join(rep.warnings) or "No valid indicators.", indicators=indicators,
                      status=400)
    nonce = secrets.token_urlsafe(16)
    return _html(to_html(rep, web=True, nonce=nonce), nonce)


class LookupRequest(BaseModel):
    indicators: list[str] = Field(..., min_length=1, max_length=MAX_INDICATORS)
    type: IType | None = None
    ai_summary: bool = False


@app.post("/api/lookup")
async def api_lookup(request: Request, body: LookupRequest) -> JSONResponse:
    if not _configured():
        return JSONResponse({"error": "server not configured"}, status_code=503)
    if not _bearer_ok(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})
    if _rate_limited(request, "lookup"):
        return JSONResponse({"error": "rate limited"}, status_code=429)
    rep = await _run(body.indicators, body.type.value if body.type else None, body.ai_summary)
    return JSONResponse(rep.to_dict())
