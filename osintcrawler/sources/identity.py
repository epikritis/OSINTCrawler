"""Email / identity sources."""

from __future__ import annotations

import hashlib
from urllib.parse import quote

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, check

EMAIL, DOMAIN = IType.EMAIL, IType.DOMAIN


class HaveIBeenPwned(Source):
    name = "HaveIBeenPwned"
    types = frozenset({EMAIL})
    key_env = "HIBP_API_KEY"
    homepage = "https://haveibeenpwned.com"
    description = "Breach exposure (paid key)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(
            await ctx.client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(ind.value)}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": ctx.key(self.key_env)},
            ),
            key_name=self.key_env,
        )
        if resp is None:
            return self.ok(findings=["Not found in any known breach"], data={"breaches": []})
        breaches = resp.json()
        breaches.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)
        classes = sorted({c for b in breaches for c in b.get("DataClasses", [])})
        return self.ok(
            findings=[f"Found in {len(breaches)} breach(es); latest {breaches[0].get('Name')} "
                      f"({breaches[0].get('BreachDate')})",
                      "Exposed data: " + ", ".join(classes[:8])],
            tags=["breached"] + (["password-exposed"] if "Passwords" in classes else []),
            link="https://haveibeenpwned.com/",
            data={"breach_count": len(breaches), "data_classes": classes,
                  "breaches": [{"name": b.get("Name"), "domain": b.get("Domain"), "date": b.get("BreachDate"),
                                "pwn_count": b.get("PwnCount"), "data_classes": b.get("DataClasses"),
                                "verified": b.get("IsVerified")} for b in breaches[:30]]},
        )


class Hunter(Source):
    name = "Hunter.io"
    types = frozenset({EMAIL, DOMAIN})
    key_env = "HUNTER_API_KEY"
    homepage = "https://hunter.io"
    description = "Email verification & domain email discovery"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        headers = {"X-API-KEY": ctx.key(self.key_env) or ""}
        if ind.type is EMAIL:
            resp = check(await ctx.client.get("https://api.hunter.io/v2/email-verifier",
                                              params={"email": ind.value}, headers=headers), key_name=self.key_env)
            if resp is None:
                return self.not_found()
            d = resp.json().get("data") or {}
            tags = [t for t in ("disposable", "webmail", "gibberish") if d.get(t)]
            score = 40 if d.get("disposable") else (15 if d.get("gibberish") else 0)
            return self.ok(
                score=score, confidence=0.6, tags=tags,
                findings=[f"Status {d.get('status')} (result {d.get('result')}, score {d.get('score')}); "
                          f"{len(d.get('sources') or [])} public source(s)"],
                data={k: d.get(k) for k in ("status", "result", "score", "regexp", "gibberish", "disposable",
                                             "webmail", "mx_records", "smtp_server", "smtp_check", "accept_all",
                                             "block")}
                     | {"sources": [s.get("uri") for s in (d.get("sources") or [])[:10]]},
            )
        resp = check(await ctx.client.get("https://api.hunter.io/v2/domain-search",
                                          params={"domain": ind.value, "limit": 10}, headers=headers),
                     key_name=self.key_env)
        if resp is None:
            return self.not_found()
        d = resp.json().get("data") or {}
        emails = d.get("emails") or []
        meta = resp.json().get("meta") or {}
        findings = [f"{(meta.get('results') or len(emails))} email(s) indexed; pattern {d.get('pattern') or 'unknown'}"]
        if d.get("organization"):
            findings.append(f"Organisation: {d.get('organization')}")
        return self.ok(
            findings=findings, link=f"https://hunter.io/search/{ind.value}",
            data={"organization": d.get("organization"), "pattern": d.get("pattern"), "disposable": d.get("disposable"),
                  "webmail": d.get("webmail"), "total_results": meta.get("results"),
                  "emails": [{"value": e.get("value"), "type": e.get("type"), "position": e.get("position"),
                              "confidence": e.get("confidence")} for e in emails]},
        )


class EmailRep(Source):
    name = "EmailRep"
    types = frozenset({EMAIL})
    key_env = "EMAILREP_API_KEY"
    key_required = False
    homepage = "https://emailrep.io"
    description = "Email reputation & profile presence"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        headers = {"Key": k} if (k := ctx.key(self.key_env)) else {}
        resp = check(await ctx.client.get(f"https://emailrep.io/{quote(ind.value)}", headers=headers),
                     key_name=self.key_env, not_found=(404, 400))
        if resp is None:
            return self.not_found()
        d = resp.json()
        det = d.get("details") or {}
        score = 0
        if det.get("malicious_activity_recent"):
            score = 85
        elif det.get("malicious_activity") or det.get("blacklisted"):
            score = 70
        elif d.get("suspicious"):
            score = 45
        tags = [t for t in ("blacklisted", "malicious_activity", "credentials_leaked", "data_breach", "spam",
                            "disposable", "free_provider", "spoofable", "new_domain") if det.get(t)]
        findings = [f"Reputation {d.get('reputation')}, suspicious={d.get('suspicious')}, "
                    f"{d.get('references', 0)} reference(s); first seen {det.get('first_seen')}"]
        if det.get("profiles"):
            findings.append("Profiles: " + ", ".join(det["profiles"][:10]))
        return self.ok(score=score, confidence=0.6, findings=findings,
                       tags=[t.replace("_", "-") for t in tags], data=d,
                       link=f"https://emailrep.io/{quote(ind.value)}")


class Gravatar(Source):
    name = "Gravatar"
    types = frozenset({EMAIL})
    homepage = "https://gravatar.com"
    description = "Public profile linked to the email (keyless)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        h = hashlib.sha256(ind.value.strip().lower().encode()).hexdigest()
        resp = check(await ctx.client.get(f"https://api.gravatar.com/v3/profiles/{h}"))
        if resp is None:
            return self.not_found("No Gravatar profile")
        d = resp.json()
        accounts = [a.get("url") for a in d.get("verified_accounts") or [] if a.get("url")]
        findings = [f"Profile: {d.get('display_name') or 'unnamed'}"
                    + (f", {d.get('location')}" if d.get("location") else "")]
        if accounts:
            findings.append("Linked accounts: " + ", ".join(accounts[:6]))
        return self.ok(findings=findings, link=d.get("profile_url"),
                       data={k: d.get(k) for k in ("display_name", "profile_url", "location", "description",
                                                    "job_title", "company", "pronouns", "avatar_url")}
                       | {"verified_accounts": accounts})
