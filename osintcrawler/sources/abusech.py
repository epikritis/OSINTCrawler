"""abuse.ch feeds: URLhaus, MalwareBazaar, ThreatFox (one free Auth-Key for all)."""

from __future__ import annotations

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, check

KEY = "ABUSECH_AUTH_KEY"


def _hdr(ctx: Context) -> dict[str, str]:
    return {"Auth-Key": ctx.key(KEY) or ""}


class URLhaus(Source):
    name = "URLhaus"
    types = frozenset({IType.URL, IType.DOMAIN, IType.IP, IType.HASH})
    key_env = KEY
    homepage = "https://urlhaus.abuse.ch"
    description = "Malware distribution URLs"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        base = "https://urlhaus-api.abuse.ch/v1"
        if ind.type is IType.URL:
            endpoint, form = "url", {"url": ind.value}
        elif ind.type is IType.HASH:
            ht = ind.meta.get("hash_type")
            if ht not in ("md5", "sha256"):
                return self.skipped("URLhaus only supports MD5/SHA256")
            endpoint, form = "payload", {f"{ht}_hash": ind.value}
        else:
            endpoint, form = "host", {"host": ind.value}
        resp = check(await ctx.client.post(f"{base}/{endpoint}/", data=form, headers=_hdr(ctx)), key_name=KEY)
        d = resp.json() if resp is not None else {}
        status = d.get("query_status")
        if resp is None or status in ("no_results", "not_found"):
            return self.not_found("Not listed in URLhaus")
        if status != "ok":
            return self.error(f"query_status={status}")

        if endpoint == "url":
            online = d.get("url_status") == "online"
            return self.ok(
                score=90 if online else 70, confidence=0.9,
                findings=[f"Listed as {d.get('threat')} ({d.get('url_status')}), added {d.get('date_added')}"],
                tags=list(d.get("tags") or [])[:6] + ["malware-distribution"],
                link=d.get("urlhaus_reference"),
                data={k: d.get(k) for k in ("threat", "url_status", "date_added", "last_online", "tags", "host",
                                             "blacklists", "reporter")},
            )
        if endpoint == "payload":
            urls = d.get("urls") or []
            return self.ok(
                score=85, confidence=0.9,
                findings=[f"Payload seen at {len(urls)} URL(s); signature {d.get('signature') or 'n/a'}"],
                tags=["malware"], link=f"https://urlhaus.abuse.ch/browse.php?search={ind.value}",
                data={"signature": d.get("signature"), "file_type": d.get("file_type"),
                      "firstseen": d.get("firstseen"), "urls": [u.get("url") for u in urls[:10]]},
            )
        urls = d.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        bl = {k: v for k, v in (d.get("blacklists") or {}).items() if v and v != "not listed"}
        score = 85 if online else (65 if urls else 0)
        if bl:
            score = max(score, 70)
        findings = [f"{d.get('url_count', len(urls))} malware URL(s) hosted, {online} online"]
        if bl:
            findings.append("Blocklists: " + ", ".join(f"{k}={v}" for k, v in bl.items()))
        return self.ok(
            score=score, confidence=0.85, findings=findings, tags=["malware-host"] if urls else [],
            link=d.get("urlhaus_reference"),
            data={"url_count": d.get("url_count"), "firstseen": d.get("firstseen"), "blacklists": d.get("blacklists"),
                  "urls": [{"url": u.get("url"), "status": u.get("url_status"), "threat": u.get("threat"),
                            "date_added": u.get("date_added")} for u in urls[:15]]},
        )


class MalwareBazaar(Source):
    name = "MalwareBazaar"
    types = frozenset({IType.HASH})
    key_env = KEY
    homepage = "https://bazaar.abuse.ch"
    description = "Malware sample repository"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(
            await ctx.client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": ind.value},
                                  headers=_hdr(ctx)),
            key_name=KEY,
        )
        d = resp.json() if resp is not None else {}
        if resp is None or d.get("query_status") in ("hash_not_found", "no_results"):
            return self.not_found("Not in MalwareBazaar")
        if d.get("query_status") != "ok":
            return self.error(f"query_status={d.get('query_status')}")
        s = (d.get("data") or [{}])[0]
        findings = [f"Known malware sample: {s.get('signature') or 'unclassified'} "
                    f"({s.get('file_type')}), first seen {s.get('first_seen')}"]
        if s.get("file_name"):
            findings.append(f"File name: {s.get('file_name')}")
        return self.ok(
            score=100, confidence=0.95, findings=findings, tags=["malware"] + list(s.get("tags") or [])[:5],
            link=f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/",
            data={k: s.get(k) for k in ("sha256_hash", "sha1_hash", "md5_hash", "file_name", "file_type",
                                         "file_size", "signature", "first_seen", "last_seen", "tags",
                                         "delivery_method", "reporter", "imphash", "ssdeep")},
        )


class ThreatFox(Source):
    name = "ThreatFox"
    types = frozenset({IType.IP, IType.DOMAIN, IType.URL, IType.HASH})
    key_env = KEY
    homepage = "https://threatfox.abuse.ch"
    description = "IOCs linked to malware families / C2"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        if ind.type is IType.HASH:
            body = {"query": "search_hash", "hash": ind.value}
        else:
            body = {"query": "search_ioc", "search_term": ind.value, "exact_match": True}
        resp = check(
            await ctx.client.post("https://threatfox-api.abuse.ch/api/v1/", json=body, headers=_hdr(ctx)),
            key_name=KEY,
        )
        d = resp.json() if resp is not None else {}
        if resp is None or d.get("query_status") in ("no_result", "no_results", "not_found"):
            return self.not_found("Not in ThreatFox")
        if d.get("query_status") != "ok":
            return self.error(f"query_status={d.get('query_status')}")
        iocs = d.get("data") or []
        if not isinstance(iocs, list) or not iocs:
            return self.not_found("Not in ThreatFox")
        families = sorted({i.get("malware_printable") for i in iocs if i.get("malware_printable")})
        conf = max((i.get("confidence_level") or 0) for i in iocs)
        threat_types = sorted({i.get("threat_type_desc") or i.get("threat_type") for i in iocs} - {None})
        return self.ok(
            score=max(70, conf), confidence=0.9,
            findings=[f"{len(iocs)} IOC record(s): {', '.join(families[:5]) or 'unknown family'}"
                      + (f" - {', '.join(threat_types[:3])}" if threat_types else "")],
            tags=["c2" if any("botnet_cc" == i.get("threat_type") for i in iocs) else "malware-ioc"],
            link=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ind.value}",
            data={"iocs": [{k: i.get(k) for k in ("ioc", "threat_type", "malware_printable", "confidence_level",
                                                   "first_seen", "last_seen", "tags", "reference")}
                           for i in iocs[:15]]},
        )
