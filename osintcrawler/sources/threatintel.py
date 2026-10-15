"""Reputation / threat-intelligence sources."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from urllib.parse import quote

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, SourceError, check

IP, DOMAIN, URL, HASH, CVE = IType.IP, IType.DOMAIN, IType.URL, IType.HASH, IType.CVE


def _ts(epoch: int | None) -> str | None:
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


class VirusTotal(Source):
    name = "VirusTotal"
    types = frozenset({IP, DOMAIN, URL, HASH})
    key_env = "VT_API_KEY"
    homepage = "https://www.virustotal.com"
    description = "Multi-engine AV/URL reputation"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        if ind.type is IP:
            path, gui = f"ip_addresses/{ind.value}", f"ip-address/{ind.value}"
        elif ind.type is DOMAIN:
            path, gui = f"domains/{ind.value}", f"domain/{ind.value}"
        elif ind.type is HASH:
            path, gui = f"files/{ind.value}", f"file/{ind.value}"
        else:
            url_id = base64.urlsafe_b64encode(ind.value.encode()).decode().rstrip("=")
            path, gui = f"urls/{url_id}", f"url/{url_id}"
        resp = check(
            await ctx.client.get(
                f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": ctx.key(self.key_env)}
            ),
            key_name=self.key_env,
        )
        link = f"https://www.virustotal.com/gui/{gui}"
        if resp is None:
            return self.not_found("Not present in VirusTotal", link=link)
        attr = resp.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {}) or {}
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int))
        score = min(100, mal * 10 + sus * 4)
        findings = [f"{mal}/{total} engines malicious, {sus} suspicious"]
        data = {
            "last_analysis_stats": stats,
            "reputation": attr.get("reputation"),
            "tags": attr.get("tags", []),
            "last_analysis_date": _ts(attr.get("last_analysis_date")),
        }
        if ind.type is IP:
            data.update(asn=attr.get("asn"), as_owner=attr.get("as_owner"), country=attr.get("country"),
                        network=attr.get("network"))
            if attr.get("as_owner"):
                findings.append(f"AS{attr.get('asn')} {attr.get('as_owner')} ({attr.get('country', '?')})")
        elif ind.type is DOMAIN:
            data.update(registrar=attr.get("registrar"), creation_date=_ts(attr.get("creation_date")),
                        categories=attr.get("categories", {}))
            cats = sorted(set((attr.get("categories") or {}).values()))
            if cats:
                findings.append("Categories: " + ", ".join(cats[:5]))
        elif ind.type is HASH:
            label = (attr.get("popular_threat_classification") or {}).get("suggested_threat_label")
            data.update(
                meaningful_name=attr.get("meaningful_name"), type_description=attr.get("type_description"),
                size=attr.get("size"), md5=attr.get("md5"), sha1=attr.get("sha1"), sha256=attr.get("sha256"),
                first_submission_date=_ts(attr.get("first_submission_date")), threat_label=label,
                names=(attr.get("names") or [])[:10],
            )
            if label:
                findings.append(f"Threat label: {label}")
            if attr.get("type_description"):
                findings.append(f"{attr.get('type_description')} - {attr.get('meaningful_name') or 'unnamed'}")
        else:
            data.update(final_url=attr.get("last_final_url"), title=attr.get("title"),
                        categories=attr.get("categories", {}))
        return self.ok(score=score, confidence=0.9, findings=findings, data=data, link=link,
                       tags=[t for t in attr.get("tags", [])[:5]])


class AbuseIPDB(Source):
    name = "AbuseIPDB"
    types = frozenset({IP})
    key_env = "ABUSEIPDB_API_KEY"
    homepage = "https://www.abuseipdb.com"
    description = "Crowd-sourced IP abuse reports"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(
            await ctx.client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ind.value, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": ctx.key(self.key_env), "Accept": "application/json"},
            ),
            key_name=self.key_env,
        )
        if resp is None:
            return self.not_found()
        d = resp.json().get("data", {})
        reports = d.get("reports") or []
        cats = sorted({c for r in reports[:200] for c in r.get("categories", [])})
        conf = d.get("abuseConfidenceScore", 0) or 0
        findings = [f"Abuse confidence {conf}% from {d.get('totalReports', 0)} reports "
                    f"by {d.get('numDistinctUsers', 0)} users (90d)"]
        if d.get("isp"):
            findings.append(f"{d.get('isp')} - {d.get('usageType') or 'unknown usage'} ({d.get('countryCode')})")
        tags = []
        if d.get("isTor"):
            tags.append("tor-exit")
        if d.get("isWhitelisted"):
            tags.append("known-good")
        return self.ok(
            score=conf, confidence=0.8, findings=findings, tags=tags,
            link=f"https://www.abuseipdb.com/check/{ind.value}",
            data={k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "countryCode",
                                         "usageType", "isp", "domain", "hostnames", "isTor", "isWhitelisted",
                                         "lastReportedAt")} | {"report_categories": [_ABUSE_CATS.get(c, c) for c in cats]},
        )


_ABUSE_CATS = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
    23: "IoT Targeted",
}


class AlienVaultOTX(Source):
    name = "AlienVault OTX"
    types = frozenset({IP, DOMAIN, URL, HASH, CVE})
    key_env = "OTX_API_KEY"
    key_required = False
    homepage = "https://otx.alienvault.com"
    description = "Community threat pulses"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        section = {
            IP: "IPv6" if ind.meta.get("version") == 6 else "IPv4",
            DOMAIN: "domain", URL: "url", HASH: "file", CVE: "cve",
        }[ind.type]
        headers = {"X-OTX-API-KEY": k} if (k := ctx.key(self.key_env)) else {}
        resp = check(
            await ctx.client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(ind.value, safe='')}/general",
                headers=headers,
            ),
            key_name=self.key_env, not_found=(404, 400),
        )
        link = f"https://otx.alienvault.com/indicator/{section.lower().replace('ipv4', 'ip').replace('ipv6', 'ip')}/{quote(ind.value, safe='')}"
        if resp is None:
            return self.not_found("No OTX record", link=link)
        d = resp.json()
        pulse_info = d.get("pulse_info") or {}
        count = pulse_info.get("count", 0) or 0
        pulses = pulse_info.get("pulses") or []
        families = sorted({
            (m.get("display_name") if isinstance(m, dict) else str(m))
            for p in pulses for m in (p.get("malware_families") or [])
        } - {None, ""})
        validation = sorted({v.get("name") or v.get("message") for v in (d.get("validation") or [])
                             if isinstance(v, dict)} - {None, ""})
        tags = sorted({t for p in pulses[:50] for t in (p.get("tags") or [])})[:10]
        # OTX "validation" mixes real allow-listing with neutral notes (e.g. "IP associated with Tor").
        whitelisted = any(re.search(r"whitelist|false positive|popular|alexa|majestic|tranco", v, re.I)
                          for v in validation)
        if whitelisted:
            score = 0
        elif count >= 10:
            score = 80
        elif count >= 3:
            score = 60
        elif count >= 1:
            score = 35
        else:
            score = 0
        # /general returns at most 50 pulses, and count is capped to match.
        findings = [f"Referenced in {count}{'+' if count >= 50 else ''} pulse(s)"]
        if whitelisted:
            findings.insert(0, "Whitelisted by OTX: " + ", ".join(validation)[:200])
        elif validation:
            findings.append("OTX notes: " + ", ".join(validation)[:200])
        if families:
            findings.append("Malware families: " + ", ".join(families[:6]))
        return self.ok(
            score=score, confidence=0.6, findings=findings, link=link,
            tags=(["known-good"] if whitelisted else []),
            data={"pulse_count": count, "pulses": [p.get("name") for p in pulses[:15]], "malware_families": families,
                  "pulse_tags": tags, "validation": validation, "reputation": d.get("reputation")},
        )


class GreyNoise(Source):
    name = "GreyNoise"
    types = frozenset({IP})
    key_env = "GREYNOISE_API_KEY"
    key_required = False
    homepage = "https://viz.greynoise.io"
    description = "Internet scanner / benign service classification"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        headers = {"key": k} if (k := ctx.key(self.key_env)) else {}
        resp = await ctx.client.get(f"https://api.greynoise.io/v3/community/{ind.value}", headers=headers)
        link = f"https://viz.greynoise.io/ip/{ind.value}"
        if resp.status_code == 404:
            return self.ok(score=0, confidence=0.3, link=link,
                           findings=["Not observed scanning the internet in the last 90 days"], data=resp.json())
        check(resp, key_name=self.key_env)
        d = resp.json()
        cls = d.get("classification")
        tags = []
        if d.get("riot"):
            tags.append("known-good")
            tags.append("benign-service")
        if d.get("noise"):
            tags.append("internet-scanner")
        score = {"malicious": 80, "suspicious": 50, "unknown": 25 if d.get("noise") else 0}.get(cls or "", 0)
        findings = [f"Classification: {cls or 'n/a'}; noise={d.get('noise')}; riot={d.get('riot')}"]
        if d.get("name") and d.get("name") != "unknown":
            findings.append(f"Actor/service: {d.get('name')}")
        return self.ok(score=score, confidence=0.7, findings=findings, tags=tags, link=link, data=d)


class CIRCLHashlookup(Source):
    name = "CIRCL hashlookup"
    types = frozenset({HASH})
    homepage = "https://hashlookup.circl.lu"
    description = "Known-good files (NSRL and others)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        algo = ind.meta.get("hash_type", "sha256")
        resp = check(await ctx.client.get(f"https://hashlookup.circl.lu/lookup/{algo}/{ind.value}"))
        if resp is None:
            return self.not_found("Not in known-good file sets")
        d = resp.json()
        name = d.get("FileName") or d.get("filename") or "unknown file"
        return self.ok(
            score=0, confidence=0.8, tags=["known-good"],
            findings=[f"Known file: {name} (source: {d.get('source', 'NSRL')})"],
            data=d, link=f"https://hashlookup.circl.lu/lookup/{algo}/{ind.value}",
        )


class GoogleSafeBrowsing(Source):
    name = "Google Safe Browsing"
    types = frozenset({URL, DOMAIN})
    key_env = "GOOGLE_SAFEBROWSING_API_KEY"
    homepage = "https://transparencyreport.google.com/safe-browsing/search"
    description = "Google malware / phishing URL lists"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        urls = [ind.value] if ind.type is URL else [f"http://{ind.value}/", f"https://{ind.value}/"]
        body = {
            "client": {"clientId": "osintcrawler", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        resp = check(
            await ctx.client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                json=body, headers={"X-Goog-Api-Key": ctx.key(self.key_env)},
            ),
            key_name=self.key_env, not_found=(),
        )
        assert resp is not None
        matches = resp.json().get("matches") or []
        link = f"https://transparencyreport.google.com/safe-browsing/search?url={quote(ind.value, safe='')}"
        if not matches:
            return self.ok(score=0, confidence=0.5, findings=["Not on Safe Browsing lists"], link=link)
        kinds = sorted({m.get("threatType", "?") for m in matches})
        return self.ok(score=95, confidence=0.95, findings=["Listed: " + ", ".join(kinds)], link=link,
                       tags=[k.lower().replace("_", "-") for k in kinds], data={"matches": matches})


class URLScan(Source):
    name = "urlscan.io"
    types = frozenset({URL, DOMAIN, IP, HASH})
    key_env = "URLSCAN_API_KEY"
    key_required = False
    homepage = "https://urlscan.io"
    description = "Search of existing public scans (never submits)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        if ind.type is URL:
            q = f'page.url:"{ind.value}"'
        elif ind.type is DOMAIN:
            q = f"domain:{ind.value}"
        elif ind.type is IP:
            q = f'ip:"{ind.value}"'
        else:
            q = f"hash:{ind.value}"
        headers = {"API-Key": k} if (k := ctx.key(self.key_env)) else {}
        resp = check(
            await ctx.client.get("https://urlscan.io/api/v1/search/", params={"q": q, "size": 20}, headers=headers),
            key_name=self.key_env, not_found=(404, 400),
        )
        link = f"https://urlscan.io/search/#{quote(q)}"
        if resp is None:
            return self.not_found("No public scans", link=link)
        d = resp.json()
        results = d.get("results") or []
        if not results:
            return self.not_found("No public scans", link=link)
        latest = results[0]
        scans = [
            {"time": r.get("task", {}).get("time"), "url": r.get("task", {}).get("url"),
             "ip": r.get("page", {}).get("ip"), "country": r.get("page", {}).get("country"),
             "server": r.get("page", {}).get("server"), "result": r.get("result")}
            for r in results[:10]
        ]
        score, findings, verdict = 0, [f"{d.get('total', len(results))} public scan(s); latest {scans[0]['time']}"], None
        uuid = latest.get("_id") or latest.get("task", {}).get("uuid")
        if uuid:
            try:
                r2 = check(await ctx.client.get(f"https://urlscan.io/api/v1/result/{uuid}/", headers=headers))
                if r2 is not None:
                    verdict = (r2.json().get("verdicts") or {}).get("overall") or {}
            except SourceError:
                verdict = None
        if verdict:
            if verdict.get("malicious"):
                score = 85
                findings.insert(0, "Latest scan verdict: MALICIOUS " + ", ".join(verdict.get("categories") or []))
            elif (verdict.get("score") or 0) > 0:
                score = min(60, int(verdict.get("score")))
                findings.insert(0, f"Latest scan verdict score {verdict.get('score')}")
        return self.ok(score=score, confidence=0.6, findings=findings, link=link,
                       data={"total": d.get("total"), "scans": scans, "latest_verdict": verdict,
                             "screenshot": latest.get("screenshot")})
