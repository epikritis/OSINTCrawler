"""Vulnerability intelligence: NVD, CISA KEV, FIRST EPSS."""

from __future__ import annotations

from typing import Any

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, SourceError, check

CVE = IType.CVE


class NVD(Source):
    name = "NVD"
    types = frozenset({CVE})
    key_env = "NVD_API_KEY"
    key_required = False
    timeout = 25
    homepage = "https://nvd.nist.gov"
    description = "CVE details & CVSS"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        headers = {"apiKey": k} if (k := ctx.key(self.key_env)) else {}
        resp = check(await ctx.client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                          params={"cveId": ind.value}, headers=headers), key_name=self.key_env)
        link = f"https://nvd.nist.gov/vuln/detail/{ind.value}"
        vulns = (resp.json().get("vulnerabilities") if resp is not None else None) or []
        if not vulns:
            return self.not_found("CVE not found in NVD", link=link)
        c = vulns[0].get("cve", {})
        desc = next((d.get("value") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        metrics = c.get("metrics", {})
        cvss: dict[str, Any] | None = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cd = m.get("cvssData", {})
                cvss = {"version": cd.get("version"), "base_score": cd.get("baseScore"),
                        "severity": cd.get("baseSeverity") or m.get("baseSeverity"), "vector": cd.get("vectorString")}
                break
        cwes = sorted({d.get("value") for w in c.get("weaknesses", []) for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE")})
        base = (cvss or {}).get("base_score")
        findings = [f"CVSS {cvss['version']} {base} {cvss['severity']}" if cvss else "No CVSS score yet",
                    desc[:240] + ("..." if len(desc) > 240 else "")]
        return self.ok(
            score=int(round(base * 10)) if base is not None else None, confidence=0.7,
            findings=findings, link=link,
            data={"description": desc, "cvss": cvss, "cwes": cwes, "published": c.get("published"),
                  "last_modified": c.get("lastModified"), "status": c.get("vulnStatus"),
                  "references": [r.get("url") for r in c.get("references", [])[:25]]},
        )


class CISAKEV(Source):
    name = "CISA KEV"
    types = frozenset({CVE})
    timeout = 25
    homepage = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    description = "Known Exploited Vulnerabilities catalogue"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        async def load() -> dict[str, dict[str, Any]]:
            resp = check(await ctx.client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
            if resp is None:
                raise SourceError("KEV feed not found")
            return {v["cveID"].upper(): v for v in resp.json().get("vulnerabilities", [])}

        catalog = await ctx.cached("cisa-kev", load, ttl=6 * 3600)
        entry = catalog.get(ind.value)
        if not entry:
            return self.ok(score=0, confidence=0.3, findings=["Not in CISA KEV (no confirmed in-the-wild exploitation)"])
        ransomware = (entry.get("knownRansomwareCampaignUse") or "").lower() == "known"
        findings = [f"KNOWN EXPLOITED - {entry.get('vendorProject')} {entry.get('product')}: "
                    f"{entry.get('vulnerabilityName')} (added {entry.get('dateAdded')})"]
        if ransomware:
            findings.append("Known use in ransomware campaigns")
        return self.ok(score=100 if ransomware else 90, confidence=0.95, findings=findings,
                       tags=["known-exploited"] + (["ransomware"] if ransomware else []), data=entry,
                       link="https://www.cisa.gov/known-exploited-vulnerabilities-catalog")


class EPSS(Source):
    name = "EPSS"
    types = frozenset({CVE})
    homepage = "https://www.first.org/epss/"
    description = "Exploit prediction probability (30 days)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(await ctx.client.get("https://api.first.org/data/v1/epss", params={"cve": ind.value}))
        rows = (resp.json().get("data") if resp is not None else None) or []
        if not rows:
            return self.not_found("No EPSS score")
        r = rows[0]
        epss, pct = float(r.get("epss", 0)), float(r.get("percentile", 0))
        return self.ok(
            score=int(round(epss * 100)), confidence=0.8,
            findings=[f"{epss:.1%} probability of exploitation in 30 days (percentile {pct:.1%}), as of {r.get('date')}"],
            data=r, link=f"https://api.first.org/data/v1/epss?cve={ind.value}",
        )
