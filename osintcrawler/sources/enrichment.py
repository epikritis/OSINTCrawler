"""Enrichment flags for IPs / domains / URLs.

* Tor exit node membership (Tor Project bulk exit list)
* Cloud / CDN provider ranges (AWS, GCP, Cloudflare, Oracle, Fastly, DigitalOcean)
* Lexical heuristics: suspicious TLDs, punycode, DGA-like labels, IP-literal URLs,
  credential-phishing keywords, URL shorteners, user-info tricks, odd ports.

VPN / proxy / hosting flags come from ipinfo (paid tiers), AbuseIPDB and
GreyNoise; their tags are merged into the indicator summary by the scorer.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, check
from .infra import doh

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "country", "kim", "loan",
    "men", "party", "review", "stream", "download", "racing", "win", "bid", "icu", "cyou", "rest", "sbs", "cfd",
    "lol", "buzz", "monster", "quest", "support", "live", "shop",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "s.id", "t.ly", "lnkd.in",
}
PHISH_WORDS = re.compile(
    r"log[-_]?in|sign[-_]?in|verify|verification|account|update|secure|banking|wallet|password|webscr|invoice|"
    r"recover|unlock|suspend|confirm|billing|office365|microsoft|paypal|appleid", re.I,
)
TTL_FEEDS = 6 * 3600


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


async def _tor_exits(ctx: Context) -> set[str]:
    async def load() -> set[str]:
        resp = check(await ctx.client.get("https://check.torproject.org/torbulkexitlist"))
        return {line.strip() for line in (resp.text if resp is not None else "").splitlines() if line.strip()}

    return await ctx.cached("tor-exits", load, ttl=TTL_FEEDS)


async def _cloud_ranges(ctx: Context) -> list[tuple[IPNet, str, str]]:
    async def load() -> list[tuple[IPNet, str, str]]:
        nets: list[tuple[IPNet, str, str]] = []

        def add(cidr: str | None, provider: str, detail: str = "") -> None:
            if not cidr:
                return
            try:
                nets.append((ipaddress.ip_network(cidr.strip(), strict=False), provider, detail))
            except ValueError:
                pass

        async def get(url: str) -> Any:
            try:
                r = await ctx.client.get(url, timeout=15)
                return r if r.status_code == 200 else None
            except Exception:
                return None

        if (r := await get("https://ip-ranges.amazonaws.com/ip-ranges.json")):
            j = r.json()
            for p in j.get("prefixes", []):
                add(p.get("ip_prefix"), "AWS", f"{p.get('service')} {p.get('region')}")
            for p in j.get("ipv6_prefixes", []):
                add(p.get("ipv6_prefix"), "AWS", f"{p.get('service')} {p.get('region')}")
        if (r := await get("https://www.gstatic.com/ipranges/cloud.json")):
            for p in r.json().get("prefixes", []):
                add(p.get("ipv4Prefix") or p.get("ipv6Prefix"), "Google Cloud", f"{p.get('service')} {p.get('scope')}")
        for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
            if (r := await get(url)):
                for line in r.text.splitlines():
                    add(line, "Cloudflare")
        if (r := await get("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")):
            for reg in r.json().get("regions", []):
                for c in reg.get("cidrs", []):
                    add(c.get("cidr"), "Oracle Cloud", reg.get("region", ""))
        if (r := await get("https://api.fastly.com/public-ip-list")):
            j = r.json()
            for c in j.get("addresses", []) + j.get("ipv6_addresses", []):
                add(c, "Fastly")
        if (r := await get("https://digitalocean.com/geo/google.csv")):
            for line in r.text.splitlines():
                parts = line.split(",")
                add(parts[0], "DigitalOcean", parts[2] if len(parts) > 2 else "")
        return nets

    return await ctx.cached("cloud-ranges", load, ttl=TTL_FEEDS * 4)


def domain_heuristics(domain: str) -> tuple[int, list[str], list[str]]:
    score, findings, tags = 0, [], []
    labels = domain.split(".")
    tld = labels[-1]
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    if tld in SUSPICIOUS_TLDS:
        score += 15
        findings.append(f"TLD .{tld} is frequently abused")
        tags.append("suspicious-tld")
    if "xn--" in domain:
        score += 20
        findings.append("Punycode/IDN domain - check for homograph impersonation")
        tags.append("punycode")
    if len(sld) >= 12 and _entropy(sld) > 3.6 and not re.search(r"[aeiou]{2}", sld):
        score += 20
        findings.append(f"Label '{sld}' looks algorithmically generated (entropy {_entropy(sld):.2f})")
        tags.append("dga-like")
    if sld.count("-") >= 3:
        score += 10
        findings.append("Many hyphens in domain label")
    if len(labels) >= 5:
        score += 10
        findings.append(f"Deep subdomain nesting ({len(labels)} labels)")
    if PHISH_WORDS.search(domain):
        score += 10
        findings.append("Domain contains credential/brand-phishing keywords")
        tags.append("phishing-keywords")
    return score, findings, tags


def url_heuristics(ind: Indicator) -> tuple[int, list[str], list[str]]:
    host = ind.meta.get("host", "")
    score, findings, tags = 0, [], []
    try:
        ipaddress.ip_address(host.strip("[]"))
        score += 25
        findings.append("URL uses a raw IP address instead of a hostname")
        tags.append("ip-literal-url")
    except ValueError:
        s, f, t = domain_heuristics(host)
        score, findings, tags = score + s, findings + f, tags + t
    netloc = ind.value.split("//", 1)[-1].split("/", 1)[0]
    if "@" in netloc:
        score += 25
        findings.append("URL contains user-info '@' (classic obfuscation)")
        tags.append("userinfo-obfuscation")
    port = ind.meta.get("port")
    if port and port not in (80, 443, 8080, 8443):
        score += 10
        findings.append(f"Non-standard port {port}")
    if host in SHORTENERS:
        findings.append("URL shortener - destination hidden")
        tags.append("url-shortener")
    path = ind.value.split(host, 1)[-1]
    if len(PHISH_WORDS.findall(path)) >= 2:
        score += 15
        findings.append("Path contains several credential-phishing keywords")
        tags.append("phishing-keywords")
    return score, findings, tags


class Enrichment(Source):
    name = "Enrichment"
    types = frozenset({IType.IP, IType.DOMAIN, IType.URL})
    timeout = 30
    description = "Tor exit, cloud/CDN ranges, lexical heuristics"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        score, findings, tags = 0, [], []
        data: dict[str, Any] = {}

        if ind.type is IType.DOMAIN:
            s, f, t = domain_heuristics(ind.value)
            score, findings, tags = s, f, t
        elif ind.type is IType.URL:
            s, f, t = url_heuristics(ind)
            score, findings, tags = s, f, t

        # Resolve to IPs (DoH) for domains/URLs, then apply IP-level flags.
        if ind.type is IType.IP:
            ips = [ind.value]
        else:
            host = ind.meta.get("host") or ind.value
            try:
                ipaddress.ip_address(host.strip("[]"))
                ips = [host.strip("[]")]
            except ValueError:
                ips = (await doh(ctx, host, "A"))[:8] + (await doh(ctx, host, "AAAA"))[:4]
        data["resolved_ips"] = ips

        tor = await _tor_exits(ctx)
        tor_hits = [ip for ip in ips if ip in tor]
        if tor_hits:
            score += 40
            tags.append("tor-exit")
            findings.insert(0, f"Tor exit node: {', '.join(tor_hits)}")

        clouds = await _cloud_ranges(ctx)
        cloud_hits: dict[str, dict[str, str]] = {}
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for net, provider, detail in clouds:
                if addr.version == net.version and addr in net:
                    cloud_hits[ip] = {"provider": provider, "detail": detail.strip(), "range": str(net)}
                    break
        if cloud_hits:
            providers = sorted({h["provider"] for h in cloud_hits.values()})
            findings.append("Hosted on " + ", ".join(providers)
                            + (" (CDN - IP reputation is shared)" if "Cloudflare" in providers or "Fastly" in providers else ""))
            tags += [f"cloud:{p.lower().replace(' ', '-')}" for p in providers]
        data.update(tor_exit=tor_hits, cloud=cloud_hits, cloud_ranges_loaded=len(clouds), tor_list_size=len(tor))

        if not findings:
            findings.append("No enrichment flags raised")
        return self.ok(score=min(score, 70), confidence=0.7, findings=findings, tags=tags, data=data)
