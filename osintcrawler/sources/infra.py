"""Infrastructure, registration and passive-DNS sources."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..models import Indicator, IType, SourceResult
from .base import Context, Source, SourceError, check

IP, CIDR, ASN, DOMAIN, URL, EMAIL = IType.IP, IType.CIDR, IType.ASN, IType.DOMAIN, IType.URL, IType.EMAIL

_BAD_SHODAN_TAGS = {"malware", "c2", "compromised", "botnet", "honeypot", "tor"}


class ShodanInternetDB(Source):
    name = "Shodan InternetDB"
    types = frozenset({IP})
    homepage = "https://internetdb.shodan.io"
    description = "Open ports, CPEs, known CVEs (keyless)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(await ctx.client.get(f"https://internetdb.shodan.io/{ind.value}"))
        if resp is None:
            return self.not_found("No open services recorded")
        d = resp.json()
        ports, vulns, tags = d.get("ports") or [], d.get("vulns") or [], d.get("tags") or []
        findings = [f"Open ports: {', '.join(map(str, ports[:20])) or 'none'}"]
        if vulns:
            findings.append(f"{len(vulns)} known CVE(s) on exposed services: {', '.join(vulns[:5])}")
        if d.get("hostnames"):
            findings.append("Hostnames: " + ", ".join(d["hostnames"][:5]))
        bad = sorted(set(t.lower() for t in tags) & _BAD_SHODAN_TAGS - {"tor"})
        return self.ok(
            score=70 if bad else None, confidence=0.6 if bad else 0.0, findings=findings,
            tags=[t.lower() for t in tags], data=d, link=f"https://www.shodan.io/host/{ind.value}",
        )


class Shodan(Source):
    name = "Shodan"
    types = frozenset({IP})
    key_env = "SHODAN_API_KEY"
    homepage = "https://www.shodan.io"
    description = "Full host banners (paid API)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(
            await ctx.client.get(f"https://api.shodan.io/shodan/host/{ind.value}",
                                 params={"key": ctx.key(self.key_env), "minify": "false"}),
            key_name=self.key_env,
        )
        link = f"https://www.shodan.io/host/{ind.value}"
        if resp is None:
            return self.not_found("No Shodan host record", link=link)
        d = resp.json()
        services = [
            {"port": s.get("port"), "transport": s.get("transport"), "product": s.get("product"),
             "version": s.get("version"), "timestamp": s.get("timestamp")}
            for s in (d.get("data") or [])[:30]
        ]
        findings = [f"{d.get('org') or d.get('isp')} ({d.get('country_name')}), OS {d.get('os') or 'unknown'}",
                    "Services: " + ", ".join(f"{s['port']}/{s['product'] or '?'}" for s in services[:10])]
        return self.ok(
            findings=findings, link=link, tags=[t.lower() for t in d.get("tags") or []],
            data={"org": d.get("org"), "isp": d.get("isp"), "asn": d.get("asn"), "os": d.get("os"),
                  "country": d.get("country_name"), "city": d.get("city"), "hostnames": d.get("hostnames"),
                  "domains": d.get("domains"), "ports": d.get("ports"), "vulns": list(d.get("vulns") or [])[:30],
                  "last_update": d.get("last_update"), "services": services},
        )


class SecurityTrails(Source):
    name = "SecurityTrails"
    types = frozenset({DOMAIN})
    key_env = "SECURITYTRAILS_API_KEY"
    homepage = "https://securitytrails.com"
    description = "Current DNS & subdomain counts"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(
            await ctx.client.get(f"https://api.securitytrails.com/v1/domain/{ind.value}",
                                 headers={"APIKEY": ctx.key(self.key_env), "Accept": "application/json"}),
            key_name=self.key_env,
        )
        link = f"https://securitytrails.com/domain/{ind.value}/dns"
        if resp is None:
            return self.not_found(link=link)
        d = resp.json()
        dns = d.get("current_dns") or {}

        def vals(rec: str, key: str) -> list[str]:
            return [v.get(key) for v in (dns.get(rec) or {}).get("values", []) if v.get(key)]

        data = {
            "a": vals("a", "ip"), "aaaa": vals("aaaa", "ipv6"), "mx": vals("mx", "hostname"),
            "ns": vals("ns", "nameserver"), "txt": vals("txt", "value"),
            "subdomain_count": d.get("subdomain_count"), "alexa_rank": d.get("alexa_rank"),
        }
        findings = [f"{d.get('subdomain_count', 0)} known subdomains; A: {', '.join(data['a'][:5]) or 'none'}"]
        return self.ok(findings=findings, data=data, link=link)


class CrtSh(Source):
    name = "crt.sh"
    types = frozenset({DOMAIN})
    timeout = 30
    homepage = "https://crt.sh"
    description = "Certificate Transparency subdomains (keyless)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        resp = check(await ctx.client.get("https://crt.sh/", params={"q": f"%.{ind.value}", "output": "json"},
                                          timeout=30))
        link = f"https://crt.sh/?q=%25.{ind.value}"
        if resp is None:
            return self.not_found(link=link)
        try:
            rows = resp.json()
        except ValueError:
            raise SourceError("crt.sh returned a non-JSON response (service overloaded?)")
        if not rows:
            return self.not_found("No certificates logged", link=link)
        names: set[str] = set()
        issuers: dict[str, int] = {}
        first = last = None
        for r in rows:
            for n in str(r.get("name_value", "")).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(ind.value):
                    names.add(n)
            iss = r.get("issuer_name", "")
            org = next((p.split("=", 1)[1] for p in iss.split(", ") if p.startswith("O=")), iss[:40])
            issuers[org] = issuers.get(org, 0) + 1
            nb = r.get("not_before")
            if nb:
                first = min(first or nb, nb)
                last = max(last or nb, nb)
        subs = sorted(names)
        return self.ok(
            findings=[f"{len(rows)} certificates, {len(subs)} unique names; first {first[:10] if first else '?'}"],
            link=link,
            data={"certificate_count": len(rows), "unique_names": len(subs), "subdomains": subs[:200],
                  "first_cert": first, "latest_cert": last,
                  "issuers": dict(sorted(issuers.items(), key=lambda x: -x[1])[:10])},
        )


def _vcard_name(entity: dict[str, Any]) -> str | None:
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item[0] == "fn":
                return item[3]
    except (IndexError, TypeError):
        pass
    return None


class RDAP(Source):
    name = "RDAP"
    types = frozenset({DOMAIN, IP, CIDR, ASN})
    homepage = "https://rdap.org"
    description = "Registration data (modern WHOIS, keyless)"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        kind = {DOMAIN: "domain", IP: "ip", CIDR: "ip", ASN: "autnum"}[ind.type]
        value = ind.value[2:] if ind.type is ASN else ind.value
        resp = check(await ctx.client.get(f"https://rdap.org/{kind}/{value}",
                                          headers={"Accept": "application/rdap+json"}))
        if resp is None:
            return self.not_found("No RDAP record (domain may be unregistered)")
        d = resp.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events") or []}
        entities = {}
        for e in d.get("entities") or []:
            for role in e.get("roles") or []:
                if (n := _vcard_name(e)):
                    entities.setdefault(role, n)
        data: dict[str, Any] = {"handle": d.get("handle"), "status": d.get("status"), "events": events,
                                "entities": entities}
        findings: list[str] = []
        score = None
        tags: list[str] = []
        if kind == "domain":
            data["nameservers"] = [n.get("ldhName", "").lower() for n in d.get("nameservers") or []]
            reg = events.get("registration")
            age_days = None
            if reg:
                try:
                    age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(reg.replace("Z", "+00:00"))).days
                except ValueError:
                    pass
            data["age_days"] = age_days
            findings.append(f"Registrar {entities.get('registrar', 'unknown')}; registered {(reg or '?')[:10]}"
                            + (f" ({age_days} days ago)" if age_days is not None else "")
                            + f"; expires {(events.get('expiration') or '?')[:10]}")
            if age_days is not None and age_days < 30:
                score, tags = 55, ["newly-registered"]
                findings.insert(0, f"Newly registered domain ({age_days} days old)")
            elif age_days is not None and age_days < 180:
                score, tags = 20, ["young-domain"]
            elif age_days is not None:
                score = 0
        elif kind == "ip":
            data.update(name=d.get("name"), country=d.get("country"), start=d.get("startAddress"),
                        end=d.get("endAddress"), type=d.get("type"))
            findings.append(f"{d.get('name')} {d.get('startAddress')}-{d.get('endAddress')} ({d.get('country') or '?'})"
                            + (f"; org {entities.get('registrant')}" if entities.get("registrant") else ""))
        else:
            data.update(name=d.get("name"), country=d.get("country"))
            findings.append(f"{ind.value} {d.get('name')} ({d.get('country') or '?'})"
                            + (f"; {entities.get('registrant')}" if entities.get("registrant") else ""))
        link = next((l.get("href") for l in d.get("links") or [] if l.get("rel") == "self"), None)
        return self.ok(score=score, confidence=0.5 if score is not None else 0.0, findings=findings, tags=tags,
                       data=data, link=link)


class IPInfo(Source):
    name = "ipinfo"
    types = frozenset({IP})
    key_env = "IPINFO_TOKEN"
    key_required = False
    homepage = "https://ipinfo.io"
    description = "Geolocation, ASN, privacy flags"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        headers = {"Accept": "application/json"}
        if (tok := ctx.key(self.key_env)):
            headers["Authorization"] = f"Bearer {tok}"
        resp = check(await ctx.client.get(f"https://ipinfo.io/{ind.value}/json", headers=headers),
                     key_name=self.key_env)
        if resp is None:
            return self.not_found()
        d = resp.json()
        privacy = d.get("privacy") or {}
        tags = [k for k in ("vpn", "proxy", "tor", "relay", "hosting") if privacy.get(k)]
        loc = ", ".join(filter(None, [d.get("city"), d.get("region"), d.get("country")]))
        findings = [f"{d.get('org') or 'unknown org'} - {loc or 'unknown location'}"]
        if d.get("hostname"):
            findings.append(f"rDNS: {d.get('hostname')}")
        if tags:
            findings.append("Privacy flags: " + ", ".join(tags))
        return self.ok(findings=findings, tags=tags, data=d, link=f"https://ipinfo.io/{ind.value}")


class RIPEstat(Source):
    name = "RIPEstat"
    types = frozenset({IP, CIDR, ASN})
    homepage = "https://stat.ripe.net"
    description = "Routing: announcing ASN, prefixes (keyless)"

    async def _get(self, ctx: Context, call: str, resource: str) -> dict[str, Any]:
        resp = check(await ctx.client.get(f"https://stat.ripe.net/data/{call}/data.json",
                                          params={"resource": resource, "sourceapp": "osintcrawler"}))
        return (resp.json().get("data") if resp is not None else None) or {}

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        link = f"https://stat.ripe.net/{ind.value}"
        if ind.type is ASN:
            ov = await self._get(ctx, "as-overview", ind.value)
            pf = await self._get(ctx, "announced-prefixes", ind.value)
            prefixes = [p.get("prefix") for p in pf.get("prefixes") or []]
            return self.ok(
                findings=[f"{ind.value} {ov.get('holder') or 'unknown holder'}; announced={ov.get('announced')}; "
                          f"{len(prefixes)} prefix(es)"],
                data={"holder": ov.get("holder"), "announced": ov.get("announced"), "block": ov.get("block"),
                      "prefix_count": len(prefixes), "prefixes": prefixes[:100]},
                link=link,
            )
        po = await self._get(ctx, "prefix-overview", ind.value)
        asns = [{"asn": a.get("asn"), "holder": a.get("holder")} for a in po.get("asns") or []]
        if not asns and not po.get("announced"):
            return self.ok(findings=["Not announced in global BGP"], data=po, link=link)
        return self.ok(
            findings=["Announced by " + ", ".join(f"AS{a['asn']} {a['holder']}" for a in asns[:3])
                      + f" via {po.get('resource')}"],
            data={"announced": po.get("announced"), "prefix": po.get("resource"), "asns": asns,
                  "block": po.get("block")},
            link=link,
        )


class DNS(Source):
    name = "DNS (DoH)"
    types = frozenset({DOMAIN, EMAIL, URL})
    homepage = "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/"
    description = "A/AAAA/MX/NS/TXT, SPF & DMARC via Cloudflare DoH"

    async def query(self, ind: Indicator, ctx: Context) -> SourceResult:
        domain = ind.meta.get("domain") or ind.meta.get("host") or ind.value
        if ind.type is URL and _is_ip(domain):
            return self.skipped("URL host is an IP literal")
        recs = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            recs[rtype] = await doh(ctx, domain, rtype)
        dmarc = [t for t in await doh(ctx, f"_dmarc.{domain}", "TXT") if "v=dmarc1" in t.lower()]
        spf = [t for t in recs["TXT"] if t.lower().startswith("v=spf1")]
        findings = [f"A: {', '.join(recs['A'][:5]) or 'none'}; MX: {', '.join(recs['MX'][:3]) or 'none'}"]
        tags = []
        if ind.type in (DOMAIN, EMAIL):
            findings.append(f"SPF: {'yes' if spf else 'missing'}; DMARC: "
                            + (dmarc[0].split(';')[1].strip() if dmarc and ';' in dmarc[0] else 'missing'))
            if not spf:
                tags.append("no-spf")
            if not dmarc:
                tags.append("no-dmarc")
        if not any(recs.values()):
            return self.not_found("Domain does not resolve (NXDOMAIN or no records)")
        return self.ok(findings=findings, tags=tags, data={"records": recs, "spf": spf, "dmarc": dmarc})


def _is_ip(v: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(v.strip("[]"))
        return True
    except ValueError:
        return False


async def doh(ctx: Context, name: str, rtype: str) -> list[str]:
    """Resolve via Cloudflare DNS-over-HTTPS (cached per run)."""

    async def fetch() -> list[str]:
        resp = await ctx.client.get("https://cloudflare-dns.com/dns-query", params={"name": name, "type": rtype},
                                    headers={"Accept": "application/dns-json"})
        if resp.status_code != 200:
            return []
        type_num = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}[rtype]
        out = []
        for a in resp.json().get("Answer") or []:
            if a.get("type") != type_num:
                continue
            v = str(a.get("data", ""))
            if rtype == "TXT":
                v = v.replace('" "', "").strip('"')
            elif rtype == "MX":
                v = v.split()[-1].rstrip(".")
            else:
                v = v.rstrip(".")
            out.append(v)
        return out

    return await ctx.cached(f"doh:{rtype}:{name}", fetch)
