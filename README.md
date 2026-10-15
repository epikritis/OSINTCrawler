# OSINTCrawler

OSINTCrawler queries **30+ OSINT sources in parallel** for security indicators and returns a **summarised, explainable verdict** together with the full per-source detail. It is available as a command-line tool and as a small token-protected web app. Both run locally.

```
$ osintcrawler lookup 185.220.101.1 CVE-2023-4966 44d88612fea8a8f36de82e1278abb02f --html report.html
```

| Indicator | Examples | Sources |
|---|---|---|
| IP (v4/v6) | `8.8.8.8`, `8.8.8[.]8` | VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, URLhaus, ThreatFox, urlscan.io, Shodan InternetDB, Shodan, ipinfo, RDAP, RIPEstat, Enrichment |
| Domain | `example.com`, `evil[.]org` | VirusTotal, OTX, URLhaus, ThreatFox, Google Safe Browsing, urlscan.io, RDAP (age), DNS/SPF/DMARC, crt.sh, SecurityTrails, Hunter.io, Chainabuse, Enrichment |
| URL | `hxxps://evil[.]com/login` | VirusTotal, OTX, URLhaus, ThreatFox, Google Safe Browsing, urlscan.io, DNS, Chainabuse, Enrichment |
| File hash | MD5 / SHA1 / SHA256 | VirusTotal, MalwareBazaar, ThreatFox, URLhaus, OTX, urlscan.io, CIRCL hashlookup (known-good) |
| Email | `john@example.com` | HaveIBeenPwned, Hunter.io, EmailRep, Gravatar, DNS (MX/SPF/DMARC) |
| Phone | `+254 712 345678` | Offline parsing (country, line type, carrier, time zone), Numverify |
| Address | `address: 10 Downing St, London` | OpenStreetMap Nominatim (+ map / Street View links) |
| CVE | `CVE-2021-44228` | NVD (CVSS, CWE), CISA KEV, FIRST EPSS, OTX |
| ASN / CIDR | `AS15169`, `1.1.1.0/24` | RIPEstat, RDAP |
| Crypto wallet | BTC / ETH addresses | Blockstream, Etherscan, Chainabuse |
| Username | `@johndoe`, `user:johndoe` | 30 social, dev and gaming platforms (Sherlock-style), with manual-check links for platforms that block automated lookups |

Input is **refanged automatically** (`hxxp`, `[.]`, `[at]`). The type is auto-detected, and you can force it with a prefix (`phone:`, `user:`, `address:`, `asn:` …) or with `--type`.

**Enrichment flags** (IP/domain/URL): Tor exit node, cloud/CDN hosting (AWS, Google Cloud, Cloudflare, Oracle, Fastly, DigitalOcean), VPN/proxy/hosting (from ipinfo, AbuseIPDB and GreyNoise), newly registered domains, suspicious TLDs, punycode/IDN homographs, DGA-like labels, raw-IP URLs, `user@host` obfuscation, URL shorteners, phishing keywords and missing SPF/DMARC.

---

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/epikritis/OSINTCrawler.git
cd OSINTCrawler
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[web]"

cp .env.example .env        # then add whichever API keys you have (see API keys below)
osintcrawler sources        # shows which sources are ready / need keys
osintcrawler lookup 8.8.8.8 example.com CVE-2021-44228
```

The tool works with **no API keys**. The keyless sources (OTX, GreyNoise community, Shodan InternetDB, RDAP, RIPEstat, crt.sh, DNS, CISA KEV, EPSS, NVD, CIRCL, Blockstream, Nominatim, Gravatar, username checks and enrichment) still run. Each key you add switches on more sources.

### CLI usage

```bash
osintcrawler lookup <indicator> [<indicator> ...] [options]

  -f, --file PATH        read indicators from a file, one per line ('-' = stdin, '#' = comment)
  -t, --type TYPE        force type: ip|cidr|asn|domain|url|hash|email|phone|address|cve|btc|eth|username
  --json PATH            write the full JSON report (all normalised source data)
  --html PATH            write a standalone HTML report (works offline, light/dark, JSON download)
  -d, --detail           print per-source results in the terminal
  -s, --sources LIST     only use these sources, e.g. "VirusTotal,AbuseIPDB"
  -x, --exclude LIST     skip these sources
  --timeout SECONDS      per-source timeout (default 15)
  --ai-summary           add an LLM analyst note (see below)
  -q, --quiet            no terminal table

osintcrawler sources     # list all sources and their key status
```

Examples:

```bash
osintcrawler lookup -f iocs.txt --html reports/case-1234.html --json reports/case-1234.json -q
cat iocs.txt | osintcrawler lookup -f - -d
osintcrawler lookup 254712345678 "+1 202 555 0143"   # phone: country code required, '+' optional
osintcrawler lookup @someuser -s "Username search"
```

---

## Web UI

The web UI is a small FastAPI app. Paste indicators, sign in, and get the HTML report with a JSON download. A JSON API is also available.

It refuses to serve lookups until you set `ACCESS_TOKEN` (at least 16 characters). Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Add it to `.env` (or export it in your shell), then start the server:

```bash
uvicorn api.index:app --port 8000
# open http://localhost:8000 and sign in with the token
```

Security features: browser sessions use an HttpOnly, SameSite=Strict HMAC cookie with a 12-hour lifetime. The JSON API uses `Authorization: Bearer <ACCESS_TOKEN>`. Sign-in is limited to 5 attempts per minute per IP address, and lookups to 20 per minute (`RATE_LIMIT_PER_MINUTE`). The app also includes an Origin check on POST requests, a nonce-based Content Security Policy, `X-Frame-Options: DENY`, `no-store` caching, `noindex`, and a cap of 20 indicators per request.

### JSON API

```bash
curl -s http://localhost:8000/api/lookup \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"indicators": ["8.8.8.8", "CVE-2021-44228"], "type": null, "ai_summary": false}'
```

The response has the same schema as `--json` output: `indicators[].verdict`, `risk_score`, `summary`, `tags` and `results[]` (per source `status`, `score`, `findings`, `data`, `link`, `error`).

---

## API keys

All keys are **optional**. The tool reads them from a `.env` file in the project folder. The repository includes [`.env.example`](.env.example), a template that lists every variable with a blank value. Copy it to `.env` and add the keys you have:

```bash
cp .env.example .env
```

Keys are never printed, and any key that appears in an upstream error message is replaced with `***`.

> **Disclaimer:** Storing API keys in a local `.env` file is fine for personal use on your own machine, but it is **not best practice for production environments**. In production, use a secret manager or key vault instead (for example AWS Secrets Manager, Azure Key Vault, Google Secret Manager, HashiCorp Vault, or your platform's built-in secret store), and inject the values as environment variables at runtime.

| Variable | Service | Free tier | Get it |
|---|---|---|---|
| `VT_API_KEY` | VirusTotal | 4 req/min, 500/day | https://www.virustotal.com/gui/my-apikey |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | 1,000/day | https://www.abuseipdb.com/account/api |
| `OTX_API_KEY` | AlienVault OTX | free (keyless works, lower limits) | https://otx.alienvault.com/settings |
| `GREYNOISE_API_KEY` | GreyNoise Community | free (keyless works, low limits) | https://viz.greynoise.io/account/api-key |
| `ABUSECH_AUTH_KEY` | URLhaus, MalwareBazaar, ThreatFox | free, **required** | https://auth.abuse.ch/ |
| `URLSCAN_API_KEY` | urlscan.io (search only) | free | https://urlscan.io/user/profile/ |
| `IPINFO_TOKEN` | ipinfo | free (privacy flags need paid) | https://ipinfo.io/account/token |
| `GOOGLE_SAFEBROWSING_API_KEY` | Google Safe Browsing | free, non-commercial | Google Cloud Console → enable *Safe Browsing API* |
| `SHODAN_API_KEY` | Shodan host API | paid membership | https://account.shodan.io/ |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | small monthly quota | https://securitytrails.com/app/account/credentials |
| `HIBP_API_KEY` | HaveIBeenPwned | **paid** | https://haveibeenpwned.com/API/Key |
| `HUNTER_API_KEY` | Hunter.io | ~25 searches/month | https://hunter.io/api-keys |
| `EMAILREP_API_KEY` | EmailRep | free on request | https://emailrep.io/key |
| `NUMVERIFY_API_KEY` | Numverify | ~100/month (HTTPS may need a paid plan) | https://numverify.com/product |
| `NVD_API_KEY` | NVD | free, optional (higher rate limit) | https://nvd.nist.gov/developers/request-an-api-key |
| `ETHERSCAN_API_KEY` | Etherscan | free | https://etherscan.io/myapikey |
| `CHAINABUSE_API_KEY` | Chainabuse | free on request | https://www.chainabuse.com/ |
| `ANTHROPIC_API_KEY` | Claude (AI summary only) | paid per use | https://console.anthropic.com/ |
| `ACCESS_TOKEN` | Web UI sign-in and API (not a third-party key) | generate locally | see Web UI |

**Recommended starter set (all free):** VirusTotal, AbuseIPDB, abuse.ch, OTX, GreyNoise, urlscan.io and ipinfo.

Phone numbers must include the country code (`+254712345678`, `254712345678` or `00254712345678`); anything else is rejected with an error. Optionally set `DEFAULT_PHONE_REGION` (e.g. `KE`) to also accept national-format numbers like `0712 345 678`. Other settings: `HTTP_TIMEOUT`, `MAX_CONCURRENCY`, `RATE_LIMIT_PER_MINUTE`, `ANTHROPIC_MODEL` (default `claude-opus-5-5`).

---

## How the verdict is calculated

Every source returns a 0-100 `score` and a 0-1 `confidence`. Purely informational sources (geo, RDAP, DNS, ...) return no score. Scores are combined with a weighted **noisy-OR**:

```
risk = 1 − Π (1 − score/100 × confidence × weight[source])
```

- One strong signal (e.g. a MalwareBazaar hit) is enough to flag an indicator.
- Several independent weak signals reinforce each other.
- Sources that find nothing **don't dilute** a real hit, which a plain average would.
- `known-good` evidence (GreyNoise RIOT, OTX allow-lists, NSRL via CIRCL, AbuseIPDB whitelist) can downgrade *suspicious* to *low risk*, but never overrides a *malicious* result.

| Risk | Verdict (CVE label) |
|---|---|
| ≥ 70 | **MALICIOUS** (HIGH PRIORITY) |
| 35-69 | **SUSPICIOUS** (MEDIUM PRIORITY) |
| < 35 | **LOW RISK** (LOW PRIORITY) |
| no scoring source | **INFO** (phone, address, username, ASN, wallet) / **UNKNOWN** |

Weights and thresholds are in one place, [`osintcrawler/scoring.py`](osintcrawler/scoring.py), so you can tune them to your own trust in each feed. Scoring is deterministic and reproducible.

### Optional AI analyst summary

`--ai-summary` (or the checkbox in the web UI) sends the **condensed results** to Claude, which writes a short ticket-ready analyst note. It is **off by default** and only available when `ANTHROPIC_API_KEY` is set. Don't use it for material your handling rules keep in-house (e.g. TLP:AMBER/RED). Treat the note as a draft: it can be wrong.

---

## OPSEC notes

- Looking up an indicator **discloses it to each third-party service** you query. Use `-s`/`-x` to control which services see it.
- urlscan.io is **search-only**: nothing is ever submitted for scanning.
- Private/reserved IPs are never sent to external services.
- Phone parsing is local. All other lookups go out over HTTPS (Numverify refuses plain HTTP so the key can't leak).
- DNS lookups use Cloudflare DNS-over-HTTPS, not your local resolver.

---

## Adding a source

1. Subclass `Source` (see [`osintcrawler/sources/base.py`](osintcrawler/sources/base.py)). Set `name`, `types`, `key_env` and implement `async query(ind, ctx)`, returning `self.ok(score=…, confidence=…, findings=[…], data={…})` / `self.not_found()`.
2. Use `check(resp, key_name=...)` for consistent HTTP error handling.
3. Register an instance in [`osintcrawler/sources/__init__.py`](osintcrawler/sources/__init__.py) and optionally add a weight in `scoring.py`.
4. Add a mocked test in `tests/` (see `tests/test_sources.py`, which uses `respx`).

Username sites are data-driven: edit [`osintcrawler/data/username_sites.json`](osintcrawler/data/username_sites.json).

## Development

```bash
pip install -e ".[dev,web]"
pytest -q
```

## Disclaimer

For defensive security, threat intelligence and authorised investigations only. Respect each provider's terms of service and rate limits, and the privacy laws that apply to you. Results are heuristic: corroborate them before blocking, attributing or taking legal action.

## License

[MIT](LICENSE)
