import asyncio

import httpx
import respx

from osintcrawler.config import Settings
from osintcrawler.engine import investigate
from osintcrawler.models import Status, Verdict

SECRET = "vt-secret-key-123456"


def _settings(**keys):
    return Settings(keys=keys, http_timeout=5)


def _run(values, settings, only):
    return asyncio.run(investigate(values, settings, only=only))


@respx.mock
def test_virustotal_malicious_hash():
    h = "a" * 64
    route = respx.get(f"https://www.virustotal.com/api/v3/files/{h}").mock(
        return_value=httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 40, "suspicious": 2, "undetected": 30, "harmless": 0},
            "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"},
            "type_description": "Win32 EXE", "meaningful_name": "invoice.exe",
        }}})
    )
    rep = _run([h], _settings(VT_API_KEY=SECRET), ["VirusTotal"])
    assert route.calls[0].request.headers["x-apikey"] == SECRET
    ind = rep.indicators[0]
    vt = ind.results[0]
    assert vt.status is Status.OK and vt.score == 100
    assert "40/72 engines malicious" in vt.findings[0]
    assert ind.verdict is Verdict.MALICIOUS


@respx.mock
def test_not_found_maps_cleanly():
    respx.get("https://www.virustotal.com/api/v3/domains/example.org").mock(return_value=httpx.Response(404))
    rep = _run(["example.org"], _settings(VT_API_KEY=SECRET), ["VirusTotal"])
    assert rep.indicators[0].results[0].status is Status.NOT_FOUND


def test_missing_key_is_skipped_without_network():
    rep = _run(["8.8.8.8"], _settings(), ["VirusTotal", "AbuseIPDB"])
    assert {r.status for r in rep.indicators[0].results} == {Status.SKIPPED}
    assert "VT_API_KEY" in rep.indicators[0].results[-1].error or "ABUSEIPDB_API_KEY" in rep.indicators[0].results[0].error


@respx.mock
def test_auth_error_and_secret_scrubbing():
    respx.get(url__startswith="https://api.shodan.io/shodan/host/1.2.3.4").mock(
        side_effect=httpx.ConnectError(f"boom https://api.shodan.io/?key={SECRET}")
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(return_value=httpx.Response(401))
    rep = _run(["1.2.3.4"], _settings(SHODAN_API_KEY=SECRET, ABUSEIPDB_API_KEY="abuse-key-0000"),
               ["Shodan", "AbuseIPDB"])
    errors = {r.source: r.error for r in rep.indicators[0].results}
    assert SECRET not in errors["Shodan"] and "***" in errors["Shodan"]
    assert "ABUSEIPDB_API_KEY" in errors["AbuseIPDB"]


@respx.mock
def test_urlhaus_host_listing():
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(return_value=httpx.Response(200, json={
        "query_status": "ok", "url_count": 3, "urlhaus_reference": "https://urlhaus.abuse.ch/host/bad.example/",
        "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
        "urls": [{"url": "http://bad.example/a.exe", "url_status": "online", "threat": "malware_download"}],
    }))
    rep = _run(["bad.example"], _settings(ABUSECH_AUTH_KEY="k" * 20), ["URLhaus"])
    res = rep.indicators[0].results[0]
    assert res.score == 85 and "malware-host" in res.tags


@respx.mock
def test_private_ip_never_sent():
    route = respx.get(url__regex=r".*").mock(return_value=httpx.Response(500))
    rep = _run(["192.168.0.1"], _settings(), None)
    assert not route.called
    assert any("private" in w for w in rep.warnings)


def test_timeout_is_reported(monkeypatch):
    from osintcrawler.sources.infra import ShodanInternetDB

    async def slow(self, ind, ctx):
        await asyncio.sleep(5)

    monkeypatch.setattr(ShodanInternetDB, "query", slow)
    rep = asyncio.run(investigate(["8.8.8.8"], _settings(), only=["Shodan InternetDB"], timeout=0.1))
    res = rep.indicators[0].results[0]
    assert res.status is Status.ERROR and "timed out" in res.error
