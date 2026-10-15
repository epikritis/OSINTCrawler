import pytest
from fastapi.testclient import TestClient

from osintcrawler.models import Indicator, IndicatorReport, IType, Report, Verdict
from osintcrawler.web import app as webapp

TOKEN = "test-token-0123456789abcdef"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN", TOKEN)
    webapp._hits.clear()

    async def fake_investigate(values, settings, **kw):
        rep = Report(generated_at="now", tool_version="test")
        for v in values:
            rep.indicators.append(IndicatorReport(indicator=Indicator(v, IType.DOMAIN), verdict=Verdict.LOW_RISK,
                                                  risk_score=0, summary=["ok"]))
        return rep

    monkeypatch.setattr(webapp, "investigate", fake_investigate)
    return TestClient(webapp.app, base_url="https://testserver")


def test_fails_closed_without_token(monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN", "")
    c = TestClient(webapp.app)
    assert c.get("/").status_code == 503
    assert c.post("/api/lookup", json={"indicators": ["example.com"]}).status_code == 503


def test_api_requires_bearer(client):
    assert client.post("/api/lookup", json={"indicators": ["example.com"]}).status_code == 401
    bad = client.post("/api/lookup", json={"indicators": ["example.com"]}, headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401
    ok = client.post("/api/lookup", json={"indicators": ["example.com"]}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert ok.status_code == 200 and ok.json()["indicators"][0]["indicator"]["value"] == "example.com"


def test_api_caps_indicator_count(client):
    resp = client.post("/api/lookup", json={"indicators": ["a.com"] * 50}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 422


def test_login_flow_and_lookup(client):
    assert "Access token" in client.get("/").text
    assert client.post("/lookup", data={"indicators": "example.com"}, follow_redirects=False).status_code == 303
    assert client.post("/login", data={"token": "wrong"}).status_code == 401
    resp = client.post("/login", data={"token": TOKEN}, follow_redirects=False)
    assert resp.status_code == 303
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie
    assert TOKEN.lower() not in cookie
    page = client.post("/lookup", data={"indicators": "example.com"})
    assert page.status_code == 200 and "OSINTCrawler report" in page.text
    assert "nonce-" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"


def test_cross_origin_post_blocked(client):
    client.post("/login", data={"token": TOKEN})
    resp = client.post("/lookup", data={"indicators": "example.com"}, headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403


def test_login_rate_limited(client):
    codes = [client.post("/login", data={"token": "x"}).status_code for _ in range(7)]
    assert codes[-1] == 429


def test_report_escapes_html(client):
    client.post("/login", data={"token": TOKEN})
    page = client.post("/lookup", data={"indicators": "<script>alert(1)</script>.com"})
    assert "<script>alert(1)</script>" not in page.text
