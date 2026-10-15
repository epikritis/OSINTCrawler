"""Deterministic, explainable risk scoring.

Each source reports a 0-100 ``score`` and a 0-1 ``confidence``. Those are
combined with a per-source ``WEIGHTS`` multiplier using a *noisy-OR*:

    risk = 1 - prod(1 - score/100 * confidence * weight)

so one strong signal is enough to flag an indicator, several weak signals
reinforce each other, and sources with nothing to say never dilute the result
(unlike a plain average). Tune the weights below to match your own trust in
each feed.
"""

from __future__ import annotations

from .models import IndicatorReport, IType, Status, Verdict

WEIGHTS: dict[str, float] = {
    "VirusTotal": 1.0,
    "AbuseIPDB": 0.9,
    "AlienVault OTX": 0.6,
    "GreyNoise": 0.8,
    "URLhaus": 1.0,
    "MalwareBazaar": 1.0,
    "ThreatFox": 1.0,
    "Google Safe Browsing": 1.0,
    "urlscan.io": 0.7,
    "EmailRep": 0.7,
    "Hunter.io": 0.5,
    "CISA KEV": 1.0,
    "NVD": 0.9,
    "EPSS": 0.8,
    "Chainabuse": 0.9,
    "Shodan InternetDB": 0.6,
    "RDAP": 0.6,
    "Enrichment": 0.8,
}

MALICIOUS_AT = 70
SUSPICIOUS_AT = 35

INFO_TYPES = {IType.PHONE, IType.ADDRESS, IType.USERNAME, IType.ASN, IType.CIDR, IType.BTC, IType.ETH}

_LABELS = {
    Verdict.MALICIOUS: "MALICIOUS",
    Verdict.SUSPICIOUS: "SUSPICIOUS",
    Verdict.LOW_RISK: "LOW RISK",
    Verdict.INFORMATIONAL: "INFO",
    Verdict.UNKNOWN: "UNKNOWN",
}
_CVE_LABELS = {
    Verdict.MALICIOUS: "HIGH PRIORITY",
    Verdict.SUSPICIOUS: "MEDIUM PRIORITY",
    Verdict.LOW_RISK: "LOW PRIORITY",
}


def verdict_label(itype: IType, verdict: Verdict) -> str:
    if itype is IType.CVE and verdict in _CVE_LABELS:
        return _CVE_LABELS[verdict]
    return _LABELS[verdict]


def score_report(rep: IndicatorReport) -> IndicatorReport:
    ok = [r for r in rep.results if r.status is Status.OK]
    scored = [r for r in ok if r.score is not None]

    remaining = 1.0
    for r in scored:
        p = max(0.0, min(1.0, (r.score or 0) / 100 * r.confidence * WEIGHTS.get(r.source, 1.0)))
        remaining *= 1 - p
    known_good = any("known-good" in r.tags for r in ok)

    if scored:
        risk = round((1 - remaining) * 100)
        if risk >= MALICIOUS_AT:
            verdict = Verdict.MALICIOUS
        elif risk >= SUSPICIOUS_AT and not known_good:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.LOW_RISK
        rep.risk_score = risk
    else:
        rep.risk_score = None
        verdict = Verdict.INFORMATIONAL if rep.indicator.type in INFO_TYPES or ok else Verdict.UNKNOWN
    rep.verdict = verdict

    # Summary: strongest signals first, then the headline of informational sources.
    summary: list[str] = []
    for r in sorted(scored, key=lambda r: -(r.score or 0)):
        if (r.score or 0) >= 20 and r.findings:
            summary.append(f"{r.source}: {r.findings[0]}")
    if known_good:
        summary.append("At least one source lists this as a known-good / benign service.")
    for r in ok:
        if (r.score is None or (r.score or 0) < 20) and r.findings and len(summary) < 10:
            summary.append(f"{r.source}: {r.findings[0]}")

    checked = [r for r in rep.results if r.status in (Status.OK, Status.NOT_FOUND)]
    flagged = [r for r in scored if (r.score or 0) >= SUSPICIOUS_AT]
    summary.append(
        f"Coverage: {len(checked)} source(s) answered, {len(flagged)} flagged it, "
        f"{sum(r.status is Status.SKIPPED for r in rep.results)} skipped (no key), "
        f"{sum(r.status is Status.ERROR for r in rep.results)} errored."
    )
    rep.summary = summary

    tags: list[str] = []
    for r in ok:
        for t in r.tags:
            if t not in tags:
                tags.append(t)
    rep.tags = tags
    return rep
