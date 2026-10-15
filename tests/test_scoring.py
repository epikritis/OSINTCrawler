from osintcrawler.models import Indicator, IndicatorReport, IType, SourceResult, Status, Verdict
from osintcrawler.scoring import score_report, verdict_label


def _rep(itype, *results):
    return score_report(IndicatorReport(indicator=Indicator("x", itype), results=list(results)))


def r(source, score, conf=0.9, status=Status.OK, tags=None, findings=None):
    return SourceResult(source=source, status=status, score=score, confidence=conf, tags=tags or [],
                        findings=findings or [f"{source} finding"])


def test_strong_single_signal_is_malicious():
    rep = _rep(IType.HASH, r("MalwareBazaar", 100, 0.95), r("CIRCL hashlookup", None, 0))
    assert rep.verdict is Verdict.MALICIOUS
    assert rep.risk_score >= 90


def test_weak_signals_reinforce():
    single = _rep(IType.IP, r("AbuseIPDB", 50, 0.8))
    double = _rep(IType.IP, r("AbuseIPDB", 50, 0.8), r("GreyNoise", 50, 0.7))
    assert double.risk_score > single.risk_score
    assert double.verdict is Verdict.SUSPICIOUS


def test_zero_scores_do_not_dilute():
    a = _rep(IType.IP, r("VirusTotal", 100, 0.9))
    b = _rep(IType.IP, r("VirusTotal", 100, 0.9), r("AlienVault OTX", 0, 0.6), r("GreyNoise", 0, 0.7))
    assert a.risk_score == b.risk_score


def test_known_good_downgrades_suspicious_only():
    rep = _rep(IType.IP, r("AbuseIPDB", 50, 0.8), r("GreyNoise", 0, 0.7, tags=["known-good"]))
    assert rep.verdict is Verdict.LOW_RISK
    rep = _rep(IType.IP, r("VirusTotal", 100, 0.9), r("GreyNoise", 0, 0.7, tags=["known-good"]))
    assert rep.verdict is Verdict.MALICIOUS


def test_informational_types():
    rep = _rep(IType.PHONE, r("Phone (offline)", None, 0))
    assert rep.verdict is Verdict.INFORMATIONAL and rep.risk_score is None


def test_unknown_when_nothing_answered():
    rep = _rep(IType.DOMAIN, SourceResult("VirusTotal", Status.SKIPPED))
    assert rep.verdict is Verdict.UNKNOWN


def test_cve_labels():
    assert verdict_label(IType.CVE, Verdict.MALICIOUS) == "HIGH PRIORITY"
    assert verdict_label(IType.IP, Verdict.MALICIOUS) == "MALICIOUS"


def test_summary_and_tags():
    rep = _rep(IType.IP, r("AbuseIPDB", 90, 0.8, tags=["tor-exit"], findings=["Abuse 90%"]))
    assert rep.summary[0] == "AbuseIPDB: Abuse 90%"
    assert rep.summary[-1].startswith("Coverage:")
    assert rep.tags == ["tor-exit"]
