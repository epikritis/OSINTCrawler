"""Core data models shared by the engine, sources and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class IType(str, Enum):
    """Supported indicator types."""

    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    CVE = "cve"
    BTC = "btc"
    ETH = "eth"
    USERNAME = "username"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class Status(str, Enum):
    OK = "ok"                # source returned data
    NOT_FOUND = "not_found"  # source has no record of the indicator
    ERROR = "error"          # request failed / timed out / bad response
    SKIPPED = "skipped"      # not configured (missing key) or not applicable

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LOW_RISK = "low_risk"        # sources checked, nothing notable
    INFORMATIONAL = "informational"  # type isn't scored (phone, address, username...)
    UNKNOWN = "unknown"          # no source could score it

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


@dataclass
class Indicator:
    value: str            # normalised value used for lookups
    type: IType
    original: str = ""    # exactly what the user supplied
    meta: dict[str, Any] = field(default_factory=dict)  # e.g. {"hash_type": "sha256"}

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "type": self.type.value, "original": self.original, "meta": self.meta}


@dataclass
class SourceResult:
    source: str
    status: Status
    # 0-100 maliciousness / risk contribution. None = informational only.
    score: int | None = None
    # 0-1 how much the scorer should trust this source's score.
    confidence: float = 0.0
    findings: list[str] = field(default_factory=list)   # human-readable key points
    tags: list[str] = field(default_factory=list)       # short flags, e.g. "tor-exit"
    data: dict[str, Any] = field(default_factory=dict)  # normalised detail
    link: str | None = None                             # where an analyst can view it
    error: str | None = None
    elapsed_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class IndicatorReport:
    indicator: Indicator
    results: list[SourceResult] = field(default_factory=list)
    risk_score: int | None = None
    verdict: Verdict = Verdict.UNKNOWN
    summary: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator.to_dict(),
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "tags": self.tags,
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class Report:
    generated_at: str
    tool_version: str
    indicators: list[IndicatorReport] = field(default_factory=list)
    ai_summary: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "ai_summary": self.ai_summary,
            "warnings": self.warnings,
            "indicators": [i.to_dict() for i in self.indicators],
        }
