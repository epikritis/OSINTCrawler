"""Optional LLM analyst summary (off by default).

Only runs when explicitly requested AND ``ANTHROPIC_API_KEY`` is set. The
indicators and their enrichment results are sent to Anthropic, so do not use
it for material your handling rules (e.g. TLP:AMBER/RED) keep in-house.
"""

from __future__ import annotations

import json

from .config import Settings
from .models import Report, Status

SYSTEM = (
    "You are a senior SOC / threat-intelligence analyst. You receive JSON enrichment results for one or more "
    "indicators gathered from public OSINT sources, plus a deterministic risk score per indicator. Write a "
    "concise analyst note for a ticket: for each indicator give a one-line assessment, the evidence that "
    "supports it (cite source names), notable relationships between indicators, any conflicting or weak "
    "evidence, and recommended next steps (e.g. block, monitor, hunt, no action). Do not invent facts that "
    "are not in the data; say when evidence is thin. Plain text, no markdown tables, under 350 words."
)


def _compact(report: Report) -> dict:
    """Trim raw payloads so the prompt stays small and focused."""
    out = []
    for rep in report.indicators:
        out.append({
            "indicator": rep.indicator.value,
            "type": rep.indicator.type.value,
            "verdict": rep.verdict.value,
            "risk_score": rep.risk_score,
            "tags": rep.tags,
            "sources": [
                {"source": r.source, "status": r.status.value, "score": r.score, "findings": r.findings[:4]}
                for r in rep.results if r.status in (Status.OK, Status.NOT_FOUND)
            ],
        })
    return {"indicators": out}


def summarise(report: Report, settings: Settings) -> str:
    key = settings.key("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    try:
        import anthropic
    except ImportError as e:  # optional dependency
        raise RuntimeError("install the anthropic package: pip install anthropic") from e

    client = anthropic.Anthropic(api_key=key, timeout=120)
    try:
        response = client.beta.messages.create(
            model=settings.anthropic_model,
            max_tokens=4000,
            system=SYSTEM,
            output_config={"effort": "medium"},
            # Threat-intel text can trip safety classifiers; let the API retry on its recommended fallback model.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[{"role": "user", "content": json.dumps(_compact(report), ensure_ascii=False)}],
        )
    except anthropic.AuthenticationError:
        raise RuntimeError("Anthropic authentication failed - check ANTHROPIC_API_KEY")
    except anthropic.RateLimitError:
        raise RuntimeError("Anthropic rate limit reached - try again later")
    except anthropic.APIStatusError as e:
        raise RuntimeError(f"Anthropic API error {e.status_code}")
    except anthropic.APIConnectionError:
        raise RuntimeError("could not reach the Anthropic API")

    if response.stop_reason == "refusal":
        return "AI summary unavailable: the model declined this request."
    text = "".join(b.text for b in response.content if b.type == "text").strip()
    return text or "AI summary unavailable: empty response."
