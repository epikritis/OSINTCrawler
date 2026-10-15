"""Report renderers: JSON, standalone HTML, and Rich console."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from ..models import Report
from ..scoring import verdict_label

_env = Environment(
    loader=PackageLoader("osintcrawler", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.globals["verdict_label"] = verdict_label
_env.filters["pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False, default=str)


def to_json(report: Report, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False, default=str)


def to_html(report: Report, *, web: bool = False, nonce: str | None = None) -> str:
    return _env.get_template("report.html.j2").render(
        report=report, report_json=report.to_dict(), web=web, nonce=nonce,
    )


def render_template(name: str, **ctx: object) -> str:
    return _env.get_template(name).render(**ctx)


def write(path: str | Path, content: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p
