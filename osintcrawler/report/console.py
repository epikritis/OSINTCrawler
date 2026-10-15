"""Rich terminal output."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..models import Report, Status, Verdict
from ..scoring import verdict_label

VERDICT_STYLE = {
    Verdict.MALICIOUS: "bold white on red",
    Verdict.SUSPICIOUS: "bold black on yellow",
    Verdict.LOW_RISK: "bold white on green",
    Verdict.INFORMATIONAL: "bold white on blue",
    Verdict.UNKNOWN: "bold white on grey37",
}
STATUS_STYLE = {Status.OK: "green", Status.NOT_FOUND: "cyan", Status.ERROR: "red", Status.SKIPPED: "grey50"}


def render(report: Report, console: Console, *, detail: bool = False, show_skipped: bool = False) -> None:
    table = Table(title="OSINTCrawler summary", show_lines=True, expand=True)
    table.add_column("Indicator", overflow="fold", ratio=3)
    table.add_column("Type", ratio=1)
    table.add_column("Verdict", ratio=2)
    table.add_column("Risk", justify="right", ratio=1)
    table.add_column("Key findings", overflow="fold", ratio=7)
    for rep in report.indicators:
        label = verdict_label(rep.indicator.type, rep.verdict)
        table.add_row(
            escape(rep.indicator.value),
            rep.indicator.type.value,
            f"[{VERDICT_STYLE[rep.verdict]}] {label} [/]",
            "-" if rep.risk_score is None else str(rep.risk_score),
            escape("\n".join(f"- {s}" for s in rep.summary[:5]))
            + (f"\n[dim]tags: {escape(', '.join(rep.tags[:10]))}[/]" if rep.tags else ""),
        )
    console.print(table)

    if detail:
        for rep in report.indicators:
            t = Table(show_header=True, expand=True, box=None, pad_edge=False)
            t.add_column("Source", ratio=2)
            t.add_column("Status", ratio=1)
            t.add_column("Score", justify="right", ratio=1)
            t.add_column("Findings", overflow="fold", ratio=8)
            for r in rep.results:
                if r.status is Status.SKIPPED and not show_skipped:
                    continue
                text = escape("\n".join(r.findings) if r.findings else (r.error or ""))
                if r.link:
                    text += f"\n[dim]{escape(r.link)}[/]"
                t.add_row(escape(r.source), f"[{STATUS_STYLE[r.status]}]{r.status.value}[/]",
                          "-" if r.score is None else str(r.score), text)
            label = verdict_label(rep.indicator.type, rep.verdict)
            console.print(Panel(t, title=f"{escape(rep.indicator.value)} - {label}", title_align="left"))

    skipped = sorted({r.source for rep in report.indicators for r in rep.results if r.status is Status.SKIPPED})
    if skipped and not show_skipped:
        console.print(f"[dim]Skipped (no API key): {', '.join(skipped)}. Run `osintcrawler sources` for setup.[/]")
    for w in report.warnings:
        console.print(f"[yellow]warning:[/] {escape(w)}")
    if report.ai_summary:
        console.print(Panel(escape(report.ai_summary), title="AI analyst summary (verify before acting)",
                            border_style="magenta"))
