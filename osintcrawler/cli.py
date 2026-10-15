"""Command-line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, report as reporting
from .config import Settings
from .engine import investigate
from .models import IType
from .report.console import render
from .sources import all_sources

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Query many OSINT sources for indicators and get a summarised verdict.")
console = Console(stderr=False)
err = Console(stderr=True)


def _split(values: Optional[str]) -> list[str]:
    return [v.strip() for v in (values or "").split(",") if v.strip()]


@app.command()
def lookup(
    indicators: list[str] = typer.Argument(None, help="Indicators (IP, domain, URL, hash, email, phone, CVE, ...)."),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read indicators from a file (one per line, '-' for stdin)."),
    itype: Optional[IType] = typer.Option(None, "--type", "-t", case_sensitive=False, help="Force the indicator type."),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write full JSON report to this path."),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Write standalone HTML report to this path."),
    only: Optional[str] = typer.Option(None, "--sources", "-s", help="Comma-separated sources to use (default: all)."),
    exclude: Optional[str] = typer.Option(None, "--exclude", "-x", help="Comma-separated sources to skip."),
    timeout: Optional[float] = typer.Option(None, help="Per-source timeout in seconds."),
    detail: bool = typer.Option(False, "--detail", "-d", help="Show per-source results in the terminal."),
    show_skipped: bool = typer.Option(False, help="List sources skipped for missing keys."),
    ai_summary: bool = typer.Option(False, "--ai-summary", help="Add an LLM analyst note (sends results to Anthropic)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="No terminal table (useful with --json/--html)."),
) -> None:
    """Enrich one or more indicators."""
    values = list(indicators or [])
    if file:
        text = sys.stdin.read() if str(file) == "-" else file.read_text(encoding="utf-8")
        values += text.splitlines()
    if not values:
        err.print("[red]No indicators given.[/] Pass them as arguments or with --file.")
        raise typer.Exit(2)

    settings = Settings.from_env()
    with console.status("Querying sources...", spinner="dots") if not quiet else _null():
        rep = asyncio.run(investigate(values, settings, forced=itype, only=_split(only),
                                      exclude=_split(exclude), timeout=timeout))
    if not rep.indicators:
        for w in rep.warnings:
            err.print(f"[yellow]warning:[/] {w}")
        raise typer.Exit(2)

    if ai_summary:
        from .ai_summary import summarise
        try:
            with console.status("Writing AI summary...", spinner="dots") if not quiet else _null():
                rep.ai_summary = summarise(rep, settings)
        except RuntimeError as e:
            rep.warnings.append(f"AI summary skipped: {e}")

    if not quiet:
        render(rep, console, detail=detail, show_skipped=show_skipped)
    if json_out:
        p = reporting.write(json_out, reporting.to_json(rep))
        err.print(f"[green]JSON report:[/] {p}")
    if html_out:
        p = reporting.write(html_out, reporting.to_html(rep))
        err.print(f"[green]HTML report:[/] {p}")


@app.command()
def sources() -> None:
    """List sources, the indicator types they cover and whether they're configured."""
    settings = Settings.from_env()
    t = Table(title="Sources", expand=True)
    t.add_column("Source")
    t.add_column("Types")
    t.add_column("Key")
    t.add_column("Status")
    t.add_column("Description", overflow="fold")
    for s in all_sources():
        if not s.key_env:
            state, key = "[green]ready (keyless)[/]", "-"
        elif settings.has(s.key_env):
            state, key = "[green]ready[/]", s.key_env
        elif not s.key_required:
            state, key = "[yellow]keyless / limited[/]", s.key_env
        else:
            state, key = "[grey50]needs key[/]", s.key_env
        t.add_row(s.name, ", ".join(sorted(x.value for x in s.types)), key, state, s.description)
    console.print(t)
    console.print("[dim]Add keys to .env (see .env.example). Keys are never printed.[/]")


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"OSINTCrawler {__version__}")


class _null:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *a: object) -> None:
        return None


def main() -> None:  # pragma: no cover
    app()


