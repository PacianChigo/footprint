"""Command-line interface for footprint."""

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from footprint import __version__
from footprint.orchestrator import gather

app = typer.Typer(
    name="footprint",
    help="OSINT footprint aggregator for pentesters and investigators.",
    no_args_is_help=True,
)
console = Console()


def _print_report(fp) -> None:
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]Target:[/] {fp.target}\n"
            f"[bold cyan]Risk score:[/] [bold yellow]{fp.risk_score}/10[/]",
            title="footprint",
            border_style="cyan",
        )
    )

    if fp.subdomains:
        table = Table(title="Subdomains (crt.sh)", show_lines=False)
        table.add_column("Count", style="green")
        table.add_column("Sample")
        sample = ", ".join(fp.subdomains.subdomains[:5]) or "—"
        table.add_row(str(fp.subdomains.count), sample)
        console.print(table)

    if fp.dns:
        table = Table(title="DNS")
        table.add_column("Type", style="green")
        table.add_column("Records")
        for rtype in ("a", "aaaa", "mx", "ns", "txt", "cname"):
            values = getattr(fp.dns, rtype)
            if values:
                table.add_row(rtype.upper(), ", ".join(values[:4]))
        console.print(table)

    if fp.whois and (fp.whois.registrar or fp.whois.creation_date):
        table = Table(title="WHOIS")
        table.add_column("Field", style="green")
        table.add_column("Value")
        for field in ("registrar", "org", "creation_date", "expiration_date"):
            value = getattr(fp.whois, field)
            if value:
                table.add_row(field.replace("_", " ").title(), str(value))
        if fp.whois.name_servers:
            table.add_row("Name servers", ", ".join(fp.whois.name_servers[:3]))
        console.print(table)

    if fp.shodan and (fp.shodan.ports or fp.shodan.vulns):
        table = Table(title=f"Shodan InternetDB ({fp.shodan.ip})")
        table.add_column("Field", style="green")
        table.add_column("Value")
        if fp.shodan.ports:
            table.add_row("Open ports", ", ".join(map(str, fp.shodan.ports)))
        if fp.shodan.tags:
            table.add_row("Tags", ", ".join(fp.shodan.tags))
        if fp.shodan.vulns:
            table.add_row("CVEs", ", ".join(fp.shodan.vulns[:5]))
        console.print(table)

    if fp.wayback and fp.wayback.total_sampled:
        console.print(
            f"[bold green]Wayback:[/] {fp.wayback.total_sampled} archived URLs sampled"
        )
        for url in fp.wayback.sample_urls[:5]:
            console.print(f"  [dim]→[/] {url}")

    if fp.errors:
        console.print(f"\n[dim]Errors: {len(fp.errors)}[/]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain to scan (e.g. example.com)"),
    output: Path = typer.Option(
        None, "--output", "-o", help="Write JSON output to this file"
    ),
    json_only: bool = typer.Option(
        False, "--json", help="Print JSON only (no tables)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose errors"),
) -> None:
    """Run a full footprint scan against a domain."""
    target = target.strip().lower().removeprefix("http://").removeprefix("https://")
    target = target.split("/")[0]

    if not json_only:
        console.print(f"[cyan]Scanning[/] {target} ...")

    fp = asyncio.run(gather(target, verbose=verbose))

    if json_only:
        print(json.dumps(fp.model_dump(), indent=2, default=str))
    else:
        _print_report(fp)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(fp.model_dump(), indent=2, default=str))
        if not json_only:
            console.print(f"[green]✓[/] Saved to {output}")


@app.command()
def version() -> None:
    """Show the version."""
    console.print(f"footprint [bold cyan]{__version__}[/]")


if __name__ == "__main__":
    app()
