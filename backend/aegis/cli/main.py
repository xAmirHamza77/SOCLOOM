"""SOCloom CLI — professional SOC analyst command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from aegis.agents.soc_analyst import get_soc_agent
from aegis.intel.enrichment import enrich_indicators
from aegis.models.schemas import IncidentAnalysisRequest, NetworkLog
from aegis.services.pipeline import get_pipeline
from aegis.skills.registry import get_skill_registry

app = typer.Typer(
    name="aegis",
    help="SOCloom — weave 800+ security skills into SOC operations",
    add_completion=False,
)
console = Console()


@app.command()
def analyze(
    src_ip: str = typer.Option(..., "--src", help="Source IP address"),
    dst_ip: str = typer.Option(..., "--dst", help="Destination IP address"),
    protocol: str = typer.Option("TCP", "--protocol", "-p"),
    packet_size: int = typer.Option(1500, "--size", "-s"),
    duration: float = typer.Option(5.0, "--duration", "-d"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Analyze a network log through ML + rules + skill-orchestrated AI."""
    log = NetworkLog(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        packet_size=packet_size,
        duration=duration,
    )
    result = get_pipeline().process(log, save_alert=False)

    if json_output:
        console.print_json(json.dumps(result.model_dump(), default=str))
        return

    color = "red" if result.prediction == "anomaly" else "green"
    console.print(
        Panel(
            f"[bold]{result.prediction.upper()}[/] (confidence: {result.confidence}%)\n"
            f"Rules: {', '.join(result.rule_hits) or 'none'}",
            title="Detection Result",
            border_style=color,
        )
    )

    if result.analysis:
        a = result.analysis
        console.print(f"\n[bold cyan]Attack:[/] {a.attack_type}")
        console.print(f"[bold]Risk:[/] {a.risk}")
        console.print(f"[bold]Reason:[/] {a.reason}")
        console.print(f"[bold]Action:[/] {a.action}")
        if a.mitre_techniques:
            mitre = ", ".join(f"{t.technique_id} ({t.technique_name})" for t in a.mitre_techniques)
            console.print(f"[bold]MITRE:[/] {mitre}")
        if a.recommended_skills:
            console.print("\n[bold yellow]Recommended Skills:[/]")
            for s in a.recommended_skills:
                console.print(f"  • {s.name} (score: {s.relevance_score})")


@app.command()
def incident(
    title: str = typer.Argument(..., help="Incident title"),
    description: str = typer.Option("", "--desc", "-d"),
    indicators: str = typer.Option("", "--iocs", "-i", help="Comma-separated IOCs"),
):
    """Analyze a full security incident with skill routing."""
    ioc_list = [x.strip() for x in indicators.split(",") if x.strip()]
    request = IncidentAnalysisRequest(title=title, description=description, indicators=ioc_list)
    analysis = get_soc_agent().analyze_incident(request)

    console.print(Panel(f"[bold]{analysis.attack_type}[/]\n{analysis.reason}", title=title, border_style="red"))
    console.print(f"[bold]Risk:[/] {analysis.risk}")
    console.print(f"[bold]Action:[/] {analysis.action}")
    console.print("\n[bold]Playbook:[/]")
    for step in analysis.playbook_steps:
        console.print(f"  {step}")


@app.command()
def hunt(query: str = typer.Argument(..., help="Threat hunt query")):
    """Search 800+ cybersecurity skills for hunt playbooks."""
    result = get_soc_agent().hunt(query)
    table = Table(title=f"Hunt Results: {query}")
    table.add_column("Skill", style="cyan")
    table.add_column("Subdomain")
    table.add_column("Score", justify="right")
    table.add_column("MITRE")

    for skill in result["skills"]:
        table.add_row(
            skill["name"],
            skill.get("subdomain") or "-",
            str(skill["relevance_score"]),
            ", ".join(skill.get("mitre_techniques", [])[:3]),
        )
    console.print(table)

    if result.get("suggested_queries"):
        console.print("\n[dim]Suggested follow-up queries:[/]")
        for q in result["suggested_queries"]:
            console.print(f"  • {q}")


@app.command()
def intel(indicators: str = typer.Argument(..., help="Comma-separated IOCs")):
    """Enrich indicators of compromise."""
    ioc_list = [x.strip() for x in indicators.split(",") if x.strip()]
    results = enrich_indicators(ioc_list)

    table = Table(title="IOC Enrichment")
    table.add_column("Indicator")
    table.add_column("Type")
    table.add_column("Confidence")
    table.add_column("Details")

    for r in results:
        details = f"country={r.get('country', '-')} abuse={r.get('abuse_score', '-')}"
        table.add_row(
            r["indicator"],
            r["type"],
            r.get("malicious_confidence", "unknown"),
            details,
        )
    console.print(table)


@app.command()
def skills(
    query: str = typer.Option("", "--query", "-q"),
    stats: bool = typer.Option(False, "--stats"),
):
    """Browse the cybersecurity skills catalog."""
    registry = get_skill_registry()
    if stats:
        s = registry.stats()
        console.print(Panel(
            f"Total skills: {s['total_skills']}\nSOC-relevant: {s['soc_skills']}",
            title="Skills Catalog",
        ))
        return

    matches = registry.search(query or "threat hunting incident response", limit=15)
    table = Table(title="Skills" + (f" matching '{query}'" if query else ""))
    table.add_column("Name", style="cyan")
    table.add_column("Subdomain")
    table.add_column("Score", justify="right")

    for skill, score in matches:
        table.add_row(skill.name, skill.subdomain or "-", f"{score:.1f}")
    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload"),
):
    """Start the SOCloom API server."""
    import uvicorn

    uvicorn.run("aegis.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()