#!/usr/bin/env python3
"""SOCloom MCP Server — expose SOC capabilities to AI agents (Cursor, Claude Desktop)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from aegis.agents.soc_analyst import get_soc_agent
from aegis.intel.enrichment import enrich_indicators
from aegis.models.schemas import IncidentAnalysisRequest, NetworkLog
from aegis.services.pipeline import get_pipeline
from aegis.skills.registry import get_skill_registry

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("Install MCP support: pip install 'socloom[mcp]'", file=sys.stderr)
    sys.exit(1)

mcp = FastMCP("socloom")


@mcp.tool()
def analyze_network_log(
    src_ip: str,
    dst_ip: str,
    protocol: str = "TCP",
    packet_size: int = 1500,
    duration: float = 5.0,
) -> str:
    """Analyze network traffic through ML anomaly detection, Sigma-style rules, and AI SOC analyst."""
    log = NetworkLog(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        packet_size=packet_size,
        duration=duration,
    )
    result = get_pipeline().process(log, save_alert=False)
    return json.dumps(result.model_dump(), default=str, indent=2)


@mcp.tool()
def analyze_incident(title: str, description: str, indicators: str = "") -> str:
    """Perform full incident analysis with MITRE ATT&CK mapping and skill recommendations."""
    iocs = [i.strip() for i in indicators.split(",") if i.strip()]
    request = IncidentAnalysisRequest(title=title, description=description, indicators=iocs)
    analysis = get_soc_agent().analyze_incident(request)
    return json.dumps(analysis.model_dump(), default=str, indent=2)


@mcp.tool()
def enrich_iocs(indicators: str) -> str:
    """Enrich IOCs (IPs, domains, hashes, URLs) with threat intelligence."""
    iocs = [i.strip() for i in indicators.split(",") if i.strip()]
    return json.dumps(enrich_indicators(iocs), indent=2)


@mcp.tool()
def threat_hunt(query: str) -> str:
    """Search 800+ cybersecurity skills for threat hunting playbooks and workflows."""
    return json.dumps(get_soc_agent().hunt(query), indent=2)


@mcp.tool()
def search_skills(query: str, limit: int = 10) -> str:
    """Search the cybersecurity skills catalog by keyword or MITRE technique."""
    registry = get_skill_registry()
    matches = registry.search(query, limit=limit)
    return json.dumps(
        [
            {
                "name": s.name,
                "description": s.description,
                "subdomain": s.subdomain,
                "relevance_score": round(score, 2),
                "mitre_techniques": s.mitre_attack,
            }
            for s, score in matches
        ],
        indent=2,
    )


@mcp.tool()
def get_skill_workflow(skill_name: str) -> str:
    """Retrieve the full workflow documentation for a specific security skill."""
    content = get_skill_registry().get_skill_content(skill_name)
    if not content:
        return json.dumps({"error": f"Skill '{skill_name}' not found"})
    return json.dumps({"name": skill_name, "workflow": content})


if __name__ == "__main__":
    mcp.run()