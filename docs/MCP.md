# SOCloom MCP Server

The SOCloom MCP (Model Context Protocol) server exposes SOC capabilities to AI agents like **Cursor**, **Claude Desktop**, and custom MCP clients.

## Why MCP?

MCP is the fastest-growing integration standard for AI tooling. Exposing SOCloom via MCP means:

- Cursor can analyze alerts during code review
- Claude Desktop can run threat hunts in conversation
- Custom agents can enrich IOCs without writing API glue code

This is a major GitHub differentiator — few open-source SOC tools ship an MCP server.

---

## Installation

```bash
pip install mcp
# or
pip install -r requirements.txt
pip install mcp
```

## Running

```bash
PYTHONPATH=backend python mcp-server/server.py
```

The server registers as **SOCloom** and exposes 6 tools.

---

## Cursor Configuration

Add to `.cursor/mcp.json` in your project or global Cursor config:

```json
{
  "mcpServers": {
    "socloom": {
      "command": "python",
      "args": ["mcp-server/server.py"],
      "env": {
        "PYTHONPATH": "backend",
        "AEGIS_SKILLS_PATH": "/path/to/Anthropic-Cybersecurity-Skills-main",
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

## Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "socloom": {
      "command": "/path/to/socloom/.venv/bin/python",
      "args": ["/path/to/socloom/mcp-server/server.py"],
      "env": {
        "PYTHONPATH": "/path/to/socloom/backend",
        "AEGIS_SKILLS_PATH": "/path/to/Anthropic-Cybersecurity-Skills-main"
      }
    }
  }
}
```

---

## Available Tools

### `analyze_network_log`

Analyze network traffic through ML + rules + skill-orchestrated AI.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `src_ip` | string | yes | Source IP |
| `dst_ip` | string | yes | Destination IP |
| `protocol` | string | no | TCP/UDP/ICMP |
| `packet_size` | int | no | Packet size |
| `duration` | float | no | Duration in seconds |

**Agent prompt example:**
> "Analyze this network log: source 203.0.113.55, destination 10.0.0.5, UDP, 7000 bytes, 30 second duration"

---

### `analyze_incident`

Full incident analysis with MITRE mapping and skill recommendations.

| Parameter | Type | Required |
|-----------|------|----------|
| `title` | string | yes |
| `description` | string | yes |
| `indicators` | string | no (comma-separated) |

---

### `enrich_iocs`

Enrich indicators with threat intelligence.

| Parameter | Type | Required |
|-----------|------|----------|
| `indicators` | string | yes (comma-separated) |

---

### `threat_hunt`

Search 817 security skills for hunt playbooks.

| Parameter | Type | Required |
|-----------|------|----------|
| `query` | string | yes |

---

### `search_skills`

Search the skills catalog by keyword or MITRE technique.

| Parameter | Type | Default |
|-----------|------|---------|
| `query` | string | required |
| `limit` | int | 10 |

---

### `get_skill_workflow`

Retrieve the full SKILL.md workflow for a specific skill.

| Parameter | Type | Required |
|-----------|------|----------|
| `skill_name` | string | yes |

---

## Example Agent Workflows

### Triage an alert in Cursor

```
User: I got a firewall alert — 203.0.113.55 sending 7KB UDP packets to 10.0.0.5 for 30 seconds. Analyze it.

Agent: [calls analyze_network_log]
→ ANOMALY, 70% confidence, UDP Flood / DoS, T1498.001
→ Recommends: analyzing-network-packets-with-scapy
→ Action: Block source IP at perimeter firewall
```

### Hunt for DNS exfiltration

```
User: How do I hunt for DNS tunneling in our environment?

Agent: [calls threat_hunt with query "dns tunneling exfiltration"]
→ Returns: hunting-for-dns-tunneling-with-zeek (score 10.5)
→ Returns: analyzing-dns-logs-for-exfiltration (score 7.5)
→ Suggests follow-up: "dns tunneling exfiltration entropy"
```

### Investigate an incident

```
User: We found .lockbit files on FS-01. IP 10.0.0.42 was involved.

Agent: [calls analyze_incident]
→ Attack: Ransomware
→ MITRE: T1486 (Data Encrypted for Impact)
→ Playbook: Triage → Contain → Isolate VLAN → Hunt PsExec/WMI
→ Skill: building-soc-playbook-for-ransomware
```