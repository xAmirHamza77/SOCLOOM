# SOCloom CLI Reference

The SOCloom CLI provides a terminal interface for analysts who prefer command-line workflows.

## Installation

```bash
pip install -r requirements.txt
export PYTHONPATH=backend
```

## Commands

### `analyze` — Analyze a network log

```bash
python -m aegis.cli.main analyze \
  --src 203.0.113.55 \
  --dst 10.0.0.5 \
  --protocol UDP \
  --size 7000 \
  --duration 30
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--src` | | required | Source IP |
| `--dst` | | required | Destination IP |
| `--protocol` | `-p` | TCP | Protocol (TCP/UDP/ICMP) |
| `--size` | `-s` | 1500 | Packet size in bytes |
| `--duration` | `-d` | 5.0 | Session duration in seconds |
| `--json` | | false | Output raw JSON |

**Example output:**
```
╭─────────────── Detection Result ───────────────╮
│ ANOMALY (confidence: 70%)                      │
│ Rules: NET-001: Potential UDP Flood            │
╰────────────────────────────────────────────────╯

Attack: UDP Flood / DoS
Risk: High
Reason: Large UDP packets with extended duration...
Action: Block source IP at perimeter firewall...
MITRE: T1498.001 (Direct Network Flood)

Recommended Skills:
  • analyzing-network-packets-with-scapy (score: 0.9)
  • hunting-for-dns-tunneling-with-zeek (score: 0.9)
```

---

### `hunt` — Threat hunt across skills catalog

```bash
python -m aegis.cli.main hunt "powershell encoded command evtx"
python -m aegis.cli.main hunt "ransomware incident response"
python -m aegis.cli.main hunt "pass the hash lateral movement"
```

Searches 817 cybersecurity skills and returns:
- Matching skill names and subdomains
- Relevance scores
- MITRE techniques per skill
- Suggested follow-up queries

---

### `intel` — Enrich indicators of compromise

```bash
python -m aegis.cli.main intel "203.0.113.55"
python -m aegis.cli.main intel "203.0.113.55,evil.com,deadbeef..."
```

Supports: IPv4, domains, URLs, SHA256/SHA1/MD5 hashes, emails.

Requires `ABUSEIPDB_API_KEY` in `.env` for IP reputation. Works offline for classification and defanging.

---

### `incident` — Full incident analysis

```bash
python -m aegis.cli.main incident "Ransomware on FS-01" \
  --desc "Encrypted files with .lockbit extension discovered" \
  --iocs "10.0.0.42,lockbit.exe"
```

Runs the full SOC analyst agent:
- Skill routing
- IOC enrichment
- LLM analysis (or rule fallback)
- MITRE mapping
- IR playbook generation

---

### `skills` — Browse skills catalog

```bash
# Show catalog statistics
python -m aegis.cli.main skills --stats

# Search skills
python -m aegis.cli.main skills --query "dns tunneling"
python -m aegis.cli.main skills -q "T1059.001"
```

---

### `serve` — Start API server

```bash
python -m aegis.cli.main serve --port 8000 --reload
```

Equivalent to:
```bash
PYTHONPATH=backend uvicorn aegis.main:app --reload --port 8000
```

---

## Environment

The CLI reads from `.env` in the project root:

```env
AEGIS_SKILLS_PATH=/path/to/Anthropic-Cybersecurity-Skills-main
OPENAI_API_KEY=sk-...
ABUSEIPDB_API_KEY=...
```

## Piping & Automation

```bash
# Analyze all sample logs
cat data/sample_logs.json | python3 -c "
import json, sys, httpx
for log in json.load(sys.stdin):
    r = httpx.post('http://localhost:8000/api/v1/analyze', json=log)
    print(log['src_ip'], '→', r.json()['prediction'])
"

# JSON output for scripting
python -m aegis.cli.main analyze --src 10.0.0.1 --dst 10.0.0.2 --json | jq .analysis.attack_type
```