# SOCloom Architecture

## Overview

SOCloom is a modular, pipeline-driven SOC platform. Every component is independently testable and replaceable.

```
┌─────────────────────────────────────────────────────────────────┐
│                        INGESTION LAYER                          │
│  REST API  •  CLI  •  MCP Server  •  Traffic Simulator          │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                      DETECTION LAYER                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Isolation    │  │ Sigma-Style  │  │ Confidence Fusion      │  │
│  │ Forest ML    │  │ Rules (5)    │  │ max(ML, rule_boost)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                    SKILLLOOM CORE                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Skill Router │  │ MITRE Mapper │  │ IOC Enrichment       │  │
│  │ 817 catalog  │  │ ATT&CK DB    │  │ AbuseIPDB + cache    │  │
│  └──────┬───────┘  └──────────────┘  └──────────────────────┘  │
│         │                                                       │
│  ┌──────▼───────────────────────────────────────────────────┐  │
│  │ SOC Analyst Agent (multi-LLM)                             │  │
│  │  • Injects top-3 skill workflows into prompt             │  │
│  │  • Returns attack type, risk, action, MITRE techniques   │  │
│  │  • Generates IR playbook steps                           │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                       OUTPUT LAYER                              │
│  SQLite Alerts  •  WebSocket Broadcast  •  REST Response        │
│  React Dashboard (charts, table, live feed)                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Detection Engine

**File:** `backend/aegis/detection/ml.py`

Isolation Forest with 8 engineered features per network log:

| Feature | Description |
|---------|-------------|
| `packet_size` | Bytes per packet/session |
| `duration` | Session duration (seconds) |
| `protocol` | TCP=1, UDP=2, ICMP=3 |
| `src_external` | Source is public IP |
| `dst_external` | Destination is public IP |
| `internal_lateral` | Both IPs are private (RFC 1918) |
| `large_packet` | packet_size > 3000 |
| `long_duration` | duration > 15s |

Model auto-trains on synthetic data if no `.pkl` file exists at `data/anomaly_model.pkl`.

**File:** `backend/aegis/detection/rules.py`

Five Sigma-inspired rules:

| Rule ID | Title | MITRE | Trigger |
|---------|-------|-------|---------|
| NET-001 | Potential UDP Flood | T1498.001 | UDP + size>3000 + duration>10 |
| NET-002 | Potential Port Scan | T1046 | size<200 + duration<2 + dst_port<1024 |
| NET-003 | Large Outbound Transfer | T1048, T1567 | size>8000 + duration>20 |
| NET-004 | Internal Lateral Anomaly | T1021, T1550.002 | both private + size>2000 + duration>15 |
| NET-005 | ICMP Flood Indicator | T1498 | ICMP + size>1000 + duration>5 |

### 2. Skill Router

**File:** `backend/aegis/skills/registry.py`

Loads the Anthropic Cybersecurity Skills catalog via `index.json` (817 skills).

**SOC-relevant subdomains** (329 skills):
- `soc-operations`, `security-operations`, `threat-hunting`
- `threat-intelligence`, `threat-detection`, `incident-response`
- `digital-forensics`, `malware-analysis`, `network-security`

**Routing algorithm:**
1. Tokenize incident text (attack type, reason, IOCs, query)
2. Score each SOC skill by keyword overlap, name match, MITRE technique match
3. Return top-N skills with relevance scores
4. Extract SKILL.md workflow content (up to 4000 chars) for LLM context

**Attack-type keyword mapping:**

| Category | Keywords | Example Skills |
|----------|----------|----------------|
| ddos | flood, udp flood, syn | network packet analysis |
| port_scan | scan, reconnaissance | API gateway log analysis |
| dns_tunnel | dns tunnel, exfil | hunting DNS tunneling with Zeek |
| lateral | pass-the-hash, internal | detecting pass-the-hash |
| exfiltration | large transfer, egress | analyzing DNS logs for exfiltration |
| ransomware | encryption, lockbit | building SOC playbook for ransomware |

### 3. SOC Analyst Agent

**File:** `backend/aegis/agents/soc_analyst.py`

Orchestrates the full analysis:

1. Enrich source IP via IOC pipeline
2. Match skills to attack type / incident description
3. Build structured prompt with log data + rule hits + intel + skill excerpts
4. Call LLM (or rule-based fallback)
5. Merge MITRE techniques from rules + LLM + matched skills
6. Generate IR playbook steps

**Cost optimization:** LLM is only called when `confidence >= AEGIS_AI_CONFIDENCE_THRESHOLD` (default 60%). Below threshold, rule-based analysis is used.

### 4. Multi-LLM Client

**File:** `backend/aegis/agents/llm.py`

| Provider | Trigger | Default Model |
|----------|---------|---------------|
| OpenAI | `OPENAI_API_KEY` set | `gpt-4o-mini` |
| Anthropic | `ANTHROPIC_API_KEY` set | `claude-sonnet-4-20250514` |
| Ollama | `AEGIS_LLM_PROVIDER=ollama` | configurable |
| Local fallback | No keys | Rule-based responses |

### 5. MITRE Mapper

**File:** `backend/aegis/mitre/mapper.py`

Maintains a technique database and generates attack-type-specific IR playbooks:

```
Triage → Contain → Investigate → [attack-specific steps] → Report → Close
```

### 6. IOC Enrichment

**File:** `backend/aegis/intel/enrichment.py`

- Classifies IOCs by regex (IPv4, domain, URL, hashes, email)
- Defangs IOCs for safe documentation
- Queries AbuseIPDB for public IPs (optional key)
- 1-hour in-memory cache per indicator

### 7. Data Layer

**File:** `backend/aegis/models/alert.py`

SQLite (default) or PostgreSQL via `AEGIS_DATABASE_URL`.

Alert fields: source/dest IP, protocol, ML prediction, confidence, attack classification, risk, MITRE techniques (JSON), rule hits (JSON), geo/intel, status, timestamp.

---

## Request Lifecycle

### Network log analysis (`POST /api/v1/analyze`)

```
1. Receive NetworkLog JSON
2. preprocess → 8-feature DataFrame
3. ML predict → {prediction, confidence}
4. evaluate_rules → [rule hits]
5. IF anomaly OR rule_hit:
   a. boost confidence to max(ml, 70) if rules fired
   b. enrich src_ip
   c. match_attack_type → top 5 skills
   d. IF confidence >= 60: LLM analyze
      ELSE: rule-based analysis
   e. resolve MITRE techniques
   f. generate playbook steps
   g. save Alert to DB
   h. WebSocket broadcast
6. Return AnalyzeResponse
```

### Incident analysis (`POST /api/v1/incident`)

```
1. Receive title + description + IOCs
2. skill search on combined text
3. enrich all IOCs
4. LLM analyze with skill context
5. Return ThreatAnalysis (no DB save by default)
```

---

## Extension Points

| Want to add… | Edit this file |
|--------------|----------------|
| New detection rule | `backend/aegis/detection/rules.py` |
| New MITRE technique | `backend/aegis/mitre/mapper.py` |
| New LLM provider | `backend/aegis/agents/llm.py` |
| New MCP tool | `mcp-server/server.py` |
| New API endpoint | `backend/aegis/api/routes.py` |
| Dashboard widget | `frontend/src/App.jsx` |