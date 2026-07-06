# SOCloom API Reference

Base URL: `http://localhost:8000`

Interactive docs: `/docs` (Swagger) and `/redoc` (ReDoc)

---

## Health

### `GET /api/v1/health`

Returns service status and skills catalog statistics.

**Response:**
```json
{
  "status": "healthy",
  "service": "SOCloom",
  "version": "1.0.0",
  "skills": {
    "total_skills": 817,
    "soc_skills": 329,
    "subdomains": { "threat-hunting": 58, "soc-operations": 35 }
  }
}
```

---

## Log Analysis

### `POST /api/v1/analyze`
### `POST /api/v1/log` (alias)

Analyze a network log through the full detection pipeline.

**Request body:**
```json
{
  "src_ip": "203.0.113.55",
  "dst_ip": "10.0.0.5",
  "protocol": "UDP",
  "packet_size": 6976,
  "duration": 22.5,
  "src_port": 54321,
  "dst_port": 53,
  "bytes_sent": 6976,
  "event_type": "firewall",
  "raw_message": "optional raw log line"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `src_ip` | string | yes | Source IP address |
| `dst_ip` | string | yes | Destination IP address |
| `protocol` | string | no | TCP, UDP, or ICMP (default: TCP) |
| `packet_size` | int | no | Packet/session size in bytes |
| `duration` | float | no | Session duration in seconds |
| `src_port` | int | no | Source port |
| `dst_port` | int | no | Destination port |
| `bytes_sent` | int | no | Bytes sent (used by exfil rule) |
| `bytes_recv` | int | no | Bytes received |
| `event_type` | string | no | Log source type |
| `raw_message` | string | no | Original log line |

**Response:**
```json
{
  "prediction": "anomaly",
  "confidence": 70,
  "rule_hits": ["NET-001: Potential UDP Flood"],
  "analysis": {
    "attack_type": "UDP Flood / DoS",
    "reason": "Large UDP packets with extended duration from external source.",
    "risk": "High",
    "action": "Block source IP at perimeter firewall and monitor bandwidth.",
    "mitre_techniques": [
      {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic": "Impact",
        "confidence": 0.85
      }
    ],
    "recommended_skills": [
      {
        "name": "analyzing-network-packets-with-scapy",
        "description": "Analyze network packets with Scapy",
        "path": "skills/analyzing-network-packets-with-scapy",
        "subdomain": "network-security",
        "relevance_score": 0.9,
        "mitre_techniques": ["T1040"]
      }
    ],
    "ioc_enrichment": {
      "src_ip": {
        "indicator": "203.0.113.55",
        "type": "ipv4",
        "country": "US",
        "abuse_score": 85,
        "malicious_confidence": "high"
      }
    },
    "playbook_steps": [
      "1. Triage: Validate alert fidelity...",
      "4. Block: Rate-limit or block source IPs..."
    ],
    "confidence": 70,
    "llm_provider": "openai"
  }
}
```

**cURL example:**
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"src_ip":"203.0.113.55","dst_ip":"10.0.0.5","protocol":"UDP","packet_size":7000,"duration":30}'
```

---

## Alerts

### `GET /api/v1/alerts?limit=100`

Returns stored alerts, newest first.

**Response:** Array of alert objects.

### `PATCH /api/v1/alerts/{alert_id}/status?status=closed`

Update alert status. Values: `open`, `investigating`, `closed`, `false_positive`.

---

## Incident Analysis

### `POST /api/v1/incident`

Full incident analysis with skill routing and MITRE mapping.

**Request:**
```json
{
  "title": "Suspected Ransomware on File Server",
  "description": "Multiple .lockbit files discovered on FS-01. User reports encrypted documents.",
  "indicators": ["10.0.0.42", "lockbit.exe", "evil-c2.darkweb.onion"],
  "severity_hint": "Critical"
}
```

**Response:** `ThreatAnalysis` object (same schema as `analysis` in log response).

---

## Threat Intelligence

### `POST /api/v1/intel/enrich`

**Request:**
```json
{
  "indicators": ["203.0.113.55", "malicious-domain.com", "d41d8cd98f00b204e9800998ecf8427e"]
}
```

**Response:**
```json
{
  "results": [
    {
      "indicator": "203.0.113.55",
      "type": "ipv4",
      "country": "US",
      "abuse_score": 92,
      "malicious_confidence": "high",
      "sources": ["AbuseIPDB"]
    },
    {
      "indicator": "malicious-domain.com",
      "type": "domain",
      "defanged": "malicious-domain[.]com",
      "malicious_confidence": "unknown"
    }
  ]
}
```

---

## Threat Hunting

### `POST /api/v1/hunt`

Search the 817-skill catalog for hunt playbooks.

**Request:**
```json
{
  "query": "dns tunneling exfiltration",
  "log_source": "network",
  "time_range_hours": 24
}
```

**Response:**
```json
{
  "query": "dns tunneling exfiltration",
  "skills": [
    {
      "name": "hunting-for-dns-tunneling-with-zeek",
      "description": "Detect DNS tunneling with Zeek logs",
      "subdomain": "threat-hunting",
      "relevance_score": 10.5,
      "mitre_techniques": ["T1071.004"],
      "workflow_preview": "## Overview\n..."
    }
  ],
  "suggested_queries": ["dns tunneling exfiltration entropy"]
}
```

---

## Skills Catalog

### `GET /api/v1/skills?q=powershell&limit=20`

Search skills by keyword or MITRE technique.

### `GET /api/v1/skills/{skill_name}`

Retrieve full SKILL.md workflow content.

---

## Dashboard Stats

### `GET /api/v1/stats`

```json
{
  "total_alerts": 42,
  "open_alerts": 38,
  "risk_distribution": { "High": 12, "Medium": 20, "Low": 10 },
  "attack_types": { "UDP Flood / DoS": 8, "Port Scan": 5 },
  "avg_confidence": 67.3
}
```

---

## WebSocket

### `WS /ws/alerts`

Connect to receive real-time alert broadcasts.

**JavaScript example:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/alerts')
ws.onmessage = (event) => {
  const alert = JSON.parse(event.data)
  console.log('New alert:', alert.attack_type, alert.risk)
}
```

**Payload:**
```json
{
  "id": 15,
  "src_ip": "203.0.113.55",
  "dst_ip": "10.0.0.5",
  "confidence": 70,
  "risk": "High",
  "attack_type": "UDP Flood / DoS",
  "country": "US",
  "status": "open",
  "created_at": "2026-07-07T12:00:00"
}
```

---

## Error Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 404 | Skill or alert not found |
| 422 | Validation error (malformed request body) |
| 500 | Internal server error |