"""MITRE ATT&CK technique mapping and playbook generation."""

from __future__ import annotations

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
    "T1498.001": {"name": "Direct Network Flood", "tactic": "Impact"},
    "T1550.002": {"name": "Pass the Hash", "tactic": "Lateral Movement"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance"},
}


def resolve_techniques(technique_ids: list[str]) -> list[dict]:
    resolved = []
    for tid in technique_ids:
        info = MITRE_TECHNIQUES.get(tid, {})
        resolved.append(
            {
                "technique_id": tid,
                "technique_name": info.get("name", tid),
                "tactic": info.get("tactic", "Unknown"),
                "confidence": 0.85 if tid in MITRE_TECHNIQUES else 0.5,
            }
        )
    return resolved


def generate_playbook(attack_type: str, techniques: list[str]) -> list[str]:
    steps = [
        "1. Triage: Validate alert fidelity and collect source/destination context",
        "2. Contain: Isolate affected hosts if active exploitation is confirmed",
        "3. Investigate: Pull correlated logs (firewall, proxy, EDR) for the last 24h",
    ]

    attack_lower = attack_type.lower()
    if "flood" in attack_lower or "ddos" in attack_lower:
        steps.extend(
            [
                "4. Block: Rate-limit or block source IPs at perimeter firewall/WAF",
                "5. Monitor: Watch bandwidth and connection table for recurrence",
                "6. Report: Document T1498 indicators and upstream provider notification",
            ]
        )
    elif "scan" in attack_lower or "recon" in attack_lower:
        steps.extend(
            [
                "4. Hunt: Search for follow-on authentication attempts from same source",
                "5. Harden: Verify exposed services and patch critical vulnerabilities",
                "6. Report: Map to T1046 and update detection rules",
            ]
        )
    elif "exfil" in attack_lower or "transfer" in attack_lower:
        steps.extend(
            [
                "4. Block: Restrict egress for affected host at firewall",
                "5. Forensics: Capture process list, open connections, and file access timeline",
                "6. Report: Assess data classification impact and trigger IR playbook",
            ]
        )
    elif "lateral" in attack_lower or "internal" in attack_lower:
        steps.extend(
            [
                "4. Isolate: Segment affected VLAN and reset credentials for involved accounts",
                "5. Hunt: Check for PsExec, WMI, RDP, and SMB anomalies (T1021)",
                "6. Report: Escalate to Tier 2 / incident commander",
            ]
        )
    else:
        steps.extend(
            [
                f"4. Enrich: Correlate with MITRE techniques {', '.join(techniques[:3]) or 'N/A'}",
                "5. Respond: Apply organization SOAR playbook or manual containment",
                "6. Close: Document findings and tune detection thresholds",
            ]
        )

    return steps