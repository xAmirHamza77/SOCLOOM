"""Skill catalog loader and semantic router for Anthropic Cybersecurity Skills."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from aegis.config import get_settings

SOC_SUBDOMAINS = {
    "soc-operations",
    "security-operations",
    "threat-hunting",
    "threat-intelligence",
    "threat-detection",
    "incident-response",
    "digital-forensics",
    "malware-analysis",
    "network-security",
}

ATTACK_KEYWORDS: dict[str, list[str]] = {
    "ddos": ["ddos", "flood", "udp flood", "syn flood", "denial of service"],
    "port_scan": ["port scan", "scanning", "reconnaissance", "nmap"],
    "dns_tunnel": ["dns tunnel", "dns exfil", "dns exfiltration", "dns tunneling"],
    "powershell": ["powershell", "encoded command", "t1059.001"],
    "lateral": ["lateral movement", "internal", "east-west", "pass-the-hash", "pth"],
    "exfiltration": ["exfiltration", "data transfer", "large transfer", "egress"],
    "phishing": ["phishing", "ioc", "malicious url", "email"],
    "ransomware": ["ransomware", "encryption", "lockbit", "conti"],
    "brute_force": ["brute force", "failed login", "authentication failure"],
    "c2": ["command and control", "c2", "beacon", "cobalt strike"],
}


@dataclass
class SkillEntry:
    name: str
    description: str
    path: str
    subdomain: str | None = None
    tags: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    nist_csf: list[str] = field(default_factory=list)


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: list[SkillEntry] = []
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return

        settings = get_settings()
        index_path = settings.skills_index_path

        if index_path.exists():
            data = json.loads(index_path.read_text())
            for entry in data.get("skills", []):
                skill_path = Path(settings.aegis_skills_path) / entry["path"]
                meta = self._parse_skill_metadata(skill_path)
                self._skills.append(
                    SkillEntry(
                        name=entry["name"],
                        description=str(entry.get("description", "")),
                        path=entry["path"],
                        subdomain=str(meta["subdomain"]) if meta.get("subdomain") else None,
                        tags=[str(t) for t in meta.get("tags", []) if t is not None],
                        mitre_attack=[str(t) for t in meta.get("mitre_attack", []) if t is not None],
                        nist_csf=[str(t) for t in meta.get("nist_csf", []) if t is not None],
                    )
                )
        else:
            self._skills = self._builtin_skills()

        self._loaded = True

    def _parse_skill_metadata(self, skill_dir: Path) -> dict:
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            return {}
        content = skill_md.read_text()
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                try:
                    return yaml.safe_load(parts[1]) or {}
                except yaml.YAMLError:
                    return {}
        return {}

    def _builtin_skills(self) -> list[SkillEntry]:
        return [
            SkillEntry(
                name="analyzing-indicators-of-compromise",
                description="IOC enrichment and triage with multi-source intelligence",
                path="skills/analyzing-indicators-of-compromise",
                subdomain="threat-intelligence",
                tags=["IOC", "VirusTotal", "AbuseIPDB"],
                mitre_attack=["T1071", "T1105"],
            ),
            SkillEntry(
                name="hunting-evtx-with-chainsaw",
                description="Sigma-based Windows event log threat hunting",
                path="skills/hunting-evtx-with-chainsaw",
                subdomain="threat-hunting",
                tags=["sigma", "evtx", "windows"],
                mitre_attack=["T1059.001"],
            ),
            SkillEntry(
                name="analyzing-dns-logs-for-exfiltration",
                description="Detect DNS tunneling and data exfiltration",
                path="skills/analyzing-dns-logs-for-exfiltration",
                subdomain="soc-operations",
                tags=["dns", "exfiltration"],
                mitre_attack=["T1071.004", "T1048"],
            ),
            SkillEntry(
                name="building-soc-playbook-for-ransomware",
                description="Ransomware incident response playbook",
                path="skills/building-soc-playbook-for-ransomware",
                subdomain="soc-operations",
                tags=["ransomware", "playbook"],
                mitre_attack=["T1486"],
            ),
            SkillEntry(
                name="detecting-pass-the-hash-attacks",
                description="Detect pass-the-hash lateral movement",
                path="skills/detecting-pass-the-hash-attacks",
                subdomain="threat-detection",
                tags=["lateral", "ntlm"],
                mitre_attack=["T1550.002"],
            ),
        ]

    @property
    def skills(self) -> list[SkillEntry]:
        self.load()
        return self._skills

    @property
    def soc_skills(self) -> list[SkillEntry]:
        return [s for s in self.skills if s.subdomain in SOC_SUBDOMAINS or not s.subdomain]

    def search(self, query: str, limit: int = 5) -> list[tuple[SkillEntry, float]]:
        self.load()
        query_lower = query.lower()
        tokens = set(re.findall(r"[a-z0-9.]+", query_lower))
        scored: list[tuple[SkillEntry, float]] = []

        for skill in self.soc_skills:
            score = 0.0
            corpus = " ".join(
                [skill.name, skill.description, skill.subdomain or "", " ".join(skill.tags)]
            ).lower()

            for token in tokens:
                if token in corpus:
                    score += 2.0
                if token in skill.name.replace("-", " "):
                    score += 3.0

            for technique in skill.mitre_attack:
                if technique.lower() in query_lower:
                    score += 5.0

            if skill.subdomain in SOC_SUBDOMAINS:
                score += 0.5

            if score > 0:
                scored.append((skill, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:limit]

    def match_attack_type(self, attack_type: str, reason: str = "") -> list[SkillEntry]:
        self.load()
        text = f"{attack_type} {reason}".lower()
        matched_categories: set[str] = set()

        for category, keywords in ATTACK_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                matched_categories.add(category)

        results: list[SkillEntry] = []
        category_skill_map = {
            "ddos": ["network", "ddos", "flood", "traffic"],
            "port_scan": ["scan", "recon", "port"],
            "dns_tunnel": ["dns", "tunnel", "exfil"],
            "powershell": ["powershell", "evtx", "chainsaw", "script"],
            "lateral": ["lateral", "pass-the-hash", "internal"],
            "exfiltration": ["exfil", "dns", "transfer"],
            "phishing": ["ioc", "phishing", "email", "indicator"],
            "ransomware": ["ransomware", "playbook"],
            "brute_force": ["authentication", "login", "anomal"],
            "c2": ["c2", "command", "beacon", "cobalt"],
        }

        for skill in self.soc_skills:
            corpus = f"{skill.name} {skill.description} {' '.join(str(t) for t in skill.tags)}".lower()
            for category in matched_categories:
                for kw in category_skill_map.get(category, []):
                    if kw in corpus:
                        results.append(skill)
                        break

        if not results:
            results = [s for s, _ in self.search(text, limit=3)]

        seen: set[str] = set()
        unique: list[SkillEntry] = []
        for skill in results:
            if skill.name not in seen:
                seen.add(skill.name)
                unique.append(skill)
        return unique[:5]

    def get_skill_content(self, skill_name: str, max_chars: int = 4000) -> str | None:
        self.load()
        settings = get_settings()
        for skill in self.skills:
            if skill.name == skill_name:
                skill_md = Path(settings.aegis_skills_path) / skill.path / "SKILL.md"
                if skill_md.exists():
                    content = skill_md.read_text()
                    if content.startswith("---"):
                        parts = content.split("---", 2)
                        body = parts[2] if len(parts) >= 3 else content
                    else:
                        body = content
                    return body[:max_chars]
        return None

    def stats(self) -> dict:
        self.load()
        subdomains: dict[str, int] = {}
        for skill in self.skills:
            key = skill.subdomain or "general"
            subdomains[key] = subdomains.get(key, 0) + 1
        return {
            "total_skills": len(self.skills),
            "soc_skills": len(self.soc_skills),
            "subdomains": subdomains,
        }


_registry: SkillRegistry | None = None


def get_skill_registry() -> SkillRegistry:
    global _registry
    if _registry is None:
        _registry = SkillRegistry()
    return _registry