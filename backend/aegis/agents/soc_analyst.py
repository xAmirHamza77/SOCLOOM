"""Skill-orchestrated SOC analyst agent."""

from __future__ import annotations

from aegis.agents.llm import get_llm
from aegis.config import get_settings
from aegis.detection.rules import DetectionRule, rules_to_mitre
from aegis.intel.enrichment import enrich_ip, enrich_indicators
from aegis.mitre.mapper import generate_playbook, resolve_techniques
from aegis.models.schemas import (
    IncidentAnalysisRequest,
    MitreTechnique,
    NetworkLog,
    SkillMatch,
    ThreatAnalysis,
)
from aegis.skills.registry import get_skill_registry

SYSTEM_PROMPT = """You are an elite Tier 2 SOC analyst and threat hunter.
Analyze security events using MITRE ATT&CK framework thinking.
Return JSON with keys: attack_type, reason, risk (Low/Medium/High/Critical), action, mitre_techniques (list of T-codes).
Be specific, actionable, and concise. Reference real attack patterns."""


class SOCAnalystAgent:
    def __init__(self) -> None:
        self.llm = get_llm()
        self.skills = get_skill_registry()
        self.settings = get_settings()

    def analyze_log(
        self,
        log: NetworkLog,
        ml_prediction: str,
        ml_confidence: int,
        rule_hits: list[DetectionRule],
    ) -> ThreatAnalysis:
        intel = enrich_ip(log.src_ip)
        matched_skills = self.skills.match_attack_type(
            rule_hits[0].title if rule_hits else "anomaly",
            " ".join(r.description for r in rule_hits),
        )

        rule_mitre = rules_to_mitre(rule_hits)
        skill_context = self._build_skill_context(matched_skills)

        use_ai = ml_prediction == "anomaly" and ml_confidence >= self.settings.aegis_ai_confidence_threshold

        if use_ai:
            user_prompt = self._build_log_prompt(log, ml_prediction, ml_confidence, rule_hits, intel, skill_context)
            raw = self.llm.analyze(SYSTEM_PROMPT, user_prompt)
        else:
            raw = self._rule_based_analysis(log, rule_hits, ml_confidence)

        all_techniques = list(dict.fromkeys(rule_mitre + raw.get("mitre_techniques", [])))
        mitre = [MitreTechnique(**t) for t in resolve_techniques(all_techniques)]

        return ThreatAnalysis(
            attack_type=raw.get("attack_type", "Suspicious Activity"),
            reason=raw.get("reason", "Anomalous pattern detected."),
            risk=raw.get("risk", "Medium"),
            action=raw.get("action", "Monitor and investigate."),
            mitre_techniques=mitre,
            recommended_skills=[self._to_skill_match(s, 0.9) for s in matched_skills],
            ioc_enrichment={"src_ip": intel},
            playbook_steps=generate_playbook(raw.get("attack_type", ""), all_techniques),
            confidence=ml_confidence,
            llm_provider=self.llm.provider if use_ai else "rules",
        )

    def analyze_incident(self, request: IncidentAnalysisRequest) -> ThreatAnalysis:
        matched_skills = self.skills.search(
            f"{request.title} {request.description} {' '.join(request.indicators)}",
            limit=5,
        )
        skill_entries = [s for s, _ in matched_skills]
        skill_context = self._build_skill_context(skill_entries)
        ioc_data = enrich_indicators(request.indicators) if request.indicators else {}

        user_prompt = f"""Incident: {request.title}
Description: {request.description}
Severity hint: {request.severity_hint or 'unknown'}
Indicators: {request.indicators}
Relevant security skills:
{skill_context}

Provide full incident analysis with MITRE mapping and response actions."""

        raw = self.llm.analyze(SYSTEM_PROMPT, user_prompt)
        techniques = raw.get("mitre_techniques", [])
        for skill in skill_entries:
            techniques.extend(skill.mitre_attack)
        techniques = list(dict.fromkeys(techniques))

        return ThreatAnalysis(
            attack_type=raw.get("attack_type", request.title),
            reason=raw.get("reason", request.description),
            risk=raw.get("risk", request.severity_hint or "Medium"),
            action=raw.get("action", "Begin incident response procedures."),
            mitre_techniques=[MitreTechnique(**t) for t in resolve_techniques(techniques)],
            recommended_skills=[
                self._to_skill_match(s, score) for s, score in matched_skills
            ],
            ioc_enrichment={"indicators": ioc_data},
            playbook_steps=generate_playbook(raw.get("attack_type", request.title), techniques),
            confidence=85,
            llm_provider=self.llm.provider,
        )

    def hunt(self, query: str) -> dict:
        results = self.skills.search(query, limit=8)
        return {
            "query": query,
            "skills": [
                {
                    "name": s.name,
                    "description": s.description,
                    "path": s.path,
                    "subdomain": s.subdomain,
                    "relevance_score": round(score, 2),
                    "mitre_techniques": s.mitre_attack,
                    "workflow_preview": (self.skills.get_skill_content(s.name, 800) or "")[:800],
                }
                for s, score in results
            ],
            "suggested_queries": self._suggest_hunt_queries(query),
        }

    def _build_skill_context(self, skills: list) -> str:
        parts = []
        for skill in skills[:3]:
            excerpt = self.skills.get_skill_content(skill.name, 1200)
            parts.append(f"### Skill: {skill.name}\n{excerpt or skill.description}")
        return "\n\n".join(parts) if parts else "No matching skills found."

    def _build_log_prompt(
        self,
        log: NetworkLog,
        prediction: str,
        confidence: int,
        rule_hits: list[DetectionRule],
        intel: dict,
        skill_context: str,
    ) -> str:
        rules_text = ", ".join(f"{r.id}:{r.title}" for r in rule_hits) or "none"
        return f"""Network log analysis request:
Source: {log.src_ip} | Dest: {log.dst_ip} | Protocol: {log.protocol}
Packet size: {log.packet_size} | Duration: {log.duration}s
ML prediction: {prediction} (confidence {confidence}%)
Rule hits: {rules_text}
Threat intel: country={intel.get('country')}, abuse_score={intel.get('abuse_score')}, isp={intel.get('isp')}

Relevant playbooks:
{skill_context}

Analyze this event and recommend response."""

    def _rule_based_analysis(
        self, log: NetworkLog, rule_hits: list[DetectionRule], confidence: int
    ) -> dict:
        if rule_hits:
            primary = rule_hits[0]
            return {
                "attack_type": primary.title,
                "reason": primary.description,
                "risk": "High" if primary.severity == "high" else "Medium",
                "action": f"Investigate {primary.id} detection and correlate with firewall logs.",
                "mitre_techniques": primary.mitre,
            }
        return {
            "attack_type": "Low-Confidence Anomaly",
            "reason": f"ML flagged unusual traffic (confidence {confidence}%) without rule confirmation.",
            "risk": "Low" if confidence < 50 else "Medium",
            "action": "Monitor source IP; escalate if pattern repeats within 1 hour.",
            "mitre_techniques": ["T1071"],
        }

    def _to_skill_match(self, skill, score: float) -> SkillMatch:
        return SkillMatch(
            name=skill.name,
            description=skill.description,
            path=skill.path,
            subdomain=skill.subdomain,
            relevance_score=score,
            mitre_techniques=skill.mitre_attack,
        )

    def _suggest_hunt_queries(self, query: str) -> list[str]:
        q = query.lower()
        suggestions = []
        if "dns" in q:
            suggestions.append("dns tunneling exfiltration entropy")
        if "powershell" in q or "windows" in q:
            suggestions.append("powershell encoded command evtx sigma")
        if "lateral" in q:
            suggestions.append("pass the hash smb lateral movement")
        if not suggestions:
            suggestions = [
                "ransomware incident response playbook",
                "ioc enrichment virustotal abuseipdb",
                "api gateway suspicious access patterns",
            ]
        return suggestions[:4]


_agent: SOCAnalystAgent | None = None


def get_soc_agent() -> SOCAnalystAgent:
    global _agent
    if _agent is None:
        _agent = SOCAnalystAgent()
    return _agent