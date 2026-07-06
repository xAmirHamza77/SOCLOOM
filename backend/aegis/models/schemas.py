from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NetworkLog(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str = "TCP"
    packet_size: int = 0
    duration: float = 0.0
    src_port: int | None = None
    dst_port: int | None = None
    bytes_sent: int | None = None
    bytes_recv: int | None = None
    event_type: str | None = None
    raw_message: str | None = None


class IOCRequest(BaseModel):
    indicators: list[str] = Field(..., min_length=1, max_length=50)


class HuntRequest(BaseModel):
    query: str
    log_source: str = "network"
    time_range_hours: int = 24


class IncidentAnalysisRequest(BaseModel):
    title: str
    description: str
    indicators: list[str] = []
    logs: list[NetworkLog] = []
    severity_hint: str | None = None


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str | None = None
    confidence: float = 0.0


class SkillMatch(BaseModel):
    name: str
    description: str
    path: str
    subdomain: str | None = None
    relevance_score: float
    mitre_techniques: list[str] = []


class ThreatAnalysis(BaseModel):
    attack_type: str
    reason: str
    risk: str
    action: str
    mitre_techniques: list[MitreTechnique] = []
    recommended_skills: list[SkillMatch] = []
    ioc_enrichment: dict[str, Any] = {}
    playbook_steps: list[str] = []
    confidence: int = 0
    llm_provider: str | None = None


class AlertResponse(BaseModel):
    id: int
    src_ip: str
    dst_ip: str
    protocol: str
    packet_size: int
    duration: float
    prediction: str
    confidence: int
    attack_type: str | None = None
    reason: str | None = None
    risk: str | None = None
    action: str | None = None
    country: str | None = None
    isp: str | None = None
    is_private: bool = False
    mitre_techniques: list[str] = []
    status: str = "open"
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class AnalyzeResponse(BaseModel):
    prediction: str
    confidence: int
    analysis: ThreatAnalysis | None = None
    rule_hits: list[str] = []