"""SOCloom REST API routes."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from aegis.agents.soc_analyst import get_soc_agent
from aegis.database import get_db
from aegis.intel.enrichment import enrich_indicators
from aegis.models.alert import Alert
from aegis.models.schemas import (
    AlertResponse,
    AnalyzeResponse,
    HuntRequest,
    IncidentAnalysisRequest,
    IOCRequest,
    NetworkLog,
    ThreatAnalysis,
)
from aegis.services.pipeline import get_pipeline
from aegis.skills.registry import get_skill_registry

router = APIRouter()
ws_connections: list[WebSocket] = []


@router.get("/health")
def health():
    registry = get_skill_registry()
    return {
        "status": "healthy",
        "service": "SOCloom",
        "version": "1.0.0",
        "skills": registry.stats(),
    }


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_log(log: NetworkLog):
    result = get_pipeline().process(log)
    if result.analysis and result.prediction == "anomaly":
        await _broadcast_latest()
    return result


@router.post("/log", response_model=AnalyzeResponse)
async def ingest_log(log: NetworkLog):
    return await analyze_log(log)


@router.get("/alerts", response_model=list[AlertResponse])
def list_alerts(limit: int = 100, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
    responses = []
    for a in alerts:
        mitre = json.loads(a.mitre_techniques) if a.mitre_techniques else []
        resp = AlertResponse.model_validate(a)
        resp.mitre_techniques = mitre
        responses.append(resp)
    return responses


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, status: str, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = status
    db.commit()
    return {"id": alert_id, "status": status}


@router.post("/incident", response_model=ThreatAnalysis)
def analyze_incident(request: IncidentAnalysisRequest):
    return get_soc_agent().analyze_incident(request)


@router.post("/intel/enrich")
def enrich_iocs(request: IOCRequest):
    return {"results": enrich_indicators(request.indicators)}


@router.post("/hunt")
def threat_hunt(request: HuntRequest):
    return get_soc_agent().hunt(request.query)


@router.get("/skills")
def list_skills(q: str = "", limit: int = 20):
    registry = get_skill_registry()
    if q:
        matches = registry.search(q, limit=limit)
        return {
            "query": q,
            "results": [
                {
                    "name": s.name,
                    "description": s.description,
                    "path": s.path,
                    "subdomain": s.subdomain,
                    "relevance_score": round(score, 2),
                    "mitre_techniques": s.mitre_attack,
                }
                for s, score in matches
            ],
        }
    return registry.stats()


@router.get("/skills/{skill_name}")
def get_skill(skill_name: str):
    registry = get_skill_registry()
    content = registry.get_skill_content(skill_name)
    if not content:
        raise HTTPException(404, f"Skill '{skill_name}' not found")
    return {"name": skill_name, "content": content}


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    attack_types: dict[str, int] = {}
    for a in alerts:
        risk = a.risk or "Medium"
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        at = a.attack_type or "Unknown"
        attack_types[at] = attack_types.get(at, 0) + 1

    return {
        "total_alerts": len(alerts),
        "open_alerts": sum(1 for a in alerts if a.status == "open"),
        "risk_distribution": risk_counts,
        "attack_types": attack_types,
        "avg_confidence": round(sum(a.confidence for a in alerts) / len(alerts), 1) if alerts else 0,
    }


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    ws_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in ws_connections:
            ws_connections.remove(websocket)


async def _broadcast_latest():
    from aegis.database import SessionLocal

    db = SessionLocal()
    try:
        alert = db.query(Alert).order_by(Alert.created_at.desc()).first()
        if not alert:
            return
        payload = {
            "id": alert.id,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "protocol": alert.protocol,
            "confidence": alert.confidence,
            "risk": alert.risk,
            "attack_type": alert.attack_type,
            "reason": alert.reason,
            "action": alert.action,
            "country": alert.country,
            "status": alert.status,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }
        for conn in ws_connections:
            try:
                await conn.send_json(payload)
            except Exception:
                pass
    finally:
        db.close()