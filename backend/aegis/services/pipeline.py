"""End-to-end detection and analysis pipeline."""

from __future__ import annotations

import json

from aegis.agents.soc_analyst import get_soc_agent
from aegis.config import get_settings
from aegis.database import SessionLocal
from aegis.detection.ml import get_detector
from aegis.detection.rules import evaluate_rules
from aegis.models.alert import Alert
from aegis.models.schemas import AnalyzeResponse, NetworkLog, ThreatAnalysis


class AnalysisPipeline:
    def __init__(self) -> None:
        self.detector = get_detector()
        self.agent = get_soc_agent()
        self.settings = get_settings()

    def process(self, log: NetworkLog, save_alert: bool = True) -> AnalyzeResponse:
        ml_result = self.detector.predict(log)
        rule_hits = evaluate_rules(log)
        rule_titles = [f"{r.id}: {r.title}" for r in rule_hits]

        is_anomaly = (
            ml_result["prediction"] == "anomaly"
            or len(rule_hits) > 0
        )

        analysis: ThreatAnalysis | None = None
        if is_anomaly:
            confidence = max(
                ml_result["confidence"],
                70 if rule_hits else 0,
            )
            ml_result["confidence"] = confidence
            analysis = self.agent.analyze_log(
                log,
                "anomaly" if is_anomaly else "normal",
                confidence,
                rule_hits,
            )

            if save_alert:
                self._save_alert(log, ml_result, analysis, rule_titles)

        return AnalyzeResponse(
            prediction="anomaly" if is_anomaly else "normal",
            confidence=ml_result["confidence"],
            analysis=analysis,
            rule_hits=rule_titles,
        )

    def _save_alert(
        self,
        log: NetworkLog,
        ml_result: dict,
        analysis: ThreatAnalysis,
        rule_hits: list[str],
    ) -> Alert:
        db = SessionLocal()
        try:
            intel = analysis.ioc_enrichment.get("src_ip", {})
            alert = Alert(
                src_ip=log.src_ip,
                dst_ip=log.dst_ip,
                protocol=log.protocol,
                packet_size=log.packet_size,
                duration=int(log.duration),
                prediction="anomaly",
                confidence=ml_result["confidence"],
                attack_type=analysis.attack_type,
                reason=analysis.reason,
                risk=analysis.risk,
                action=analysis.action,
                country=intel.get("country", "Unknown"),
                isp=intel.get("isp", "Unknown"),
                is_private=intel.get("is_private", False),
                mitre_techniques=json.dumps(
                    [t.technique_id for t in analysis.mitre_techniques]
                ),
                rule_hits=json.dumps(rule_hits),
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            return alert
        finally:
            db.close()


_pipeline: AnalysisPipeline | None = None


def get_pipeline() -> AnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline