"""Isolation Forest anomaly detection for network telemetry."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from aegis.config import ROOT_DIR
from aegis.models.schemas import NetworkLog

MODEL_PATH = ROOT_DIR / "data" / "anomaly_model.pkl"


class AnomalyDetector:
    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            random_state=42,
        )
        self._ready = False

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def featurize(self, log: NetworkLog) -> pd.DataFrame:
        protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
        src_private = self._is_private(log.src_ip)
        dst_private = self._is_private(log.dst_ip)
        packet_size = log.bytes_sent or log.packet_size

        return pd.DataFrame(
            [
                {
                    "packet_size": packet_size,
                    "duration": log.duration,
                    "protocol": protocol_map.get(log.protocol.upper(), 0),
                    "src_external": 0 if src_private else 1,
                    "dst_external": 0 if dst_private else 1,
                    "internal_lateral": 1 if src_private and dst_private else 0,
                    "large_packet": 1 if packet_size > 3000 else 0,
                    "long_duration": 1 if log.duration > 15 else 0,
                }
            ]
        )

    def train(self, data: pd.DataFrame) -> None:
        scaled = self.scaler.fit_transform(data)
        self.model.fit(scaled)
        self._ready = True

    def predict(self, log: NetworkLog) -> dict:
        if not self._ready:
            self.load_or_train()
        features = self.featurize(log)
        scaled = self.scaler.transform(features)
        result = self.model.predict(scaled)[0]
        raw_score = self.model.decision_function(scaled)[0]
        confidence = max(1, min(99, round((1 - raw_score) * 50)))
        return {
            "prediction": "anomaly" if result == -1 else "normal",
            "confidence": confidence,
        }

    def save(self, path: Path = MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, path)

    def load_or_train(self) -> None:
        if MODEL_PATH.exists():
            data = joblib.load(MODEL_PATH)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self._ready = True
            return

        training = self._generate_training_data()
        self.train(training)
        self.save()

    def _generate_training_data(self) -> pd.DataFrame:
        import random

        rows = []
        for _ in range(500):
            rows.append(
                {
                    "packet_size": random.randint(64, 1500),
                    "duration": random.uniform(0.1, 8),
                    "protocol": random.choice([1, 1, 1, 2]),
                    "src_external": random.choice([0, 0, 1]),
                    "dst_external": random.choice([0, 1]),
                    "internal_lateral": random.choice([0, 0, 1]),
                    "large_packet": 0,
                    "long_duration": 0,
                }
            )
        for _ in range(40):
            rows.append(
                {
                    "packet_size": random.randint(3500, 9000),
                    "duration": random.uniform(12, 60),
                    "protocol": random.choice([2, 2, 3]),
                    "src_external": 1,
                    "dst_external": 0,
                    "internal_lateral": 0,
                    "large_packet": 1,
                    "long_duration": 1,
                }
            )
        return pd.DataFrame(rows)


_detector: AnomalyDetector | None = None


def get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        _detector.load_or_train()
    return _detector