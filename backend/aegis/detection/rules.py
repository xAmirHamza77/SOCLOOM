"""Sigma-inspired detection rules for network and auth events."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.models.schemas import NetworkLog


@dataclass
class DetectionRule:
    id: str
    title: str
    severity: str
    mitre: list[str]
    description: str

    def evaluate(self, log: NetworkLog) -> bool:
        raise NotImplementedError


class UDPFloodRule(DetectionRule):
    def __init__(self):
        super().__init__(
            id="NET-001",
            title="Potential UDP Flood",
            severity="high",
            mitre=["T1498.001"],
            description="Large UDP packets with extended duration from external source",
        )

    def evaluate(self, log: NetworkLog) -> bool:
        return (
            log.protocol.upper() == "UDP"
            and log.packet_size > 3000
            and log.duration > 10
        )


class PortScanRule(DetectionRule):
    def __init__(self):
        super().__init__(
            id="NET-002",
            title="Potential Port Scan",
            severity="medium",
            mitre=["T1046"],
            description="Small packets with very short duration indicating reconnaissance",
        )

    def evaluate(self, log: NetworkLog) -> bool:
        return log.packet_size < 200 and log.duration < 2 and (log.dst_port or 0) < 1024


class DataExfilRule(DetectionRule):
    def __init__(self):
        super().__init__(
            id="NET-003",
            title="Large Outbound Transfer",
            severity="high",
            mitre=["T1048", "T1567"],
            description="Unusually large packet/session size suggesting data exfiltration",
        )

    def evaluate(self, log: NetworkLog) -> bool:
        size = log.bytes_sent or log.packet_size
        return size > 8000 and log.duration > 20


class LateralMovementRule(DetectionRule):
    def __init__(self):
        super().__init__(
            id="NET-004",
            title="Internal Lateral Traffic Anomaly",
            severity="medium",
            mitre=["T1021", "T1550.002"],
            description="Unusual internal-to-internal traffic pattern",
        )

    def evaluate(self, log: NetworkLog) -> bool:
        from aegis.intel.enrichment import is_private_ip

        return (
            is_private_ip(log.src_ip)
            and is_private_ip(log.dst_ip)
            and log.packet_size > 2000
            and log.duration > 15
        )


class ICMPFloodRule(DetectionRule):
    def __init__(self):
        super().__init__(
            id="NET-005",
            title="ICMP Flood Indicator",
            severity="high",
            mitre=["T1498"],
            description="High-volume ICMP traffic pattern",
        )

    def evaluate(self, log: NetworkLog) -> bool:
        return log.protocol.upper() == "ICMP" and log.packet_size > 1000 and log.duration > 5


RULES: list[DetectionRule] = [
    UDPFloodRule(),
    PortScanRule(),
    DataExfilRule(),
    LateralMovementRule(),
    ICMPFloodRule(),
]


def evaluate_rules(log: NetworkLog) -> list[DetectionRule]:
    return [rule for rule in RULES if rule.evaluate(log)]


def rules_to_mitre(hits: list[DetectionRule]) -> list[str]:
    techniques: list[str] = []
    for rule in hits:
        for t in rule.mitre:
            if t not in techniques:
                techniques.append(t)
    return techniques