#!/usr/bin/env python3
"""Generate realistic SOC traffic scenarios for SOCloom demo and testing."""

from __future__ import annotations

import random
import time

import httpx

API_URL = "http://localhost:8000/api/v1/log"

SCENARIOS = {
    "normal": lambda: {
        "src_ip": f"10.0.{random.randint(1,50)}.{random.randint(2,254)}",
        "dst_ip": f"10.0.{random.randint(1,50)}.{random.randint(2,254)}",
        "protocol": random.choice(["TCP", "TCP", "TCP", "UDP"]),
        "packet_size": random.randint(64, 1400),
        "duration": round(random.uniform(0.1, 5), 1),
    },
    "udp_flood": lambda: {
        "src_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst_ip": "10.0.0.5",
        "protocol": "UDP",
        "packet_size": random.randint(4000, 9000),
        "duration": round(random.uniform(15, 45), 1),
    },
    "port_scan": lambda: {
        "src_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst_ip": "10.0.0.10",
        "protocol": "TCP",
        "packet_size": random.randint(40, 120),
        "duration": round(random.uniform(0.1, 1.5), 1),
        "dst_port": random.randint(1, 1024),
    },
    "data_exfil": lambda: {
        "src_ip": "10.0.0.42",
        "dst_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "protocol": "TCP",
        "packet_size": random.randint(8000, 15000),
        "duration": round(random.uniform(25, 90), 1),
        "bytes_sent": random.randint(8000, 15000),
    },
    "lateral": lambda: {
        "src_ip": "10.0.0.15",
        "dst_ip": "10.0.0.88",
        "protocol": "TCP",
        "packet_size": random.randint(2500, 5000),
        "duration": round(random.uniform(18, 40), 1),
    },
}


def send_log(client: httpx.Client, payload: dict) -> dict:
    resp = client.post(API_URL, json=payload, timeout=30)
    return resp.json()


def main():
    print("SOCloom Traffic Simulator")
    print(f"Target: {API_URL}\n")

    weights = ["normal"] * 12 + ["udp_flood", "port_scan", "data_exfil", "lateral"]

    with httpx.Client() as client:
        for i in range(30):
            scenario = random.choice(weights)
            payload = SCENARIOS[scenario]()
            try:
                result = send_log(client, payload)
                pred = result.get("prediction", "?")
                conf = result.get("confidence", 0)
                attack = ""
                if result.get("analysis"):
                    attack = f" → {result['analysis'].get('attack_type', '')}"
                print(
                    f"[{i+1:02d}] {scenario:12s} {payload['src_ip']:>15s} → {payload['dst_ip']:<15s} "
                    f"| {pred} ({conf}%){attack}"
                )
            except Exception as e:
                print(f"[{i+1:02d}] ERROR: {e}")
            time.sleep(0.5)

    print("\nDone. Check dashboard at http://localhost:5173")


if __name__ == "__main__":
    main()