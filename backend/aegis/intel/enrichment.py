"""IOC classification and threat intelligence enrichment."""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any

import httpx

from aegis.config import get_settings

_CACHE: dict[str, dict] = {}
_CACHE_TTL = 3600


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def classify_ioc(value: str) -> str:
    value = value.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ipv4"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "md5"
    if re.match(r"^https?://", value):
        return "url"
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return "email"
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return "domain"
    return "unknown"


def defang_ioc(value: str) -> str:
    value = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return re.sub(r"\.(?=\w)", "[.]", value)


def _cache_get(key: str) -> dict | None:
    entry = _CACHE.get(key)
    if entry and time.time() - entry["ts"] < _CACHE_TTL:
        return entry["data"]
    return None


def _cache_set(key: str, data: dict) -> None:
    _CACHE[key] = {"data": data, "ts": time.time()}


def enrich_ip(ip: str) -> dict[str, Any]:
    cached = _cache_get(f"ip:{ip}")
    if cached:
        return {**cached, "cached": True}

    result: dict[str, Any] = {
        "indicator": ip,
        "type": "ipv4",
        "is_private": is_private_ip(ip),
        "country": "Local Network" if is_private_ip(ip) else "Unknown",
        "isp": "Local" if is_private_ip(ip) else "Unknown",
        "abuse_score": 0,
        "malicious_confidence": "low",
        "sources": [],
    }

    if not is_private_ip(ip):
        settings = get_settings()
        if settings.abuseipdb_api_key:
            try:
                with httpx.Client(timeout=5.0) as client:
                    resp = client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                    )
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    result.update(
                        {
                            "country": data.get("countryCode", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "abuse_score": score,
                            "usage_type": data.get("usageType"),
                            "malicious_confidence": (
                                "high" if score >= 75 else "medium" if score >= 40 else "low"
                            ),
                            "sources": ["AbuseIPDB"],
                        }
                    )
            except Exception:
                pass

    _cache_set(f"ip:{ip}", result)
    return {**result, "cached": False}


def enrich_indicators(indicators: list[str]) -> list[dict[str, Any]]:
    results = []
    for indicator in indicators:
        ioc_type = classify_ioc(indicator)
        if ioc_type == "ipv4":
            results.append(enrich_ip(indicator))
        else:
            results.append(
                {
                    "indicator": indicator,
                    "type": ioc_type,
                    "defanged": defang_ioc(indicator),
                    "malicious_confidence": "unknown",
                    "note": "Local classification only — add VIRUSTOTAL_API_KEY for deep enrichment",
                }
            )
    return results