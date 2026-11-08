"""Deterministic threat intelligence analyst: allowlisted report lookups only."""

import asyncio
import re
from datetime import datetime, timezone

import httpx

from .context import public_ip
from .model import ModelFailure, bounded_json

MAX_LOOKUPS = 3
RESERVED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".test",
                     ".invalid", ".example", ".onion", ".arpa")


def eligible(kind, value):
    if kind == "ip":
        try:
            return public_ip(value)
        except ValueError:
            return False
    if kind == "sha256":
        return bool(re.fullmatch(r"[a-f0-9]{64}", value))
    if kind == "domain":
        return (bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value))
                and not value.endswith(RESERVED_SUFFIXES)
                and value not in {"example.com", "example.net", "example.org", "localhost"}
                and not value.endswith((".example.com", ".example.net", ".example.org")))
    return False


class ThreatIntel:
    def __init__(self, client, api_key="", enabled=False):
        self.client = client
        self._api_key = api_key
        self.enabled = enabled and bool(api_key.strip())

    async def enrich(self, indicators, own_ips):
        reports, evidence, lookups = [], [], 0
        for kind, value in indicators[:12]:
            report = {"kind": kind, "value": value, "status": "unavailable"}
            reports.append(report)
            if value in own_ips or not eligible(kind, value):
                report["status"] = "skipped_nonpublic_or_protected"
                continue
            if not self.enabled:
                report["status"] = "unavailable_provider_disabled"
                continue
            if lookups >= MAX_LOOKUPS:
                report["status"] = "unavailable_lookup_limit"
                continue
            lookups += 1
            resource = {"ip": "ip_addresses", "sha256": "files", "domain": "domains"}[kind]
            url = "https://www.virustotal.com/api/v3/" + resource + "/" + value
            try:
                reply = await asyncio.wait_for(bounded_json(
                    self.client, "GET", url, headers={"x-apikey": self._api_key},
                ), timeout=4)
                data = reply["data"]
                if data["id"] != value or data["type"] != {"ip": "ip_address", "sha256": "file", "domain": "domain"}[kind]:
                    raise ValueError("Provider returned a different indicator")
                attributes = data["attributes"]
                stats = attributes["last_analysis_stats"]
                counts = {key: stats[key] for key in ("malicious", "suspicious", "harmless", "undetected")}
                if any(type(v) is not int or v < 0 for v in counts.values()) or not sum(counts.values()):
                    raise ValueError("No valid analysis statistics")
                analyzed = attributes["last_analysis_date"]
                if type(analyzed) is not int:
                    raise ValueError("Invalid provider analysis time")
                analysis_time = datetime.fromtimestamp(analyzed, timezone.utc).isoformat().replace("+00:00", "Z")
                now = datetime.now(timezone.utc)
                if analyzed <= 0 or analyzed > now.timestamp():
                    raise ValueError("Invalid provider analysis time")
                claim = (f"VirusTotal report for {value}: {counts['malicious']} malicious, "
                         f"{counts['suspicious']} suspicious, {counts['harmless']} harmless and "
                         f"{counts['undetected']} undetected engine results; last analysis {analysis_time}. "
                         "Historical reputation is not proof of current compromise or safety.")
                record = {"claim": claim, "source": "virustotal", "log_ref": url,
                          "observed_at": now.isoformat().replace("+00:00", "Z")}
                evidence.append(record)
                report.update(status="available", evidence=record)
            except (ModelFailure, httpx.HTTPError, asyncio.TimeoutError, ValueError,
                    KeyError, TypeError, AttributeError, OverflowError, OSError):
                # Never echo provider bodies, error messages or keys to the model/UI.
                report["status"] = "unavailable_provider_error_or_no_report"
        return {"reports": reports, "evidence": evidence, "lookups": lookups}
