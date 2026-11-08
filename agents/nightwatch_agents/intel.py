"""Deterministic threat intelligence analyst: allowlisted report lookups only."""

import asyncio
import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from .context import public_ip
from .intel_limits import IntelBudget
from .model import MAX_RESPONSE_BYTES

MAX_LOOKUPS = 3
LOOKUP_TIMEOUT_SECONDS = 4
# Shared by request-scoped adapters in this one Python process; no report cache.
_shared_budget = IntelBudget()
RESERVED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".test",
                     ".invalid", ".example", ".onion", ".arpa")


def eligible(kind, value):
    if not isinstance(value, str) or len(value) > 253:
        return False
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


class IntelUnavailable(Exception):
    """Fixed status labels only; never provider message bodies or credentials."""


def retry_delay(value):
    try:
        seconds = int(value)
    except (ValueError, TypeError):
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                return 60
            seconds = int((parsed - datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return 60
    return min(max(seconds, 1), 86400)


async def fetch_report(client, url, api_key, budget):
    # Explicitly disallow redirects even if the supplied client enables them.
    async with client.stream("GET", url, headers={"x-apikey": api_key},
                             follow_redirects=False, timeout=LOOKUP_TIMEOUT_SECONDS) as response:
        if response.status_code == 429:
            budget.cool_down(retry_delay(response.headers.get("retry-after")))
            raise IntelUnavailable("unavailable_provider_rate_limit")
        if response.status_code in (401, 403):
            raise IntelUnavailable("unavailable_provider_auth")
        if response.status_code == 404:
            raise IntelUnavailable("unavailable_no_report")
        if response.status_code != 200:
            raise IntelUnavailable("unavailable_provider_error")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise IntelUnavailable("unavailable_invalid_report")
        return json.loads(body)


class ThreatIntel:
    def __init__(self, client, api_key="", enabled=False, budget=None):
        self.client = client
        self._api_key = api_key
        self.enabled = enabled and bool(api_key.strip())
        self.budget = budget if budget is not None else _shared_budget

    async def enrich(self, indicators, own_ips):
        reports, evidence, lookups = [], [], 0
        seen = set()
        for kind, value in indicators[:12]:
            if not isinstance(kind, str) or not isinstance(value, str):
                continue
            if (kind, value) in seen:
                continue
            seen.add((kind, value))
            report: dict[str, object] = {"kind": kind, "value": value, "status": "unavailable"}
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
            unavailable = self.budget.reserve()
            if unavailable:
                report["status"] = unavailable
                continue
            lookups += 1
            resource = {"ip": "ip_addresses", "sha256": "files", "domain": "domains"}[kind]
            url = "https://www.virustotal.com/api/v3/" + resource + "/" + value
            try:
                reply = await asyncio.wait_for(fetch_report(
                    self.client, url, self._api_key, self.budget,
                ), timeout=LOOKUP_TIMEOUT_SECONDS)
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
            except IntelUnavailable as unavailable:
                report["status"] = str(unavailable)
            except (asyncio.TimeoutError, httpx.TimeoutException):
                report["status"] = "unavailable_provider_timeout"
            except (httpx.HTTPError, ValueError, RecursionError,
                    KeyError, TypeError, AttributeError, OverflowError, OSError):
                # Never echo provider bodies, error messages or keys to the model/UI.
                report["status"] = "unavailable_provider_error_or_no_report"
        return {"reports": reports, "evidence": evidence, "lookups": lookups}
