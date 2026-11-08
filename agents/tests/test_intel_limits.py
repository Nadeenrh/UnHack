import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from nightwatch_agents.context import build_context
from nightwatch_agents.intel import ThreatIntel, retry_delay
from nightwatch_agents.intel_limits import IntelBudget


class Clock:
    value = 0.0

    def __call__(self):
        return self.value


def report(request):
    value = request.url.path.rsplit("/", 1)[1]
    kind = "ip_address" if "/ip_addresses/" in request.url.path else "file"
    return httpx.Response(200, json={"data": {"id": value, "type": kind, "attributes": {
        "last_analysis_date": 1700000000,
        "last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 3}}}})


def test_concurrent_reservations_are_atomic_and_minute_rolls():
    clock = Clock()
    budget = IntelBudget(clock)
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: budget.reserve(), range(20)))
    assert results.count(None) == 4
    assert results.count("unavailable_minute_limit") == 16
    clock.value = 59.99
    assert budget.reserve() == "unavailable_minute_limit"
    clock.value = 60
    assert budget.reserve() is None


def test_rolling_day_does_not_reset_at_a_calendar_boundary():
    clock = Clock()
    budget = IntelBudget(clock)
    for _ in range(125):
        for _ in range(4):
            assert budget.reserve() is None
        clock.value += 60
    assert budget.reserve() == "unavailable_daily_limit"
    clock.value = 86400
    assert budget.reserve() is None


def test_different_adapters_share_the_process_budget():
    calls = []

    def handler(request):
        calls.append(request)
        return report(request)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            results = await asyncio.gather(*[
                ThreatIntel(client, "fake", True).enrich([("ip", "8.8.8.8")], set()) for _ in range(8)
            ])
        assert len(calls) == 4
        assert sum(r["lookups"] for r in results) == 4
        assert sum(bool(r["evidence"]) for r in results) == 4
        assert all(r["evidence"] or r["reports"][0]["status"] == "unavailable_minute_limit" for r in results)
    asyncio.run(scenario())


def test_duplicate_indicators_only_lookup_once_per_investigation():
    calls = []

    def handler(request):
        calls.append(request)
        return report(request)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await ThreatIntel(client, "fake", True).enrich([("ip", "8.8.8.8")] * 8, set())
        assert len(calls) == result["lookups"] == len(result["reports"]) == len(result["evidence"]) == 1
    asyncio.run(scenario())


def test_429_cooldown_is_shared_and_never_waits_or_retries():
    clock = Clock()
    budget = IntelBudget(clock)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"retry-after": "120"}, json={"error": "sensitive-marker"})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            first = await ThreatIntel(client, "fake", True, budget).enrich([("ip", "8.8.8.8")], set())
            second = await ThreatIntel(client, "fake", True, budget).enrich([("ip", "1.1.1.1")], set())
        assert len(calls) == 1
        assert first["reports"][0]["status"] == "unavailable_provider_rate_limit"
        assert second["reports"][0]["status"] == "unavailable_provider_cooldown"
        assert second["lookups"] == 0
        assert first["evidence"] == second["evidence"] == []
        assert "sensitive-marker" not in json.dumps([first, second])
    asyncio.run(scenario())
    clock.value = 119
    assert budget.reserve() == "unavailable_provider_cooldown"
    clock.value = 120
    assert budget.reserve() is None


@pytest.mark.parametrize("status,label", [(401, "auth"), (403, "auth"), (404, "no_report"),
                                         (500, "error"), (302, "error")])
def test_provider_statuses_never_imply_a_clean_report(status, label):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"location": "http://127.0.0.1/secret"},
                              json={"error": "sensitive-marker"})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
            result = await ThreatIntel(client, "fake", True).enrich([("ip", "8.8.8.8")], set())
        assert len(calls) == 1
        expected = "unavailable_no_report" if label == "no_report" else "unavailable_provider_" + label
        assert result["reports"][0]["status"] == expected
        assert result["evidence"] == []
        assert "sensitive-marker" not in json.dumps(result)
    asyncio.run(scenario())


@pytest.mark.parametrize("value,expected", [(None, 60), ("invalid", 60), ("0", 1),
                                           ("120", 120), ("99999999", 86400)])
def test_retry_after_is_bounded(value, expected):
    assert retry_delay(value) == expected


def test_retry_after_http_date():
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=90), usegmt=True)
    assert 87 <= retry_delay(future) <= 90


def test_sysmon_sha256_extraction():
    digest = "AB" * 32
    context = build_context({"alert": {"data": {"win": {"eventdata": {
        "hashes": "MD5=" + "a" * 32 + ",SHA256=" + digest + ",IMPHASH=" + "c" * 32}}}},
        "related_events": []})
    assert context["indicators"] == [("sha256", digest.lower())]


def test_disabled_or_private_reports_do_not_use_quota():
    clock = Clock()
    budget = IntelBudget(clock)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("No lookup permitted"))) as client:
            await ThreatIntel(client, "fake", False, budget).enrich([("ip", "8.8.8.8")], set())
            await ThreatIntel(client, "fake", True, budget).enrich([("ip", "192.168.8.66")], set())
        assert all(budget.reserve() is None for _ in range(4))
    asyncio.run(scenario())
