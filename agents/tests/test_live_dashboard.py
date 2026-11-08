"""Offline tests for the gate that bounds the manually authorized dashboard test."""

import asyncio
import copy

import pytest

from nightwatch_agents.contracts import RESULT_VALIDATOR
from nightwatch_agents.model import ModelFailure
from nightwatch_agents.workflow import FINAL_SCHEMA
from tools.live_dashboard import SingleInvestigation, prepare_alerts


class LocalModel:
    model = "offline-only-gate-test"

    def __init__(self, failure=False, cancel=False):
        self.calls = 0
        self.failure = failure
        self.cancel = cancel

    async def generate(self, instructions, data, schema):
        self.calls += 1
        if self.cancel:
            raise asyncio.CancelledError()
        if self.failure:
            raise ModelFailure("simulated failure")
        await asyncio.sleep(0.01)
        field = next(f for f in data["records"] if f["ref"] == "/alert/rule/description")
        quotes = [{"ref": field["ref"], "quote": field["text"]}]
        if schema != FINAL_SCHEMA:
            return {"assessment": "Offline triage", "quotes": quotes}
        return {"title": "Offline gate test", "summary": "Verify the reported events.",
                "severity": "high", "verdict": "suspicious", "confidence": 0.5,
                "quotes": quotes, "recommended_actions": []}


class LocalIntel:
    async def enrich(self, indicators, own_ips):
        return {"reports": [], "evidence": [], "lookups": 0}


def sample_request(alerts):
    return {"contract_version": "0.1", "incident_id": "gate-test",
            "org_name": "Northfield Dental Clinic", "alert": alerts[1],
            "related_events": [alerts[3], alerts[0], alerts[2]]}


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(org_name="Another clinic"),
    lambda r: r["alert"].update(id="unexpected-alert"),
    lambda r: r["alert"]["rule"].update(description="unexpected text"),
    lambda r: r["related_events"].pop(),
    lambda r: r["related_events"].append(copy.deepcopy(r["related_events"][0])),
])
def test_unapproved_payload_does_not_consume_slot(mutation):
    async def scenario():
        alerts, _ = prepare_alerts()
        model = LocalModel()
        gate = SingleInvestigation(alerts, model, LocalIntel())
        request = sample_request(copy.deepcopy(alerts))
        mutation(request)
        result = await gate(request)
        RESULT_VALIDATOR.validate(result)
        assert result["verdict"] == "undetermined"
        assert gate.used is False
        assert model.calls == 0
    asyncio.run(scenario())


def test_concurrent_requests_only_allow_one_live_investigation():
    async def scenario():
        alerts, _ = prepare_alerts()
        model = LocalModel()
        gate = SingleInvestigation(alerts, model, LocalIntel())
        results = await asyncio.gather(gate(sample_request(alerts)), gate(sample_request(alerts)))
        for result in results:
            RESULT_VALIDATOR.validate(result)
        assert sorted(r["verdict"] for r in results) == ["suspicious", "undetermined"]
        assert model.calls == 2
        assert gate.used is True
        again = await gate(sample_request(alerts))
        assert again["verdict"] == "undetermined"
        assert model.calls == 2
    asyncio.run(scenario())


@pytest.mark.parametrize("cancel", [False, True])
def test_failed_or_cancelled_test_cannot_restart(cancel):
    async def scenario():
        alerts, _ = prepare_alerts()
        model = LocalModel(failure=not cancel, cancel=cancel)
        gate = SingleInvestigation(alerts, model, LocalIntel())
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await gate(sample_request(alerts))
        else:
            assert (await gate(sample_request(alerts)))["verdict"] == "undetermined"
        assert gate.used is True
        assert (await gate(sample_request(alerts)))["verdict"] == "undetermined"
        assert model.calls == 1
    asyncio.run(scenario())
