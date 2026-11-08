"""TEST ONLY: explicit deterministic SOC responses, never a production demo mode."""

import importlib
import os

import httpx

from nightwatch_agents.intel import ThreatIntel
from nightwatch_agents.workflow import FINAL_SCHEMA, run_workflow


class ReplayModel:
    model = "integration-mock-model"

    async def generate(self, instructions, data, schema):
        field = next(f for f in data["records"] if f["ref"] == "/alert/rule/description")
        quotes = [{"ref": field["ref"], "quote": field["text"]}]
        if schema != FINAL_SCHEMA:
            return {"assessment": "MOCK: logon failures require review.", "quotes": quotes}
        if os.environ["NW_INTEGRATION_SCENARIO"] == "invalid-output":
            quotes[0]["quote"] = "invented observation not in any log"
        return {
            "title": "MOCK integration investigation",
            "summary": "MOCK: the replay logs report logon failures and a PowerShell download command. Verify authorization.",
            "severity": "critical", "verdict": "suspicious", "confidence": 0.6,
            "quotes": quotes,
            "recommended_actions": [{"type": "block_ip", "target": "192.168.8.66",
                                     "rationale": "MOCK: observed source IP; approval required."}],
        }


def create_test_app():
    module = importlib.import_module("nightwatch_agents.app")
    scenario = os.environ["NW_INTEGRATION_SCENARIO"]
    if scenario not in {"offline", "success", "invalid-output"}:
        raise RuntimeError("Unknown integration scenario")
    if scenario != "offline":
        async def investigate(request):
            def no_provider_network(request):
                raise AssertionError("Integration tests must never contact a provider")

            async with httpx.AsyncClient(transport=httpx.MockTransport(no_provider_network)) as client:
                return await run_workflow(request, ReplayModel(), ThreatIntel(client))

        # This replacement exists only in this test subprocess. Production code
        # has no switch that enables fabricated model or provider responses.
        setattr(module, "investigate", investigate)
    return module.create_app()
