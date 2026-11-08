"""Explicit single-investigation demo through the real local backend and MySQL.

No persistent live flag is enabled. This temporary service accepts live analysis
only for the exact four prepared sample alerts and only once. All other requests
receive offline fallback. The backend URL is restored when the command finishes.
"""

import argparse
import asyncio
import importlib
import json
import logging
import os
import re
import secrets
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import uvicorn
from dotenv import dotenv_values, set_key, unset_key

AGENTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENTS))

from nightwatch_agents import model as model_module
from nightwatch_agents.fallback import fallback_result
from nightwatch_agents.intel import ThreatIntel
from nightwatch_agents.model import DEFAULT_MODEL, OpenAIModel
from nightwatch_agents.workflow import run_workflow
from tools.live_smoke import INPUT_USD_PER_MILLION, OUTPUT_USD_PER_MILLION, PLANNED_CEILING_USD


class SingleInvestigation:
    def __init__(self, expected_alerts, model, intel):
        self.expected = {alert["id"]: alert for alert in expected_alerts}
        self.model = model
        self.intel = intel
        self.used = False
        self.result = None

    async def __call__(self, request):
        events = [request["alert"], *request["related_events"]]
        matching_sample = (
            request["org_name"] == "Northfield Dental Clinic"
            and len(events) == len(self.expected)
            and all(isinstance(event.get("id"), str) for event in events)
            and {event["id"] for event in events} == set(self.expected)
            and all(event == self.expected.get(event["id"]) for event in events)
        )
        if self.used or not matching_sample:
            return fallback_result(request, "live_calls_disabled")
        # Consume the slot before the first await: concurrent requests cannot
        # launch another investigation, even if this one fails or is cancelled.
        self.used = True
        self.result = await run_workflow(request, self.model, self.intel)
        return self.result


def prepare_alerts():
    alerts = json.loads((AGENTS.parent / "web/tools/replay/samples/clinic-attack.json").read_text())
    suffix = secrets.token_hex(4)
    host = "RECEPTION-PC-AI-TEST-" + suffix
    anchor = datetime.now(timezone.utc)
    def parse_time(value):
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value).replace("Z", "+00:00")
        return datetime.fromisoformat(value)

    first = parse_time(alerts[0]["timestamp"])
    for alert in alerts:
        original_time = parse_time(alert["timestamp"])
        alert["id"] += "-ai-test-" + suffix
        alert["timestamp"] = (anchor + (original_time - first)).isoformat().replace("+00:00", "Z")
        alert["agent"]["name"] = host
        win = alert.get("data", {}).get("win", {})
        if "computer" in win.get("system", {}):
            win["system"]["computer"] = host
        if "user" in win.get("eventdata", {}):
            win["eventdata"]["user"] = win["eventdata"]["user"].replace("RECEPTION-PC", host)
    return alerts, host


async def run(budget):
    if not PLANNED_CEILING_USD <= budget <= 0.25:
        raise ValueError("Budget does not meet the approved bounds")
    agent_config = dotenv_values(AGENTS / ".env")
    web_file = AGENTS.parent / "web/.env.local"
    web_config = dotenv_values(web_file)
    if any((agent_config.get(name) or "false").lower() == "true" for name in (
            "NIGHTWATCH_LIVE_CALLS_ENABLED", "NIGHTWATCH_INTEL_ENABLED")):
        raise ValueError("Keep persistent live flags disabled")
    if web_config.get("EXECUTOR_MODE") != "simulate":
        raise ValueError("Backend must be configured for simulated execution")
    shared = agent_config.get("AGENT_SERVICE_KEY")
    if not shared or shared != web_config.get("AGENT_SERVICE_KEY"):
        raise ValueError("Local service credentials must match")
    key = agent_config.get("OPENAI_API_KEY") or ""
    if not key.startswith("sk-") or "..." in key or any(c.isspace() for c in key):
        raise ValueError("Complete local API key required; value withheld")
    if agent_config.get("OPENAI_MODEL") != DEFAULT_MODEL:
        raise ValueError("Verified model snapshot required")
    alerts, host = prepare_alerts()
    usage, statuses = [], []
    sent = 0

    async def guard_request(request):
        nonlocal sent
        if str(request.url) != "https://api.openai.com/v1/responses" or request.method != "POST" or sent >= 2:
            raise ValueError("Outbound request outside approved bounds")
        sent += 1

    async def note_status(response):
        statuses.append(response.status_code)

    original_reader = model_module.bounded_json

    async def metered_reader(*args, **kwargs):
        reply = await original_reader(*args, **kwargs)
        counts = {name: reply.get("usage", {}).get(name) for name in ("input_tokens", "output_tokens")}
        if all(type(value) is int and value >= 0 for value in counts.values()):
            usage.append(counts)
        return reply

    model_module.bounded_json = metered_reader
    original_key = os.environ.get("AGENT_SERVICE_KEY")
    os.environ["AGENT_SERVICE_KEY"] = shared  # Service credential only; never the API key.
    original_url = web_config.get("AGENT_SERVICE_URL")
    server = None
    task = None
    listener = None
    temporary_url = None
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=25, trust_env=False, follow_redirects=False,
                                     event_hooks={"request": [guard_request], "response": [note_status]}) as provider:
            gate = SingleInvestigation(alerts, OpenAIModel(provider, key, DEFAULT_MODEL),
                                       ThreatIntel(provider, enabled=False))
            app_module = importlib.import_module("nightwatch_agents.app")
            setattr(app_module, "investigate", gate)
            app = app_module.create_app()
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            temporary_url = "http://127.0.0.1:" + str(listener.getsockname()[1])
            server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
            task = asyncio.create_task(server.serve(sockets=[listener]))
            for _ in range(100):
                if server.started:
                    break
                if task.done():
                    raise RuntimeError("Temporary service did not start")
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("Temporary service startup deadline exceeded")
            async with httpx.AsyncClient(base_url="http://localhost:3000", timeout=30,
                                         trust_env=False, follow_redirects=False) as web:
                login = await web.post("/api/v1/auth/login", headers={"origin": "http://localhost:3000"},
                                       json={"email": "leah@northfield.test", "password": "pass123"})
                login.raise_for_status()
                memberships = login.json()["data"]["memberships"]
                org = next(m["org_id"] for m in memberships if m["org_name"] == "Northfield Dental Clinic")
                policy_response = await web.get(f"/api/v1/orgs/{org}/policies")
                policy_response.raise_for_status()
                policies = policy_response.json()["data"]
                if next(p["mode"] for p in policies if p["action_type"] == "block_ip") != "ask":
                    raise ValueError("The sample block action must require human approval")
                set_key(str(web_file), "AGENT_SERVICE_URL", temporary_url)
                # Let Next dev load the new local setting before ingestion.
                await asyncio.sleep(3)
                print("Submitting one batch of four sample alerts; one live investigation slot available.", flush=True)
                ingest = await web.post("/api/v1/ingest/wazuh", headers={
                    "authorization": "Bearer nwk_dev_northfield_0001", "x-nightwatch-replay": "1"}, json=alerts)
                ingest.raise_for_status()
                incidents = ingest.json()["data"]["incidents"]
                if len(incidents) != 1 or not incidents[0]["created"]:
                    raise RuntimeError("Expected one new isolated sample incident")
                incident_id = incidents[0]["id"]
                found = None
                for _ in range(45):
                    response = await web.get(f"/api/v1/orgs/{org}/incidents/{incident_id}")
                    response.raise_for_status()
                    found = response.json()["data"]
                    if found["agent_runs"]:
                        break
                    await asyncio.sleep(2)
                if found is None or not found["agent_runs"]:
                    raise RuntimeError("Investigation persistence deadline exceeded")
                page_url = f"http://localhost:3000/app/{org}/incidents/{incident_id}"
                page = await web.get(page_url)
                page.raise_for_status()
                input_tokens = sum(item["input_tokens"] for item in usage)
                output_tokens = sum(item["output_tokens"] for item in usage)
                report = {
                    "ref": found["ref"], "url": page_url, "sample_host": host,
                    "live_slot_consumed": gate.used, "requests_sent": sent, "http_statuses": statuses,
                    "input_tokens": input_tokens, "output_tokens": output_tokens,
                    "estimated_cost_usd": round((input_tokens * INPUT_USD_PER_MILLION +
                                                 output_tokens * OUTPUT_USD_PER_MILLION) / 1_000_000, 6)
                    if len(usage) == sent else None,
                    "elapsed_seconds": round(time.monotonic() - started, 2),
                    "title": found["title"], "summary": found["summary"],
                    "severity": found["severity"], "verdict": found["verdict"], "confidence": found["confidence"],
                    "data_source": found["data_source"], "injection_detected": found["injection_detected"],
                    "evidence_count": len(found["evidence"]),
                    "agent_runs": [{"agent": r["agent"], "status": r["status"], "model": r["model"]}
                                   for r in found["agent_runs"]],
                    "actions": [{"id": a["id"], "type": a["type"], "target": a["target"],
                                 "policy_decision": a["policy_decision"], "status": a["status"],
                                 "result": a["result"]} for a in found["actions"]],
                    "dashboard_checks": {
                        "http_200": page.status_code == 200, "replay_label": "Replay" in page.text,
                        "model_name": DEFAULT_MODEL in page.text,
                        "injection_warning": "Someone tried to trick the AI" in page.text,
                    },
                }
                print(json.dumps(report, indent=2).replace(key, "[REDACTED]"), flush=True)
    finally:
        current = dotenv_values(web_file).get("AGENT_SERVICE_URL")
        if temporary_url is not None and current == temporary_url:
            if original_url is None:
                unset_key(str(web_file), "AGENT_SERVICE_URL")
            else:
                set_key(str(web_file), "AGENT_SERVICE_URL", original_url)
        if server is not None:
            server.should_exit = True
        if task is not None:
            await task
        if listener is not None:
            listener.close()
        model_module.bounded_json = original_reader
        if original_key is None:
            os.environ.pop("AGENT_SERVICE_KEY", None)
        else:
            os.environ["AGENT_SERVICE_KEY"] = original_key
        print("Temporary live service stopped; original backend URL restored where unchanged externally.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", required=True)
    parser.add_argument("--budget-usd", type=float, default=0.25)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(run(args.budget_usd))
    except Exception:
        print("Dashboard test stopped; sensitive diagnostics withheld. No automatic retry was made.")
        sys.exit(1)
