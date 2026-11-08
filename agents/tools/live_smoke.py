"""One explicitly enabled clinic-sample investigation; no persistence or execution.

Run from agents/: .venv/bin/python tools/live_smoke.py --check
Paid test:        .venv/bin/python tools/live_smoke.py --live --budget-usd 0.25
The key is read from agents/.env only into this process, never logged or copied.
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

import httpx
from dotenv import dotenv_values

AGENTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENTS))

from nightwatch_agents import model as model_module
from nightwatch_agents.contracts import REQUEST_VALIDATOR, RESULT_VALIDATOR
from nightwatch_agents.intel import ThreatIntel
from nightwatch_agents.model import DEFAULT_MODEL, MAX_INPUT_BYTES, MAX_OUTPUT_TOKENS, OpenAIModel
from nightwatch_agents.workflow import run_workflow

# Standard uncached prices verified against official model docs on 2026-11-07.
INPUT_USD_PER_MILLION = 0.75
OUTPUT_USD_PER_MILLION = 4.50
MAX_REQUESTS = 2
# Conservative planning reserve for API framing in addition to bounded input bytes.
# This is an estimate at the verified rates, not an account-wide spending limit.
PLANNED_CEILING_USD = MAX_REQUESTS * (
    (MAX_INPUT_BYTES + 4096) * INPUT_USD_PER_MILLION
    + MAX_OUTPUT_TOKENS * OUTPUT_USD_PER_MILLION
) / 1_000_000


async def run(live, budget):
    if not 0 < budget <= 0.25 or PLANNED_CEILING_USD > budget:
        raise ValueError("Budget must cover the planning estimate and cannot exceed US$0.25")
    config = dotenv_values(AGENTS / ".env")
    if (config.get("NIGHTWATCH_LIVE_CALLS_ENABLED") or "false").lower() == "true":
        raise ValueError("Keep automatic live calls disabled before this isolated test")
    if (config.get("NIGHTWATCH_INTEL_ENABLED") or "false").lower() == "true":
        raise ValueError("Keep public intelligence disabled before this test")
    selected_model = config.get("OPENAI_MODEL") or DEFAULT_MODEL
    if selected_model != DEFAULT_MODEL:
        raise ValueError("This priced smoke test requires the verified default model snapshot")
    key = config.get("OPENAI_API_KEY") or ""
    if not key.startswith("sk-") or len(key) < 20 or any(c.isspace() for c in key) or "..." in key:
        raise ValueError("A complete API key must be configured locally; value withheld")
    alerts = json.loads((AGENTS.parent / "web/tools/replay/samples/clinic-attack.json").read_text())
    request = {"contract_version": "0.1", "incident_id": "one-shot-clinic-smoke-test",
               "org_name": "Clinic replay sample", "alert": alerts[1],
               "related_events": [alerts[0], *alerts[2:]]}
    REQUEST_VALIDATOR.validate(request)
    print("Local preflight passed; the key value is withheld.", flush=True)
    print(f"Planning estimate ceiling: US${PLANNED_CEILING_USD:.6f}; allowance: US${budget:.2f}.", flush=True)
    if not live:
        print("Check only: no network calls made.")
        return

    usage, statuses = [], []
    sent = 0
    original_reader = model_module.bounded_json

    async def guard_request(outbound):
        nonlocal sent
        if (str(outbound.url) != "https://api.openai.com/v1/responses"
                or outbound.method != "POST" or sent >= MAX_REQUESTS):
            raise ValueError("Unexpected request or test request limit reached")
        sent += 1

    async def note_status(response):
        statuses.append(response.status_code)

    async def metered_reader(*args, **kwargs):
        reply = await original_reader(*args, **kwargs)
        raw = reply.get("usage", {})
        counts = {name: raw.get(name) for name in ("input_tokens", "output_tokens")}
        if all(type(v) is int and v >= 0 for v in counts.values()):
            usage.append(counts)
        return reply

    model_module.bounded_json = metered_reader
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=25, trust_env=False, follow_redirects=False,
                                     event_hooks={"request": [guard_request], "response": [note_status]}) as client:
            model = OpenAIModel(client, key, selected_model)
            # Direct workflow call: no web ingestion, database, action executor,
            # persistent live setting, reputation lookups or subsequent reruns.
            result = await run_workflow(request, model, ThreatIntel(client, enabled=False))
        RESULT_VALIDATOR.validate(result)
    finally:
        model_module.bounded_json = original_reader
    input_tokens = sum(item["input_tokens"] for item in usage)
    output_tokens = sum(item["output_tokens"] for item in usage)
    estimate = (input_tokens * INPUT_USD_PER_MILLION + output_tokens * OUTPUT_USD_PER_MILLION) / 1_000_000
    report = {
        "requests_sent": sent, "http_statuses": statuses,
        "usage_records_received": len(usage), "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "estimated_cost_usd_at_standard_rates": round(estimate, 6) if len(usage) == sent else None,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "title": result["title"], "summary": result["summary"],
        "severity": result["severity"], "verdict": result["verdict"], "confidence": result["confidence"],
        "injection_detected": result["injection_detected"],
        "evidence": [{"claim": e["claim"], "log_ref": e["log_ref"]} for e in result["evidence"]],
        "recommended_actions": result["recommended_actions"],
        "agent_runs": [{"agent": r["agent"], "status": r["status"], "model": r["model"]}
                       for r in result["agent_runs"]],
    }
    print(json.dumps(report, indent=2).replace(key, "[REDACTED]"))
    if len(usage) != sent:
        print("Complete usage was unavailable; check the OpenAI usage dashboard. No automatic retry will run.")
    print("Test stopped. No actions executed or results persisted; automatic live calls remain disabled.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--budget-usd", type=float, default=0.25)
    args = parser.parse_args()
    try:
        asyncio.run(run(args.live, args.budget_usd))
    except Exception:
        # Never expose dotenv values, provider errors, headers or tracebacks.
        print("Test could not complete; sensitive diagnostics withheld. No automatic retry was made.")
        sys.exit(1)
