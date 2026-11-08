"""Request-scoped workflow selection. Live calls require explicit opt-in."""

import os

import httpx

from .fallback import fallback_result
from .intel import ThreatIntel
from .model import DEFAULT_MODEL, OpenAIModel
from .workflow import run_workflow


async def investigate(request):
    # Check the opt-in BEFORE reading API keys or constructing network clients.
    if os.environ.get("NIGHTWATCH_LIVE_CALLS_ENABLED", "false").lower() != "true":
        return await offline_result(request)
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False, trust_env=False) as client:
            model = OpenAIModel(client, os.environ.get("OPENAI_API_KEY", ""),
                                os.environ.get("OPENAI_MODEL", DEFAULT_MODEL))
            intel_enabled = os.environ.get("NIGHTWATCH_INTEL_ENABLED", "false").lower() == "true"
            intel = ThreatIntel(client, os.environ.get("VIRUSTOTAL_API_KEY", "") if intel_enabled else "",
                                enabled=intel_enabled)
            return await run_workflow(request, model, intel)
    except Exception:
        # Workflow failures are handled with stage progress inside run_workflow.
        # This covers configuration/client setup without exposing exception values.
        return fallback_result(request, "configuration_unavailable")


async def offline_result(request):
    return fallback_result(request, "live_calls_disabled")
