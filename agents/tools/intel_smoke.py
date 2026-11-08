"""One explicit VirusTotal report lookup, independent of OpenAI and the backend."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx
from dotenv import dotenv_values

AGENTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENTS))

from nightwatch_agents.intel import ThreatIntel, eligible


async def run(kind, indicator, live):
    if not eligible(kind, indicator):
        raise ValueError("Indicator is invalid or excluded from public lookups")
    if not live:
        print("Indicator format is eligible. No provider or OpenAI calls made.")
        return
    config = dotenv_values(AGENTS / ".env")
    key = config.get("VIRUSTOTAL_API_KEY") or ""
    if not key.strip():
        raise ValueError("Configure the provider key locally; never share it in chat")
    # This tool is one report GET only. It does not enable persistent live flags,
    # submit files/URLs, invoke OpenAI, modify MySQL or execute any action.
    async with httpx.AsyncClient(timeout=4, trust_env=False, follow_redirects=False) as client:
        result = await ThreatIntel(client, key, enabled=True).enrich([(kind, indicator)], set())
    print(json.dumps(result, indent=2).replace(key, "[REDACTED]"))
    if not result["evidence"]:
        print("No validated provider evidence available. No retry was made.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--kind", choices=("ip", "domain", "sha256"), required=True)
    parser.add_argument("--indicator", required=True)
    args = parser.parse_args()
    try:
        asyncio.run(run(args.kind, args.indicator, args.live))
    except Exception:
        print("Intel check stopped; sensitive diagnostics withheld. No automatic retry was made.")
        sys.exit(1)
