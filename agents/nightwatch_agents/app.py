"""Authenticated HTTP boundary. Never include request values in error responses."""

import asyncio
import hmac
import json
import math
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .contracts import REQUEST_VALIDATOR, RESULT_VALIDATOR, SCHEMA
from .fallback import fallback_result
from .service import investigate

MAX_BODY_BYTES = 2 * 1024 * 1024
SERVICE_TIMEOUT_SECONDS = 75  # Leave margin beneath the backend's 90 seconds.


def reject_nonfinite(value):
    raise ValueError("Non-finite JSON number")


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Non-finite JSON number")
    return result


def create_app():
    @asynccontextmanager
    async def lifespan(app):
        # Model credentials are read only by the explicitly enabled workflow.
        key = os.environ.get("AGENT_SERVICE_KEY", "")
        if not key.strip():
            raise RuntimeError("Set a nonempty AGENT_SERVICE_KEY before starting the service.")
        app.state.service_key = key.encode("utf-8")
        yield
        app.state.service_key = None

    app = FastAPI(title="Nightwatch agent service", version="0.1", lifespan=lifespan)

    @app.post("/investigate", openapi_extra={
        "requestBody": {"required": True, "content": {
            "application/json": {"schema": SCHEMA["$defs"]["request"]}}},
    })
    async def investigate_route(request: Request):
        supplied = request.headers.get("x-nightwatch-service-key", "").encode("utf-8")
        if not hmac.compare_digest(supplied, app.state.service_key):
            raise HTTPException(401, "Invalid service credential")
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Expected application/json")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BODY_BYTES:
                raise HTTPException(413, "Request exceeds 2 MiB service limit")
        try:
            payload = json.loads(body, parse_constant=reject_nonfinite, parse_float=finite_float)
            valid = REQUEST_VALIDATOR.is_valid(payload)
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPException(400, "Malformed JSON") from None
        if not valid:
            raise HTTPException(422, "Request does not match investigation contract v0.1")
        try:
            result = await asyncio.wait_for(investigate(payload), SERVICE_TIMEOUT_SECONDS)
            if not RESULT_VALIDATOR.is_valid(result) or result["incident_id"] != payload["incident_id"]:
                raise ValueError("Invalid investigation result")
            return JSONResponse(result)
        except asyncio.TimeoutError:
            return JSONResponse(fallback_result(payload, "service_deadline"))
        except Exception:
            # Do not expose logs, credentials, provider errors or generated content.
            return JSONResponse(fallback_result(payload, "invalid_service_result"))

    return app


app = create_app()
