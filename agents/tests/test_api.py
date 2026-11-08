import asyncio
import copy
import importlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nightwatch_agents.app import create_app
from nightwatch_agents.contracts import RESULT_VALIDATOR

app_module = importlib.import_module("nightwatch_agents.app")
REPO = Path(__file__).resolve().parents[2]
AUTH = {"x-nightwatch-service-key": "offline-test-service-key"}


@pytest.fixture
def payload():
    alerts = json.loads((REPO / "web/tools/replay/samples/clinic-attack.json").read_text())
    return {"contract_version": "0.1", "incident_id": "offline-clinic-incident",
            "org_name": "Northfield Dental Clinic", "alert": alerts[1],
            "related_events": [alerts[0], *alerts[2:]]}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AGENT_SERVICE_KEY", AUTH["x-nightwatch-service-key"])
    with TestClient(create_app()) as client:
        yield client


def test_clinic_replay_round_trip(client, payload):
    original = copy.deepcopy(payload)
    response = client.post("/investigate", json=payload, headers=AUTH)
    assert response.status_code == 200
    result = response.json()
    RESULT_VALIDATOR.validate(result)
    assert result["incident_id"] == payload["incident_id"]
    assert result["verdict"] == "undetermined"
    assert result["severity"] == "critical"
    assert result["confidence"] == 0
    assert result["recommended_actions"] == []
    assert result["evidence"]
    assert all(e["source"] == "wazuh" for e in result["evidence"])
    assert "Fallback analysis" in result["summary"]
    assert "unavailable" in result["summary"]
    assert result["injection_detected"] is True
    assert "best-effort" in result["injection_notes"]
    assert [(r["agent"], r["status"], r["model"]) for r in result["agent_runs"]] == [
        (s, "skipped", None) for s in ("triage", "intel", "investigator")]
    assert payload == original


@pytest.mark.parametrize("headers", [{}, {"x-nightwatch-service-key": "wrong"},
                                    {"x-nightwatch-service-key": ""}])
def test_authentication_precedes_parsing(client, headers):
    assert client.post("/investigate", content="bad-json", headers=headers).status_code == 401


@pytest.mark.parametrize("key", [None, "", "  "])
def test_startup_requires_service_key(monkeypatch, key):
    if key is None:
        monkeypatch.delenv("AGENT_SERVICE_KEY", raising=False)
    else:
        monkeypatch.setenv("AGENT_SERVICE_KEY", key)
    with pytest.raises(RuntimeError, match="nonempty AGENT_SERVICE_KEY"):
        with TestClient(create_app()):
            pass


@pytest.mark.parametrize("field,value", [
    ("contract_version", "0.2"), ("incident_id", 123), ("org_name", None),
    ("alert", []), ("related_events", ["not-an-object"]), ("unexpected", "sensitive-marker"),
])
def test_rejects_invalid_contract(client, payload, field, value):
    payload[field] = value
    response = client.post("/investigate", json=payload, headers=AUTH)
    assert response.status_code == 422
    assert "sensitive-marker" not in response.text


def test_required_fields_and_empty_alert(client, payload):
    for field in payload:
        incomplete = {k: v for k, v in payload.items() if k != field}
        assert client.post("/investigate", json=incomplete, headers=AUTH).status_code == 422
    payload.update(alert={}, related_events=[])
    assert client.post("/investigate", json=payload, headers=AUTH).status_code == 200


@pytest.mark.parametrize("body", ["{", "NaN", '{"alert": Infinity}', '{"alert": 1e999}', b"\xff"])
def test_malformed_json(client, body):
    response = client.post("/investigate", content=body,
                           headers={**AUTH, "content-type": "application/json"})
    assert response.status_code == 400


def test_media_type_and_body_limit(client):
    assert client.post("/investigate", content="{}", headers=AUTH).status_code == 415
    response = client.post("/investigate", content=b" " * (app_module.MAX_BODY_BYTES + 1),
                           headers={**AUTH, "content-type": "application/json"})
    assert response.status_code == 413


@pytest.mark.parametrize("failure", ["extra", "incident", "date", "confidence", "exception"])
def test_bad_service_output_is_never_returned(client, payload, monkeypatch, failure):
    original = app_module.investigate

    async def bad_service(request):
        if failure == "exception":
            raise RuntimeError("sensitive-marker")
        result = await original(request)
        if failure == "extra":
            result["sensitive-marker"] = True
        elif failure == "incident":
            result["incident_id"] = "another-incident"
        elif failure == "date":
            result["agent_runs"][0]["finished_at"] = "invalid"
        else:
            result["confidence"] = True  # JSON Schema numbers exclude booleans.
        return result

    monkeypatch.setattr(app_module, "investigate", bad_service)
    response = client.post("/investigate", json=payload, headers=AUTH)
    assert response.status_code == 200
    result = response.json()
    RESULT_VALIDATOR.validate(result)
    assert result["incident_id"] == payload["incident_id"]
    assert result["verdict"] == "undetermined"
    assert result["recommended_actions"] == []
    assert result["agent_runs"] == []  # Unknown stage outcomes are never invented.
    assert "sensitive-marker" not in response.text


def test_deadline(client, payload, monkeypatch):
    async def slow(request):
        await asyncio.sleep(1)
    monkeypatch.setattr(app_module, "investigate", slow)
    monkeypatch.setattr(app_module, "SERVICE_TIMEOUT_SECONDS", 0.01)
    response = client.post("/investigate", json=payload, headers=AUTH)
    assert response.status_code == 200
    RESULT_VALIDATOR.validate(response.json())
    assert "service deadline" in response.json()["summary"]
