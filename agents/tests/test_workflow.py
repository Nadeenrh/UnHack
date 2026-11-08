import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from nightwatch_agents.app import create_app
from nightwatch_agents.context import build_context, evidence_from_quotes
from nightwatch_agents.contracts import RESULT_VALIDATOR
from nightwatch_agents.intel import ThreatIntel, eligible
from nightwatch_agents.model import DEFAULT_MODEL, MAX_INPUT_BYTES, ModelFailure, OpenAIModel
from nightwatch_agents.workflow import FINAL_SCHEMA, TRIAGE_SCHEMA, run_workflow


@pytest.fixture
def request_data():
    sample = Path(__file__).resolve().parents[2] / "web/tools/replay/samples/clinic-attack.json"
    alerts = json.loads(sample.read_text())
    return {"contract_version": "0.1", "incident_id": "offline-incident",
            "org_name": "Clinic", "alert": alerts[1],
            "related_events": [alerts[0], *alerts[2:]]}


def analysis(data, final=False):
    field = next(f for f in data["records"] if f["ref"] == "/alert/rule/description")
    quotes = [{"ref": field["ref"], "quote": field["text"]}]
    if not final:
        return {"assessment": "Repeated logon failures require review.", "quotes": quotes}
    return {"title": "Logon failures followed by a download command",
            "summary": "The logs report failed logons and a PowerShell download command. Verify whether access was authorized.",
            "severity": "high", "verdict": "suspicious", "confidence": 0.6,
            "quotes": quotes, "recommended_actions": [{"type": "block_ip", "target": "192.168.8.66",
                                                       "rationale": "Observed source of repeated failures; review before approval."}]}


class FakeModel:
    model = "offline-fake-model"

    def __init__(self, mutate=None):
        self.inputs = []
        self.mutate = mutate

    async def generate(self, instructions, data, schema):
        self.inputs.append((instructions, copy.deepcopy(data)))
        final = schema == FINAL_SCHEMA
        result = analysis(data, final)
        if final and self.mutate:
            self.mutate(result)
        return result


def test_two_analysts_three_stages(request_data):
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("No public lookup expected"))) as client:
            model = FakeModel()
            original = copy.deepcopy(request_data)
            result = await run_workflow(request_data, model, ThreatIntel(client, "fake", enabled=True))
            RESULT_VALIDATOR.validate(result)
            assert request_data == original
            assert len(model.inputs) == 2
            assert [(r["agent"], r["status"]) for r in result["agent_runs"]] == [
                ("triage", "succeeded"), ("intel", "skipped"), ("investigator", "succeeded")]
            assert result["agent_runs"][1]["model"] is None
            assert result["injection_detected"] is True
            assert "unavailable" in result["summary"]
            assert result["evidence"][0]["log_ref"] == "/alert/rule/description"
            assert all(e["source"] == "wazuh" for e in result["evidence"])
            assert result["recommended_actions"][0]["target"] == "192.168.8.66"
            assert {t["technique_id"] for t in result["mitre"]} == {"T1110", "T1078", "T1059.001", "T1105"}
            assert all("UNTRUSTED DATA" in prompt for prompt, _ in model.inputs)
    asyncio.run(scenario())


@pytest.mark.parametrize("mutation", [
    lambda r: r["quotes"][0].update(ref="/alert/missing"),
    lambda r: r["quotes"][0].update(quote="214 passwords tried"),
    lambda r: r["recommended_actions"][0].update(target="8.8.8.8"),
    lambda r: r["recommended_actions"][0].update(target="192.168.8.20"),
    lambda r: r["recommended_actions"][0].update(type="isolate_host"),
    lambda r: r["recommended_actions"][0].update(type="notify_only", target="other-incident"),
    lambda r: r.update(summary="VirusTotal says this is known malicious."),
    lambda r: r.update(evidence=[{"source": "virustotal", "claim": "fake report"}]),
    lambda r: r.update(confidence=True),
])
def test_rejects_fabricated_evidence_or_unsafe_actions(request_data, mutation):
    async def scenario():
        async with httpx.AsyncClient() as client:
            result = await run_workflow(request_data, FakeModel(mutation), ThreatIntel(client))
            RESULT_VALIDATOR.validate(result)
            assert result["verdict"] == "undetermined"
            assert result["recommended_actions"] == []
            assert "Fallback analysis" in result["summary"]
            assert [r["status"] for r in result["agent_runs"]] == ["succeeded", "skipped", "failed"]
    asyncio.run(scenario())


def test_missing_or_invalid_evidence_timestamp(request_data):
    request_data["alert"]["timestamp"] = "invalid"
    context = build_context(request_data)
    with pytest.raises(ValueError):
        evidence_from_quotes([{"ref": "/alert/rule/description", "quote": "Multiple Windows logon failures."}], context)


def test_workflow_appends_only_actual_provider_evidence(request_data):
    request_data["alert"]["data"]["srcip"] = "8.8.8.8"

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json=vt_reply()))) as client:
            result = await run_workflow(request_data, FakeModel(), ThreatIntel(client, "fake", True))
            RESULT_VALIDATOR.validate(result)
            assert result["agent_runs"][1]["status"] == "succeeded"
            reports = [e for e in result["evidence"] if e["source"] == "virustotal"]
            assert len(reports) == 1
            assert "2 malicious" in reports[0]["claim"]
            assert reports[0]["claim"] in result["summary"]
            assert "Some indicator enrichment was skipped" in result["summary"]
    asyncio.run(scenario())


def test_disabled_mode_does_not_read_provider_keys_or_create_clients(request_data, monkeypatch):
    import nightwatch_agents.service as service
    original_get = service.os.environ.get

    def checked_get(name, *args):
        assert name not in ("OPENAI_API_KEY", "VIRUSTOTAL_API_KEY")
        return original_get(name, *args)

    def no_client(*args, **kwargs):
        pytest.fail("Disabled mode must not construct a network client")

    monkeypatch.setattr(service.os.environ, "get", checked_get)
    monkeypatch.setattr(service.httpx, "AsyncClient", no_client)
    result = asyncio.run(service.investigate(request_data))
    assert result["verdict"] == "undetermined"


def test_context_bounds_and_escaped_references(request_data):
    request_data["alert"]["untrusted/key~"] = "unique-text"
    request_data["related_events"] *= 100
    request_data["alert"]["full_log"] = "x" * 50000
    context = build_context(request_data)
    assert context["truncated"] is True
    assert len(json.dumps(context["records"]).encode()) < 12000
    assert any(f["ref"] == "/alert/untrusted~1key~0" for f in context["records"])
    assert not any(f["ref"] == "/alert/full_log" for f in context["records"])


def test_context_labels_nested_omissions(request_data):
    request_data["alert"] = {"items": ["one"] * 40}
    request_data["related_events"] = []
    assert build_context(request_data)["truncated"] is True


@pytest.mark.parametrize("ip", ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
    "0.0.0.0", "169.254.1.1", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "224.0.0.1", "255.255.255.255", "::1", "::", "fc00::1", "fe80::1", "2001:db8::1",
    "::ffff:8.8.8.8", "not-an-ip"])
def test_skip_nonpublic_ip(ip):
    assert not eligible("ip", ip)


@pytest.mark.parametrize("domain", ["host.local", "clinic.internal", "example.com", "a.example.org", "a.test",
                                    "http://attacker.net/", "localhost", "x/../../admin", "-bad.com"])
def test_skip_invalid_or_local_domain(domain):
    assert not eligible("domain", domain)


def vt_reply(value="8.8.8.8", kind="ip_address"):
    return {"data": {"id": value, "type": kind, "attributes": {
        "last_analysis_date": 1700000000,
        "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 4, "undetected": 3}}}}


def test_intel_provider_allowlist_and_budget():
    calls = []
    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.host == "www.virustotal.com"
        assert request.headers["x-apikey"] == "fake-intel-key"
        value = request.url.path.split("/")[-1]
        kind = "file" if "/files/" in request.url.path else "domain" if "/domains/" in request.url.path else "ip_address"
        return httpx.Response(200, json=vt_reply(value, kind))

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            indicators = [("ip", "192.168.8.66"), ("ip", "1.1.1.1"), ("ip", "8.8.8.8"),
                          ("domain", "malware-sample.net"), ("sha256", "a" * 64), ("ip", "9.9.9.9")]
            result = await ThreatIntel(client, "fake-intel-key", True).enrich(indicators, {"1.1.1.1"})
            assert result["lookups"] == len(calls) == 3
            assert len(result["evidence"]) == 3
            assert result["reports"][0]["status"].startswith("skipped")
            assert result["reports"][1]["status"].startswith("skipped")
            assert result["reports"][-1]["status"] == "unavailable_lookup_limit"
            for evidence in result["evidence"]:
                assert "2 malicious" in evidence["claim"]
                assert "last analysis" in evidence["claim"]
                assert evidence["source"] == "virustotal"
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["404", "429", "redirect", "wrong-id", "bad-stats", "empty", "timeout"])
def test_unavailable_intel_never_becomes_reputation(failure):
    calls = []
    def handler(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("secret-provider-error", request=request)
        reply = vt_reply()
        status = {"404": 404, "429": 429, "redirect": 302}.get(failure, 200)
        if failure == "wrong-id":
            reply["data"]["id"] = "another-ip"
        if failure == "bad-stats":
            reply["data"]["attributes"]["last_analysis_stats"]["malicious"] = True
        if failure == "empty":
            reply = {}
        return httpx.Response(status, json=reply, headers={"location": "http://127.0.0.1/secret"})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await ThreatIntel(client, "fake", True).enrich([("ip", "8.8.8.8")], set())
            assert len(calls) == 1  # No retries or redirects.
            assert result["evidence"] == []
            assert result["reports"][0]["status"].startswith("unavailable")
            assert "secret-provider-error" not in json.dumps(result)
    asyncio.run(scenario())


def test_responses_adapter_parameters_and_call_limit():
    calls = []
    schema = {"type": "object", "additionalProperties": False, "required": ["ok"],
              "properties": {"ok": {"type": "boolean"}}}
    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        assert str(request.url) == "https://api.openai.com/v1/responses"
        assert body["model"] == DEFAULT_MODEL
        assert body["store"] is False
        assert body["reasoning"] == {"effort": "none"}
        assert body["max_output_tokens"] == 1800
        assert body["tools"] == []
        assert body["text"]["format"]["strict"] is True
        return httpx.Response(200, json={"status": "completed", "output": [
            {"type": "message", "content": [{"type": "output_text", "text": '{"ok":true}'}]}]})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            model = OpenAIModel(client, "fake-openai-key")
            for _ in range(2):
                assert await model.generate("Instructions", {"untrusted": "data"}, schema) == {"ok": True}
            with pytest.raises(ModelFailure, match="limit"):
                await model.generate("Instructions", {}, schema)
            assert len(calls) == 2
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["refusal", "incomplete", "invalid-json", "invalid-schema", "http", "tool", "huge"])
def test_model_failures_are_bounded_and_sanitized(failure):
    calls = []
    def handler(request):
        calls.append(request)
        reply = {"status": "completed", "output": [{"type": "message", "content": [
            {"type": "output_text", "text": '{"ok":true}'}]}]}
        if failure == "refusal":
            reply["output"][0]["content"] = [{"type": "refusal", "refusal": "sensitive-marker"}]
        elif failure == "incomplete":
            reply["status"] = "incomplete"
        elif failure == "invalid-json":
            reply["output"][0]["content"][0]["text"] = "sensitive-marker"
        elif failure == "invalid-schema":
            reply["output"][0]["content"][0]["text"] = '{"sensitive-marker":true}'
        elif failure == "tool":
            reply["output"] = [{"type": "function_call", "name": "shell"}]
        elif failure == "huge":
            return httpx.Response(200, content=b"x" * 128001)
        return httpx.Response(401 if failure == "http" else 200, json=reply)

    async def scenario():
        schema = {"type": "object", "additionalProperties": False, "required": ["ok"],
                  "properties": {"ok": {"type": "boolean"}}}
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ModelFailure) as error:
                await OpenAIModel(client, "fake").generate("Instructions", {}, schema)
            assert "sensitive-marker" not in str(error.value)
            assert len(calls) == 1
    asyncio.run(scenario())


def test_model_rejects_unverified_config_and_large_input():
    async def scenario():
        async with httpx.AsyncClient() as client:
            with pytest.raises(ModelFailure):
                OpenAIModel(client, "fake", "unverified-expensive-model")
            with pytest.raises(ModelFailure):
                await OpenAIModel(client, "fake").generate("x" * MAX_INPUT_BYTES, {}, TRIAGE_SCHEMA)
    asyncio.run(scenario())


def test_enabled_api_workflow_uses_only_mock_transport(request_data, monkeypatch):
    # Exercise the real API -> service -> model wrapper -> workflow path, entirely offline.
    import nightwatch_agents.service as service
    real_client = httpx.AsyncClient
    calls = []
    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        data = json.loads(body["input"][0]["content"])
        output = analysis(data, final=len(calls) == 2)
        return httpx.Response(200, json={"status": "completed", "output": [
            {"type": "message", "content": [{"type": "output_text", "text": json.dumps(output)}]}]})
    monkeypatch.setattr(service.httpx, "AsyncClient", lambda **kwargs: real_client(
        transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setenv("NIGHTWATCH_LIVE_CALLS_ENABLED", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    monkeypatch.setenv("AGENT_SERVICE_KEY", "fake-service-key")
    with TestClient(create_app()) as client:
        response = client.post("/investigate", json=request_data,
                               headers={"x-nightwatch-service-key": "fake-service-key"})
    assert response.status_code == 200
    RESULT_VALIDATOR.validate(response.json())
    assert len(calls) == 2


@pytest.mark.parametrize("stage,expected", [
    ("triage", ["failed", "skipped", "skipped"]),
    ("intel", ["succeeded", "failed", "skipped"]),
    ("investigator", ["succeeded", "skipped", "failed"]),
])
def test_workflow_deadline_preserves_stage_progress(request_data, monkeypatch, stage, expected):
    import nightwatch_agents.workflow as workflow
    cancelled = []

    async def pause():
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.append(True)

    class SlowModel(FakeModel):
        async def generate(self, instructions, data, schema):
            if (stage == "triage" and schema == TRIAGE_SCHEMA or
                    stage == "investigator" and schema == FINAL_SCHEMA):
                await pause()
            return await super().generate(instructions, data, schema)

    class SlowIntel:
        async def enrich(self, indicators, own_ips):
            if stage == "intel":
                await pause()
            return {"reports": [], "evidence": [], "lookups": 0}

    monkeypatch.setattr(workflow, "WORKFLOW_TIMEOUT_SECONDS", 0.01)

    async def scenario():
        model = SlowModel()
        result = await run_workflow(request_data, model, SlowIntel())
        RESULT_VALIDATOR.validate(result)
        assert [r["status"] for r in result["agent_runs"]] == expected
        assert cancelled == [True]
        assert result["verdict"] == "undetermined"
        assert result["confidence"] == 0
        assert result["recommended_actions"] == []
        assert "workflow deadline" in result["summary"]
    asyncio.run(scenario())


def test_failed_final_preserves_verified_intel_but_discards_model_prose(request_data):
    request_data["alert"]["data"]["srcip"] = "8.8.8.8"

    class FailedFinal(FakeModel):
        async def generate(self, instructions, data, schema):
            if schema == FINAL_SCHEMA:
                raise ModelFailure("sensitive-marker")
            return await super().generate(instructions, data, schema)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json=vt_reply()))) as client:
            result = await run_workflow(request_data, FailedFinal(), ThreatIntel(client, "fake", True))
        RESULT_VALIDATOR.validate(result)
        assert [r["status"] for r in result["agent_runs"]] == ["succeeded", "succeeded", "failed"]
        assert any(e["source"] == "virustotal" and "2 malicious" in e["claim"] for e in result["evidence"])
        assert "historical provider reports" in result["summary"]
        assert "sensitive-marker" not in json.dumps(result)
        assert "Repeated logon failures require review." not in json.dumps(result)
        assert result["recommended_actions"] == []
    asyncio.run(scenario())


def test_intel_internal_failure_allows_final_local_analysis(request_data):
    class BrokenIntel:
        async def enrich(self, indicators, own_ips):
            raise RuntimeError("sensitive-marker")

    async def scenario():
        model = FakeModel()
        result = await run_workflow(request_data, model, BrokenIntel())
        RESULT_VALIDATOR.validate(result)
        assert len(model.inputs) == 2
        assert [r["status"] for r in result["agent_runs"]] == ["succeeded", "failed", "succeeded"]
        assert "unavailable" in result["summary"]
        assert "sensitive-marker" not in json.dumps(result)
        assert all(e["source"] == "wazuh" for e in result["evidence"])
    asyncio.run(scenario())


def test_request_cancellation_is_not_swallowed(request_data):
    class CancelledModel(FakeModel):
        async def generate(self, instructions, data, schema):
            raise asyncio.CancelledError()

    async def scenario():
        with pytest.raises(asyncio.CancelledError):
            await run_workflow(request_data, CancelledModel(), None)
    asyncio.run(scenario())


@pytest.mark.parametrize("configuration", ["missing-key", "unverified-model"])
def test_enabled_but_invalid_config_falls_back_without_network(request_data, monkeypatch, configuration):
    from nightwatch_agents.service import investigate
    monkeypatch.setenv("NIGHTWATCH_LIVE_CALLS_ENABLED", "true")
    if configuration == "unverified-model":
        monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
        monkeypatch.setenv("OPENAI_MODEL", "unverified-expensive-model")
    result = asyncio.run(investigate(request_data))
    RESULT_VALIDATOR.validate(result)
    assert "available configuration" in result["summary"]
    assert all(r["status"] == "skipped" and r["model"] is None for r in result["agent_runs"])
    assert result["recommended_actions"] == []


def test_fallback_without_valid_timestamps_never_invents_evidence(request_data):
    from nightwatch_agents.fallback import fallback_result
    for event in [request_data["alert"], *request_data["related_events"]]:
        event["timestamp"] = "invalid"
    result = fallback_result(request_data, "analysis_failed")
    RESULT_VALIDATOR.validate(result)
    assert result["evidence"] == []
    assert result["injection_detected"] is True
    assert "No timestamped evidence" in result["summary"]


@pytest.mark.parametrize("failure", ["401", "429", "timeout", "refusal", "incomplete", "schema"])
def test_real_model_adapter_failures_return_fallback_without_retries(request_data, failure):
    calls = []

    def handler(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("sensitive-marker", request=request)
        status = int(failure) if failure in ("401", "429") else 200
        content = {"type": "refusal", "refusal": "sensitive-marker"} if failure == "refusal" else {
            "type": "output_text", "text": '{"invalid":"sensitive-marker"}'}
        return httpx.Response(status, json={"status": "incomplete" if failure == "incomplete" else "completed",
                                           "output": [{"type": "message", "content": [content]}]})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await run_workflow(request_data, OpenAIModel(client, "fake-key"), ThreatIntel(client))
        RESULT_VALIDATOR.validate(result)
        assert len(calls) == 1
        assert [r["status"] for r in result["agent_runs"]] == ["failed", "skipped", "skipped"]
        assert result["agent_runs"][0]["model"] == DEFAULT_MODEL
        assert result["confidence"] == 0
        assert result["verdict"] == "undetermined"
        assert result["recommended_actions"] == []
        assert "sensitive-marker" not in json.dumps(result)
    asyncio.run(scenario())
