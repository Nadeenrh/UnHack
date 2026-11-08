"""Small, bounded Responses API adapter. No SDK retries or model tools."""

import asyncio
import json

import httpx
from jsonschema import Draft202012Validator, ValidationError

VERIFIED_MODELS = {"gpt-5.4-mini", "gpt-5.4-mini-2026-03-17"}
DEFAULT_MODEL = "gpt-5.4-mini-2026-03-17"
MAX_INPUT_BYTES = 24000
MAX_OUTPUT_TOKENS = 1800
MAX_RESPONSE_BYTES = 128000
CALL_TIMEOUT = 25


class ModelFailure(Exception):
    """A deliberately sanitized error; never retain provider response bodies."""


async def bounded_json(client, method, url, **kwargs):
    async with client.stream(method, url, **kwargs) as response:
        if response.status_code != 200:
            raise ModelFailure("Provider request unavailable")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ModelFailure("Provider response exceeds limit")
        return json.loads(body)


class OpenAIModel:
    def __init__(self, client, api_key, model=DEFAULT_MODEL):
        if model not in VERIFIED_MODELS or not api_key.strip():
            raise ModelFailure("Missing key or unverified model configuration")
        self.client = client
        self._api_key = api_key
        self.model = model
        self.calls = 0

    async def generate(self, instructions, data, schema):
        if self.calls >= 2:
            raise ModelFailure("Model call limit reached")
        self.calls += 1
        content = json.dumps(data, ensure_ascii=True, allow_nan=False)
        if len((instructions + content + json.dumps(schema)).encode()) > MAX_INPUT_BYTES:
            raise ModelFailure("Model input exceeds limit")
        body = {
            "model": self.model, "store": False,
            "instructions": instructions,
            "input": [{"role": "user", "content": content}],
            "reasoning": {"effort": "none"},
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "tools": [],
            "text": {"format": {"type": "json_schema", "name": "soc_analysis",
                                "strict": True, "schema": schema}},
        }
        try:
            reply = await asyncio.wait_for(bounded_json(
                self.client, "POST", "https://api.openai.com/v1/responses",
                headers={"Authorization": "Bearer " + self._api_key}, json=body,
            ), timeout=CALL_TIMEOUT)
            if reply.get("status") != "completed":
                raise ModelFailure("Model response incomplete")
            texts = []
            for item in reply.get("output", []):
                if item.get("type") == "reasoning":
                    continue
                if item.get("type") != "message":
                    raise ModelFailure("Unexpected model output item")
                for part in item.get("content", []):
                    if part.get("type") != "output_text":
                        raise ModelFailure("Model refusal or unexpected output")
                    texts.append(part["text"])
            if len(texts) != 1:
                raise ModelFailure("Missing or ambiguous model output")
            result = json.loads(texts[0])
            Draft202012Validator(schema).validate(result)
            return result
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError, ValidationError,
                asyncio.TimeoutError, RecursionError):
            raise ModelFailure("Model request failed or output invalid") from None
