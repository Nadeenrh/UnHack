"""Validate the shared schema directly, without duplicating or coercing types."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from rfc3339_validator import validate_rfc3339

FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time")
def valid_datetime(value):
    # Explicit registration prevents silently skipping this optional format check.
    return not isinstance(value, str) or validate_rfc3339(value.upper())

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "web/contracts/investigation.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(SCHEMA)


def validator(name):
    return Draft202012Validator(
        {"$schema": SCHEMA["$schema"], "$defs": SCHEMA["$defs"],
         "$ref": "#/$defs/" + name},
        format_checker=FORMAT_CHECKER,
    )


REQUEST_VALIDATOR = validator("request")
RESULT_VALIDATOR = validator("result")
