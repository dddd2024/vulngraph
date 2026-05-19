from __future__ import annotations

import json
from typing import Any

from llm.exceptions import LLMResponseFormatError

PATCH_RESPONSE_KEYS = ("reason", "patch", "test")


def validate_patch_response(data: dict[str, Any]) -> dict[str, str]:
    if not isinstance(data, dict):
        raise LLMResponseFormatError("LLM patch response must be a JSON object.")

    validated: dict[str, str] = {}
    for key in PATCH_RESPONSE_KEYS:
        value = data.get(key)
        if not isinstance(value, str):
            raise LLMResponseFormatError(
                f"LLM patch response missing required string field: {key}"
            )
        validated[key] = value
    return validated


def parse_patch_json(content: str) -> dict[str, str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise LLMResponseFormatError("LLM patch response is not valid JSON.") from exc
    return validate_patch_response(data)
