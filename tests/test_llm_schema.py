import pytest

from llm.exceptions import LLMResponseFormatError
from llm.schemas import parse_patch_json


def test_parse_patch_json_valid_response():
    assert parse_patch_json('{"reason": "why", "patch": "diff", "test": "pytest"}') == {
        "reason": "why",
        "patch": "diff",
        "test": "pytest",
    }


def test_parse_patch_json_rejects_non_json():
    with pytest.raises(LLMResponseFormatError):
        parse_patch_json("not json")


def test_parse_patch_json_rejects_missing_reason():
    with pytest.raises(LLMResponseFormatError):
        parse_patch_json('{"patch": "diff", "test": "pytest"}')


def test_parse_patch_json_rejects_missing_patch():
    with pytest.raises(LLMResponseFormatError):
        parse_patch_json('{"reason": "why", "test": "pytest"}')


def test_parse_patch_json_rejects_missing_test():
    with pytest.raises(LLMResponseFormatError):
        parse_patch_json('{"reason": "why", "patch": "diff"}')
