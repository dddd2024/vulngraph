import pytest

from llm.exceptions import LLMResponseFormatError
from llm.schemas import parse_analysis_json


def test_parse_analysis_json_valid_response():
    assert parse_analysis_json(
        '{"analysis": "SQL injection found", "impact_description": "Data breach risk", "mitigation_recommendation": "Use parameterized queries"}'
    ) == {
        "analysis": "SQL injection found",
        "impact_description": "Data breach risk",
        "mitigation_recommendation": "Use parameterized queries",
    }


def test_parse_analysis_json_rejects_non_json():
    with pytest.raises(LLMResponseFormatError):
        parse_analysis_json("not json")


def test_parse_analysis_json_accepts_partial_fields():
    # Analysis response can have partial fields
    result = parse_analysis_json('{"analysis": "test"}')
    assert result["analysis"] == "test"
    assert result["impact_description"] == ""
    assert result["mitigation_recommendation"] == ""


def test_parse_analysis_json_accepts_empty_response():
    result = parse_analysis_json('{}')
    assert result["analysis"] == ""
    assert result["impact_description"] == ""
    assert result["mitigation_recommendation"] == ""
