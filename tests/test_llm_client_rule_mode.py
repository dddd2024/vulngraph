import pytest

from llm.client import LLMClient
from llm.exceptions import LLMConfigError


def test_llm_client_rule_mode_rejects_external_calls():
    client = LLMClient(ai_mode="rule")

    with pytest.raises(LLMConfigError, match="rule mode"):
        client.generate_text("hello")
