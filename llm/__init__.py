"""
LLM module for interacting with language models.

Provides abstract interfaces and concrete implementations for
OpenAI, DeepSeek, and Mock clients.

OpenAI / DeepSeek clients are registered only when the ``openai`` SDK is
installed; otherwise they are silently skipped so that the ``llm`` package
can still be imported (e.g. in test environments or CI runners without the
SDK).
"""

from llm.base import LLMClientBase, LLMResponse, LLMClientFactory
from llm.exceptions import (
    LLMError,
    LLMConfigError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMResponseError,
)
from llm.mock_client import MockLLMClient

# Register mock client (always available)
LLMClientFactory.register("mock", MockLLMClient)

# Conditionally register OpenAI / DeepSeek when the SDK is present.
try:
    from llm.openai_client import OpenAIClient
    LLMClientFactory.register("openai", OpenAIClient)
except ImportError:
    pass

try:
    from llm.deepseek_client import DeepSeekClient
    LLMClientFactory.register("deepseek", DeepSeekClient)
except ImportError:
    pass

__all__ = [
    "LLMClientBase",
    "LLMResponse",
    "LLMClientFactory",
    "LLMError",
    "LLMConfigError",
    "LLMConnectionError",
    "LLMTimeoutError",
    "LLMRateLimitError",
    "LLMResponseError",
    "MockLLMClient",
    "OpenAIClient",
    "DeepSeekClient",
]
