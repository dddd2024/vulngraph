"""
LLM module for interacting with language models.

Provides abstract interfaces and concrete implementations for
OpenAI, DeepSeek, and Mock clients.
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

# Register mock client in factory
LLMClientFactory.register("mock", MockLLMClient)

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
]