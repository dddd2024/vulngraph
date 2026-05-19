class LLMError(Exception):
    """Base exception for LLM client failures."""


class LLMConfigError(LLMError):
    """Raised when LLM configuration is missing or invalid."""


class LLMConnectionError(LLMError):
    """Raised when an LLM endpoint cannot be reached."""


class LLMTimeoutError(LLMConnectionError):
    """Raised when an LLM request times out."""


class LLMResponseFormatError(LLMError):
    """Raised when an LLM response does not match the expected schema."""
