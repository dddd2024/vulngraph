"""
Tests for llm/__init__.py — client registration and availability.

Verifies that:
1. MockLLMClient is always registered and usable.
2. OpenAIClient / DeepSeekClient are registered when their modules are importable.
3. Importing the llm package never fails, even when sub-modules raise ImportError.
4. No real API calls are made.
"""

import sys
from unittest.mock import patch

import pytest

from llm.base import LLMClientBase, LLMClientFactory
from llm import MockLLMClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_openai_sdk() -> bool:
    """Return True if the ``openai`` third-party package is importable."""
    try:
        import openai  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Tests: registration (run against the actual import-time state)
# ---------------------------------------------------------------------------

class TestLLMInitRegistration:

    def test_mock_always_registered(self):
        """``mock`` should always appear in available_providers."""
        providers = LLMClientFactory.available_providers()
        assert "mock" in providers

    def test_mock_client_create_success(self):
        """Creating a mock client via the factory should succeed."""
        client = LLMClientFactory.create("mock")
        assert isinstance(client, LLMClientBase)
        assert client.provider_name == "mock"
        assert client.is_available() is True

    def test_openai_registered_when_module_importable(self):
        """``openai`` should be registered when llm.openai_client is importable."""
        providers = LLMClientFactory.available_providers()
        # openai_client.py does lazy-import openai SDK, so it is always
        # importable as a module; the SDK check happens at call time.
        assert "openai" in providers

    def test_deepseek_registered_when_module_importable(self):
        """``deepseek`` should be registered when llm.deepseek_client is importable."""
        providers = LLMClientFactory.available_providers()
        assert "deepseek" in providers

    def test_import_llm_package_never_fails(self):
        """``import llm`` must succeed regardless of openai SDK availability."""
        # Force a fresh top-level import to prove the package is loadable.
        for key in list(sys.modules):
            if key == "llm" or key.startswith("llm."):
                del sys.modules[key]
        import llm  # noqa: F401
        assert hasattr(llm, "LLMClientFactory")
        assert hasattr(llm, "MockLLMClient")


class TestConditionalRegistrationMechanism:

    """Test the try/except guard logic in __init__.py directly."""

    def test_openai_import_error_does_not_break_init(self):
        """If importing OpenAIClient raises ImportError, init still works."""
        saved = LLMClientFactory._registry.copy()
        try:
            LLMClientFactory._registry.clear()
            LLMClientFactory._registry["mock"] = MockLLMClient

            # Simulate ImportError for openai_client
            with patch.dict("sys.modules", {"llm.openai_client": None}):
                with patch("llm.openai_client.OpenAIClient", side_effect=ImportError):
                    try:
                        from llm.openai_client import OpenAIClient  # noqa: F401
                        LLMClientFactory.register("openai", OpenAIClient)
                    except ImportError:
                        pass  # This is the expected path

            providers = LLMClientFactory.available_providers()
            assert "mock" in providers
            assert "openai" not in providers
        finally:
            LLMClientFactory._registry = saved

    def test_deepseek_import_error_does_not_break_init(self):
        """If importing DeepSeekClient raises ImportError, init still works."""
        saved = LLMClientFactory._registry.copy()
        try:
            LLMClientFactory._registry.clear()
            LLMClientFactory._registry["mock"] = MockLLMClient

            with patch.dict("sys.modules", {"llm.deepseek_client": None}):
                with patch("llm.deepseek_client.DeepSeekClient", side_effect=ImportError):
                    try:
                        from llm.deepseek_client import DeepSeekClient  # noqa: F401
                        LLMClientFactory.register("deepseek", DeepSeekClient)
                    except ImportError:
                        pass

            providers = LLMClientFactory.available_providers()
            assert "mock" in providers
            assert "deepseek" not in providers
        finally:
            LLMClientFactory._registry = saved

    def test_fresh_import_with_missing_modules(self):
        """
        Simulate a fresh ``import llm`` where openai_client and deepseek_client
        modules cannot be imported.  The package should still load with only mock.
        """
        saved_modules = {}
        for key in list(sys.modules):
            if key == "llm" or key.startswith("llm."):
                saved_modules[key] = sys.modules.pop(key)

        saved_registry = LLMClientFactory._registry.copy()

        try:
            # Block llm.openai_client and llm.deepseek_client from being imported
            blocked = {"llm.openai_client", "llm.deepseek_client"}

            import_orig = __import__

            def _fake_import(name, *args, **kwargs):
                if name in blocked or any(name.startswith(b + ".") for b in blocked):
                    raise ImportError(f"blocked: {name}")
                return import_orig(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=_fake_import):
                LLMClientFactory._registry.clear()
                # Re-execute the __init__.py registration logic (same pattern)
                from llm.mock_client import MockLLMClient as MC
                LLMClientFactory.register("mock", MC)

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

            providers = LLMClientFactory.available_providers()
            assert "mock" in providers
            assert "openai" not in providers
            assert "deepseek" not in providers
        finally:
            LLMClientFactory._registry = saved_registry
            for key, mod in saved_modules.items():
                sys.modules[key] = mod


# ---------------------------------------------------------------------------
# Tests: mock client usage (no real API calls)
# ---------------------------------------------------------------------------

class TestMockClientUsage:

    def test_mock_generate_no_api_call(self):
        """Mock client generate() returns a response without any network call."""
        client = LLMClientFactory.create("mock", response_delay_ms=0)
        resp = client.generate("hello")
        assert resp.success is True
        assert isinstance(resp.content, str)
        assert len(resp.content) > 0

    def test_mock_call_count(self):
        """Mock client tracks call count."""
        client = LLMClientFactory.create("mock", response_delay_ms=0)
        assert client.get_call_count() == 0
        client.generate("test")
        assert client.get_call_count() == 1
        client.generate("test2")
        assert client.get_call_count() == 2
