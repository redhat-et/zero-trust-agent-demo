import os
import pytest
from llm import get_provider, MockProvider, SUMMARIZER_SYSTEM_PROMPT


def test_mock_provider_returns_canned_response():
    provider = MockProvider()
    result = provider.complete("system", "user content")
    assert "Mock summary" in result
    assert "user content" in result


def test_get_provider_defaults_to_mock_when_no_key():
    os.environ.pop("LLM_API_KEY", None)
    os.environ.pop("LLM_PROVIDER", None)
    provider = get_provider()
    assert isinstance(provider, MockProvider)


def test_summarizer_system_prompt_exists():
    assert "summarize" in SUMMARIZER_SYSTEM_PROMPT.lower()
