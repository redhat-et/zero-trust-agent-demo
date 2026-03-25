"""Multi-provider LLM abstraction for document summarization."""

import os
from abc import ABC, abstractmethod

import anthropic
import openai


SUMMARIZER_SYSTEM_PROMPT = (
    "You are a document summarization assistant. "
    "Summarize the provided document concisely, capturing the key points, "
    "findings, and conclusions. Keep your summary clear and well-structured."
)

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
    "litellm": "qwen3-14b",
}


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a completion request and return the response text."""


class MockProvider(LLMProvider):
    """Mock provider for testing without API keys."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        truncated = user_prompt[:200] if len(user_prompt) > 200 else user_prompt
        return f"Mock summary of document:\n\n{truncated}"


class AnthropicProvider(LLMProvider):
    """Provider wrapping the Anthropic API."""

    def __init__(self, api_key: str, model: str | None = None):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model or DEFAULT_MODELS["anthropic"]

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        message = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return message.content[0].text


class OpenAIProvider(LLMProvider):
    """Provider wrapping the OpenAI-compatible API (also used for litellm)."""

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
    ):
        kwargs: dict = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = openai.OpenAI(**kwargs)
        self.model = model or DEFAULT_MODELS["openai"]

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content or ""


def get_provider() -> LLMProvider:
    """Factory that returns an LLM provider based on environment variables.

    Environment variables:
        LLM_PROVIDER: "anthropic", "openai", or "litellm" (default: "anthropic")
        LLM_API_KEY: API key for the provider (if unset, returns MockProvider)
        LLM_BASE_URL: Base URL override (used for litellm / custom endpoints)
        LLM_MODEL: Model name override
    """
    api_key = os.environ.get("LLM_API_KEY", "")
    if not api_key:
        return MockProvider()

    provider_name = os.environ.get("LLM_PROVIDER", "anthropic").lower()
    model = os.environ.get("LLM_MODEL")
    base_url = os.environ.get("LLM_BASE_URL")

    if provider_name == "anthropic":
        return AnthropicProvider(api_key=api_key, model=model)
    elif provider_name in ("openai", "litellm"):
        effective_model = model or DEFAULT_MODELS.get(provider_name, "gpt-4o")
        return OpenAIProvider(api_key=api_key, model=effective_model, base_url=base_url)
    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}")
