from app.providers.base import AIProvider, AISummary
from app.providers.anthropic_provider import AnthropicProvider
from app.providers.openai_provider import OpenAIProvider
from app.providers.openrouter_provider import OpenRouterProvider

def get_provider(provider: str, api_key: str, model: str = None) -> AIProvider:
    if provider == "anthropic":
        return AnthropicProvider(api_key)
    elif provider == "openai":
        return OpenAIProvider(api_key)
    elif provider == "openrouter":
        # Let OpenRouterProvider choose its own default model unless explicitly overridden.
        return OpenRouterProvider(api_key, model) if model else OpenRouterProvider(api_key)
    else:
        raise ValueError(f"Unknown provider: {provider}")
