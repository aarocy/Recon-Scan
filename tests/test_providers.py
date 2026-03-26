from app.providers import get_provider
from app.providers.openai_provider import OpenAIProvider
from app.providers.openrouter_provider import OpenRouterProvider
from app.providers.prompt import parse_summary


def test_parse_summary_structured():
    short, full = parse_summary("SHORT: one\n\nFULL: two")
    assert short == "one"
    assert full == "two"


def test_parse_summary_fallback():
    short, full = parse_summary("plain text response")
    assert short == "plain text response"
    assert full == ""


def test_get_provider_factory():
    assert isinstance(get_provider("openai", "k"), OpenAIProvider)
    assert isinstance(get_provider("openrouter", "k"), OpenRouterProvider)

    try:
        get_provider("nope", "k")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "unknown provider" in str(exc).lower()
