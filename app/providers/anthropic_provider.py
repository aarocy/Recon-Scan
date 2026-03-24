import httpx
from app.providers.base import AIProvider, AISummary
from app.providers.prompt import SYSTEM_PROMPT, SCAN_PROMPT, parse_summary

class AnthropicProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.model = "claude-sonnet-4-6"

    async def summarize(self, scan_context: dict) -> AISummary:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": self.model,
                    "max_tokens": 600,
                    "system": SYSTEM_PROMPT,
                    "messages": [{
                        "role": "user",
                        "content": SCAN_PROMPT.format(
                            target=scan_context.get("target", "target"),
                            context=str(scan_context)
                        )
                    }]
                }
            )
            response.raise_for_status()
            data = response.json()
            text = data["content"][0]["text"]
            short, full = parse_summary(text)

            return AISummary(
                short_narrative=short,
                full_narrative=full,
                model_used=self.model,
                provider="anthropic"
            )
