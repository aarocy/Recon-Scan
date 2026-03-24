import httpx
from app.providers.base import AIProvider, AISummary
from app.providers.prompt import SYSTEM_PROMPT, SCAN_PROMPT, parse_summary

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.model = "gpt-4.5-preview"

    async def summarize(self, scan_context: dict) -> AISummary:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "max_tokens": 600,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": SCAN_PROMPT.format(
                            target=scan_context.get("target", "target"),
                            context=str(scan_context)
                        )}
                    ]
                }
            )
            response.raise_for_status()
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            short, full = parse_summary(text)

            return AISummary(
                short_narrative=short,
                full_narrative=full,
                model_used=self.model,
                provider="openai"
            )
