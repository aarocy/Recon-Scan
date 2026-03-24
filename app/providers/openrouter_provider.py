import httpx
import logging
from app.providers.base import AIProvider, AISummary
from app.providers.prompt import SYSTEM_PROMPT, SCAN_PROMPT, parse_summary

logger = logging.getLogger(__name__)

class OpenRouterProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "nvidia/nemotron-3-super-120b-a12b:free"):
        self.api_key = api_key
        self.model = model

    async def summarize(self, scan_context: dict) -> AISummary:
        context_str = str(scan_context)
        if len(context_str) > 3000:
            context_str = context_str[:3000] + "..."

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "max_tokens": 800,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": SCAN_PROMPT.format(
                            target=scan_context.get("target", "target"),
                            context=context_str
                        )}
                    ]
                }
            )

            if response.status_code != 200:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", {}).get("message", str(error_data))
                except Exception:
                    error_msg = response.text
                raise Exception(f"OpenRouter API error {response.status_code}: {error_msg}")

            data = response.json()
            logger.info("OpenRouter summary response received")

            if "choices" not in data or not data["choices"]:
                raise Exception(f"No choices in response: {data}")

            content = data["choices"][0].get("message", {}).get("content")
            if isinstance(content, list):
                content = "\n".join(
                    part.get("text", "") for part in content if isinstance(part, dict)
                ).strip()
            if not content:
                logger.error("OpenRouter response missing message content")
                raise Exception("AI response missing content")

            short, full = parse_summary(content)
            return AISummary(
                short_narrative=short,
                full_narrative=full,
                model_used=self.model,
                provider="openrouter"
            )
