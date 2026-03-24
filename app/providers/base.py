from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class AISummary:
    short_narrative: str
    full_narrative: str
    model_used: str
    provider: str

class AIProvider(ABC):
    @abstractmethod
    async def summarize(self, scan_context: dict) -> AISummary:
        pass
