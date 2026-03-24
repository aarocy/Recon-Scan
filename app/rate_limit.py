import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int = 0
    reason: str = ""


class InMemoryRateLimiter:
    def __init__(self, per_minute: int, per_day: int):
        self.per_minute = per_minute
        self.per_day = per_day
        self._minute_events = defaultdict(deque)
        self._day_events = defaultdict(deque)
        self._lock = Lock()

    def _prune(self, events: deque, window_seconds: int, now: float) -> None:
        cutoff = now - window_seconds
        while events and events[0] <= cutoff:
            events.popleft()

    def check(self, key: str) -> RateLimitDecision:
        now = time.time()
        with self._lock:
            minute_events = self._minute_events[key]
            day_events = self._day_events[key]

            self._prune(minute_events, 60, now)
            self._prune(day_events, 86400, now)

            if len(minute_events) >= self.per_minute:
                retry_after = max(1, int(60 - (now - minute_events[0])))
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=retry_after,
                    reason=f"Per-minute limit reached ({self.per_minute}/minute)",
                )

            if len(day_events) >= self.per_day:
                retry_after = max(1, int(86400 - (now - day_events[0])))
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=retry_after,
                    reason=f"Per-day limit reached ({self.per_day}/day)",
                )

            minute_events.append(now)
            day_events.append(now)
            return RateLimitDecision(allowed=True)
