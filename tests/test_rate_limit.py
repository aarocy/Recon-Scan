from app.rate_limit import InMemoryRateLimiter


def test_rate_limiter_allows_then_blocks_per_minute(monkeypatch):
    limiter = InMemoryRateLimiter(per_minute=2, per_day=10)

    times = iter([1000.0, 1001.0, 1002.0])
    monkeypatch.setattr("app.rate_limit.time.time", lambda: next(times))

    assert limiter.check("ip1").allowed is True
    assert limiter.check("ip1").allowed is True
    decision = limiter.check("ip1")
    assert decision.allowed is False
    assert decision.retry_after_seconds >= 1
    assert "minute" in decision.reason.lower()


def test_rate_limiter_day_limit(monkeypatch):
    limiter = InMemoryRateLimiter(per_minute=100, per_day=2)

    times = iter([2000.0, 2001.0, 2002.0])
    monkeypatch.setattr("app.rate_limit.time.time", lambda: next(times))

    assert limiter.check("ip2").allowed is True
    assert limiter.check("ip2").allowed is True
    decision = limiter.check("ip2")
    assert decision.allowed is False
    assert "day" in decision.reason.lower()
