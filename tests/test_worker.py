import json

from tests.conftest import run


def test_fallback_summary_counts():
    from app.worker import _fallback_summary

    result = _fallback_summary(
        "example.com",
        ["a", "b"],
        [
            {"severity": "critical"},
            {"severity": "low"},
        ],
    )
    assert "Critical: 1" in result["short"]
    assert "Severity distribution:" in result["full"]


def test_run_scan_completes_and_saves_fallback(monkeypatch):
    from app import worker

    calls = {"update_result": [], "summary": None, "scan": None}

    class FakeStorage:
        def update_scan_result(self, **kwargs):
            calls["update_result"].append(kwargs)

        def upsert_summary(self, **kwargs):
            calls["summary"] = kwargs

        def update_scan(self, **kwargs):
            calls["scan"] = kwargs

    async def mod_ok(_target):
        return {"findings": {"ok": True}, "severity": "low"}

    monkeypatch.setattr(worker, "storage", FakeStorage())
    monkeypatch.setattr(worker, "MODULE_MAP", {"m1": mod_ok})

    run(worker.run_scan({}, "scan-1", "example.com", ["m1"], None, None))

    assert len(calls["update_result"]) == 2
    assert calls["update_result"][1]["status"] == "complete"
    assert json.loads(calls["update_result"][1]["raw_data"]) == {"ok": True}
    assert calls["summary"]["provider"] == "local"
    assert calls["scan"]["status"] == "complete"


def test_run_scan_uses_byo_provider(monkeypatch):
    from app import worker

    calls = {"summary": None}

    class FakeStorage:
        def update_scan_result(self, **kwargs):
            pass

        def upsert_summary(self, **kwargs):
            calls["summary"] = kwargs

        def update_scan(self, **kwargs):
            pass

    class FakeSummary:
        short_narrative = "short"
        full_narrative = "full"
        model_used = "model-a"
        provider = "openrouter"

    class FakeProvider:
        async def summarize(self, _scan_context):
            return FakeSummary()

    async def mod_ok(_target):
        return {"findings": {"ok": True}, "severity": "info"}

    monkeypatch.setattr(worker, "storage", FakeStorage())
    monkeypatch.setattr(worker, "MODULE_MAP", {"m1": mod_ok})
    monkeypatch.setattr(worker, "get_provider", lambda *_args, **_kwargs: FakeProvider())

    run(worker.run_scan({}, "scan-2", "example.com", ["m1"], "secret", "openrouter"))

    assert calls["summary"]["model_used"] == "model-a"
    assert calls["summary"]["provider"] == "openrouter"
