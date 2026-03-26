import httpx

from tests.conftest import run


class Decision:
    def __init__(self, allowed=True, retry_after_seconds=0, reason=""):
        self.allowed = allowed
        self.retry_after_seconds = retry_after_seconds
        self.reason = reason


class FakeRateLimiter:
    def __init__(self, decision):
        self._decision = decision

    def check(self, _key):
        return self._decision


def _setup_main_with_temp_db(monkeypatch, tmp_path):
    from app import main
    from app.database import Storage

    monkeypatch.setattr(main, "storage", Storage(f"sqlite:///{tmp_path / 'api.db'}"))
    monkeypatch.setattr(main.settings, "use_arq_queue", False)
    monkeypatch.setattr(main.settings, "allow_byo_api_key", False)
    monkeypatch.setattr(main.settings, "openrouter_api_key", "default-openrouter-key")

    captured = {"task_scheduled": False}

    def fake_create_task(coro):
        captured["task_scheduled"] = True
        coro.close()
        return None

    monkeypatch.setattr(main.asyncio, "create_task", fake_create_task)

    return main, captured


async def _request(main, method, path, **kwargs):
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        return await client.request(method, path, **kwargs)


def test_health_has_security_headers():
    from app import main

    response = run(_request(main, "GET", "/health"))

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"


def test_create_scan_and_fetch_scan(monkeypatch, tmp_path):
    main, captured = _setup_main_with_temp_db(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "rate_limiter", FakeRateLimiter(Decision(True)))

    create_resp = run(_request(main, "POST", "/scans", json={"target": "example.com"}))

    assert create_resp.status_code == 200
    body = create_resp.json()
    assert body["status"] == "queued"
    assert len(body["modules"]) == len(main.ALL_MODULES)
    assert captured["task_scheduled"] is True

    scan_resp = run(_request(main, "GET", f"/scans/{body['scan_id']}"))
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["scan"]["target_domain"] == "example.com"
    assert len(scan_data["results"]) == len(main.ALL_MODULES)


def test_create_scan_rejects_rate_limit(monkeypatch):
    from app import main

    monkeypatch.setattr(main, "rate_limiter", FakeRateLimiter(Decision(False, retry_after_seconds=30, reason="minute")))

    response = run(_request(main, "POST", "/scans", json={"target": "example.com"}))
    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"


def test_create_scan_rejects_byo_when_disabled(monkeypatch, tmp_path):
    main, _ = _setup_main_with_temp_db(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "rate_limiter", FakeRateLimiter(Decision(True)))
    monkeypatch.setattr(main.settings, "allow_byo_api_key", False)

    response = run(
        _request(
            main,
            "POST",
            "/scans",
            json={"target": "example.com", "byoapi_key": "secret", "byoapi_provider": "openrouter"},
        )
    )
    assert response.status_code == 403


def test_get_scan_not_found():
    from app import main

    response = run(_request(main, "GET", "/scans/does-not-exist"))
    assert response.status_code == 404


def test_download_pdf_not_found():
    from app import main

    response = run(_request(main, "GET", "/scans/does-not-exist/report.pdf"))
    assert response.status_code == 404
