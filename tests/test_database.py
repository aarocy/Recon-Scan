from app.database import Storage


def test_storage_scan_lifecycle(tmp_path):
    db = Storage(f"sqlite:///{tmp_path / 'test.db'}")

    db.create_scan(scan_id="scan-1", user_id="u1", target_domain="example.com")
    db.create_scan_result(result_id="res-1", scan_id="scan-1", module="security_headers")

    db.update_scan_result("scan-1", "security_headers", status="complete", raw_data='{"ok": true}', severity="low")
    db.upsert_summary("scan-1", "short", "full", "model-x", "provider-y")
    db.update_scan("scan-1", status="complete")

    scan = db.get_scan("scan-1")
    results = db.get_results("scan-1")
    summary = db.get_summary("scan-1")

    assert scan is not None
    assert scan["status"] == "complete"

    assert len(results) == 1
    assert results[0]["module"] == "security_headers"
    assert results[0]["raw_data"] == {"ok": True}

    assert summary is not None
    assert summary["short_narrative"] == "short"
    assert summary["provider"] == "provider-y"


def test_storage_rejects_non_sqlite_url():
    try:
        Storage("postgres://invalid")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "sqlite" in str(exc).lower()
