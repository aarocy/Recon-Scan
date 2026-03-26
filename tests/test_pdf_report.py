from app.pdf_report import _result_details, _safe_text, _severity_snapshot, build_scan_pdf


def test_pdf_helpers():
    assert _safe_text("<x&y>") == "&lt;x&amp;y&gt;"
    assert _result_details({"a": 1}).startswith("{")

    crit, high, med, low, info = _severity_snapshot(
        [{"severity": "critical"}, {"severity": "low"}, {"severity": "unknown"}]
    )
    assert (crit, high, med, low, info) == (1, 0, 0, 1, 0)


def test_build_scan_pdf_returns_pdf_bytes():
    scan = {"id": "scan-1", "target_domain": "example.com", "created_at": "2026-01-01T00:00:00Z"}
    results = [
        {
            "module": "security_headers",
            "severity": "medium",
            "status": "complete",
            "raw_data": {"missing": ["csp"]},
        }
    ]
    summary = {
        "short_narrative": "Short summary",
        "full_narrative": "Full summary",
        "model_used": "model",
        "provider": "local",
    }

    pdf = build_scan_pdf(scan, results, summary)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 500
