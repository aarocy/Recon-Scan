from tests.conftest import run


class _FailingAsyncClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        raise Exception("network down")

    async def post(self, *args, **kwargs):
        raise Exception("network down")


def _assert_common_shape(res, module):
    assert res["module"] == module
    assert "findings" in res
    assert "severity" in res


def test_httpx_modules_handle_errors(monkeypatch):
    from app.modules import (
        cookie_security,
        cors_check,
        directory_exposure,
        js_exposure,
        robots_sitemap,
        security_headers,
        subdomains,
        tech_fingerprint,
        waf_detection,
        whois,
    )

    modules = [
        cookie_security,
        cors_check,
        directory_exposure,
        js_exposure,
        robots_sitemap,
        security_headers,
        subdomains,
        tech_fingerprint,
        waf_detection,
        whois,
    ]

    for mod in modules:
        monkeypatch.setattr(mod.httpx, "AsyncClient", lambda *a, **k: _FailingAsyncClient())

    for mod in modules:
        res = run(mod.run("example.com"))
        _assert_common_shape(res, mod.__name__.split(".")[-1])


def test_dns_email_missing_records(monkeypatch):
    from app.modules import dns_email

    monkeypatch.setattr(dns_email.dns.resolver, "resolve", lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception("dns fail")))

    res = run(dns_email.run("example.com"))
    _assert_common_shape(res, "dns_email")
    assert res["severity"] == "critical"
    assert "SPF" in res["findings"]["missing"]
    assert "DMARC" in res["findings"]["missing"]


def test_ssl_tls_ssl_error(monkeypatch):
    from app.modules import ssl_tls

    res = run(ssl_tls.run("example.com"))
    _assert_common_shape(res, "ssl_tls")
    assert res["severity"] in {"critical", "medium"}
    assert "error" in res["findings"]
