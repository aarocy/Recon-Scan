from app import security


def test_normalize_plain_domain():
    assert security.normalize_and_validate_target("Example.COM") == "example.com"


def test_normalize_from_url():
    assert security.normalize_and_validate_target("https://Sub.Example.com/path") == "sub.example.com"


def test_rejects_empty_target():
    try:
        security.normalize_and_validate_target("   ")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "required" in str(exc).lower()


def test_rejects_localhost():
    try:
        security.normalize_and_validate_target("localhost")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "not allowed" in str(exc).lower()
