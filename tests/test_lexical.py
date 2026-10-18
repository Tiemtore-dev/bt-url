import pytest

from bt_url import lexical as lx


def test_normalize_adds_scheme_and_strips_fragment():
    assert lx.normalize_url(" example.com/a#frag ") == "https://example.com/a"
    assert lx.normalize_url("http://a.com") == "http://a.com"


@pytest.mark.parametrize("u,ok", [
    ("https://example.com:8080/p?q=1", True), ("http://a.b", True),
    ("ftp://x.com", False), ("javascript:alert(1)", False), ("https://", False),
])
def test_is_valid_url(u, ok):
    assert lx.is_valid_url(u) is ok


def test_levenshtein():
    assert lx.levenshtein("kitten", "sitting") == 3
    assert lx.levenshtein("", "abc") == 3 and lx.levenshtein("a", "a") == 0


def test_typosquatting_detected_on_registered_domain():
    assert lx.check_typosquatting("login.paypa1.com")[0]["legitimate_domain"] == "paypal.com"


def test_legitimate_domain_not_flagged_including_subdomains():
    assert lx.check_typosquatting("www.google.com") == []
    assert lx.check_typosquatting("paypal.com") == []


def test_url_features():
    f = lx.extract_url_features("http://user@192.168.0.1/login/verify/account?a=1&b=2")
    assert f["has_ip_in_url"] and f["has_userinfo"] and not f["uses_https"]
    assert f["param_count"] == 2 and f["path_depth"] == 3
    assert {"login", "verify", "account"} <= set(f["suspicious_keywords"])


def test_punycode_flag():
    assert lx.extract_url_features("https://xn--pypal-4ve.com")["is_punycode"]


def test_shortener_detection():
    assert lx.is_shortened_url("https://bit.ly/abc") and not lx.is_shortened_url("https://github.com/x")


def test_base64_payload_decoded():
    import base64
    enc = base64.urlsafe_b64encode(b"http://evil.example/payload").decode()
    found = lx.extract_base64_payloads(f"https://x.com/r?u={enc}")
    assert found and found[0]["decoded"].startswith("http://evil.example")


def test_base64_ignores_random_text():
    assert lx.extract_base64_payloads("https://example.com/some/normal/path") == []
