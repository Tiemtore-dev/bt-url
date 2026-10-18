"""API HTTP : validation, cache, limites, single-flight, en-têtes — analyseur simulé."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from bt_url.api.app import SCOPE_MESSAGES, client_ip, create_app
from bt_url.api.service import AnalysisService, cache_key
from bt_url.api.settings import ApiSettings
from bt_url.config import Settings


class FakeAnalyzer:
    sources = []
    settings = Settings(ml_enabled=False)

    def __init__(self, delay=0.0, verdict="CLEAN", fail=False):
        self.calls, self.delay, self.verdict, self.fail = [], delay, verdict, fail

    async def analyze(self, url, **kw):
        self.calls.append(url)
        await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("secret-internal-detail")
        return {"meta": {"scan_duration_ms": 5}, "target": {"url": url},
                "risk": {"verdict": self.verdict, "score": 0.1, "confidence": 0.5, "reasons": []},
                "sources": []}


def client(analyzer=None, **cfg):
    base = dict(rate_per_ip_minute=100, rate_per_ip_hour=100, rate_global_minute=100,
                daily_budget=100, max_concurrent=4, analysis_timeout=5)
    base.update(cfg)
    an = analyzer or FakeAnalyzer()
    return TestClient(create_app(an, ApiSettings(**base), preload_ml=False)), an


def post(c, url="https://example.com/a", **kw):
    return c.post("/api/analyze", json={"url": url}, **kw)


def test_health_and_index_and_status():
    c, _ = client()
    assert c.get("/health").json() == {"status": "ok"}
    r = c.get("/")
    assert r.status_code == 200 and "bt-url" in r.text
    s = c.get("/api/status").json()
    assert s["quota"]["daily_limit"] == 100 and "sources" in s
    assert s["ml"] == "training" and "ml_loaded" not in s


def test_static_assets_served():
    c, _ = client()
    assert c.get("/static/app.js").status_code == 200
    assert c.get("/static/style.css").status_code == 200


def test_analyze_ok_and_response_shape():
    c, an = client()
    r = post(c)
    assert r.status_code == 200
    body = r.json()
    assert body["risk"]["verdict"] == "CLEAN" and body["cache"] == {"hit": False}


@pytest.mark.parametrize("bad", ["ftp://x.com", "javascript:alert(1)", "https://", "x" * 3000])
def test_invalid_urls_rejected_without_calling_analyzer(bad):
    c, an = client()
    r = post(c, bad)
    assert r.status_code in (422,) and an.calls == []


def test_missing_or_malformed_body_uses_uniform_error_envelope():
    c, _ = client()
    for r in (c.post("/api/analyze", json={}),
              c.post("/api/analyze", content=b"{not json", headers={"content-type": "application/json"})):
        assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_request"


def test_second_request_is_served_from_cache_and_costs_no_quota():
    c, an = client(rate_per_ip_minute=1)
    assert post(c).status_code == 200
    r = post(c)  # le quota IP (1/min) est épuisé, mais le cache répond
    assert r.status_code == 200 and r.json()["cache"]["hit"] is True
    assert len(an.calls) == 1


def test_cache_key_is_canonical():
    assert cache_key("HTTPS://Example.COM/Path?q=1#frag") == "https://example.com/Path?q=1"
    c, an = client()
    post(c, "https://EXAMPLE.com/a")
    post(c, "example.com/a")
    assert len(an.calls) == 1


def test_rate_limit_returns_429_with_retry_after():
    c, an = client(rate_per_ip_minute=2)
    assert post(c, "https://a.com").status_code == 200
    assert post(c, "https://b.com").status_code == 200
    r = post(c, "https://c.com")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    assert r.json()["error"]["code"] == "rate_limited"
    assert r.json()["error"]["message"] == SCOPE_MESSAGES["ip_minute"]
    assert len(an.calls) == 2


def test_daily_budget_returns_429():
    c, _ = client(daily_budget=1)
    assert post(c, "https://a.com").status_code == 200
    r = post(c, "https://b.com")
    assert r.status_code == 429 and "quota" in r.json()["error"]["message"].lower()


def test_internal_errors_do_not_leak_details():
    c, _ = client(FakeAnalyzer(fail=True))
    r = post(c)
    assert r.status_code == 500
    assert "secret-internal-detail" not in r.text and r.json()["error"]["code"] == "internal"


def test_degraded_results_get_short_ttl():
    svc = AnalysisService(FakeAnalyzer(), ApiSettings(cache_ttl=3600, cache_ttl_degraded=60))
    assert svc._ttl({"risk": {"verdict": "UNKNOWN"}, "sources": []}) == 60
    assert svc._ttl({"risk": {"verdict": "CLEAN"}, "sources": [{"error": "HTTP 500"}]}) == 60
    assert svc._ttl({"risk": {"verdict": "CLEAN"}, "sources": [{"error": None}]}) == 3600


def test_security_headers():
    c, _ = client()
    r = c.get("/")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert c.get("/api/status").headers["cache-control"] == "no-store"


def test_page_has_no_inline_script_or_style_or_innerhtml():
    from bt_url.api.app import STATIC
    html = (STATIC / "index.html").read_text()
    js = (STATIC / "app.js").read_text()
    assert "<script>" not in html and "style=" not in html and "onclick" not in html
    assert "innerHTML" not in js and "eval(" not in js


class _Req:
    def __init__(self, xff=None, host="9.9.9.9"):
        self.headers = {"x-forwarded-for": xff} if xff else {}
        self.client = type("C", (), {"host": host})()


def test_client_ip_ignores_forwarded_header_unless_trusted():
    assert client_ip(_Req("1.2.3.4"), trust_proxy=False) == "9.9.9.9"


def test_client_ip_uses_rightmost_forwarded_entry_when_trusted():
    # le client peut injecter « 6.6.6.6 » à gauche ; seule l'entrée de notre proxy (droite) compte
    assert client_ip(_Req("6.6.6.6, 203.0.113.7"), trust_proxy=True) == "203.0.113.7"
    assert client_ip(_Req("not-an-ip"), trust_proxy=True) == "9.9.9.9"


async def test_identical_concurrent_requests_are_coalesced_and_charged_once():
    an = FakeAnalyzer(delay=0.2)
    svc = AnalysisService(an, ApiSettings(daily_budget=100, rate_per_ip_minute=100,
                                          rate_per_ip_hour=100, rate_global_minute=100))
    results = await asyncio.gather(*(svc.analyze("https://same.com/x", f"1.1.1.{i}") for i in range(5)))
    assert len(an.calls) == 1 and svc.limits.daily.used == 1
    assert sum(1 for _, info in results if info.get("coalesced")) == 4


async def test_busy_when_all_slots_taken_and_no_quota_consumed():
    from bt_url.api.service import Busy
    an = FakeAnalyzer(delay=0.3)
    svc = AnalysisService(an, ApiSettings(max_concurrent=1, daily_budget=100, rate_per_ip_minute=100,
                                          rate_per_ip_hour=100, rate_global_minute=100))
    first = asyncio.ensure_future(svc.analyze("https://one.com", "1.1.1.1"))
    await asyncio.sleep(0.05)
    with pytest.raises(Busy):
        await svc.analyze("https://two.com", "2.2.2.2")
    assert svc.limits.daily.used == 1
    await first


async def test_timeout_raises_but_result_still_lands_in_cache():
    from bt_url.api.service import AnalysisTimeout
    an = FakeAnalyzer(delay=0.3)
    svc = AnalysisService(an, ApiSettings(analysis_timeout=0.05, daily_budget=100, rate_per_ip_minute=100,
                                          rate_per_ip_hour=100, rate_global_minute=100))
    with pytest.raises(AnalysisTimeout):
        await svc.analyze("https://slow.com", "1.1.1.1")
    await asyncio.sleep(0.4)
    _, info = await svc.analyze("https://slow.com", "1.1.1.1")
    assert info["hit"] is True and len(an.calls) == 1
