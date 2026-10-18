"""Intégration de l'analyseur avec sources et ML simulés."""

import pytest

from bt_url.analyzer import URLAnalyzer, merge_source_results
from bt_url.config import Settings
from bt_url.models import MLResult, SourceResult
from bt_url.sources.base import BaseSource


class FakeSource(BaseSource):
    def __init__(self, name, by_url=None, default=None):
        super().__init__()
        self._name, self.by_url = name, by_url or {}
        self.default = default or SourceResult(name, verdict="CLEAN")
        self.calls = []

    @property
    def name(self):
        return self._name

    async def check_url(self, url):
        self.calls.append(url)
        return self.by_url.get(url, self.default)


class FakeML:
    def __init__(self, score, label):
        self.r = MLResult(score=score, label=label, confidence=1 - score, threshold=0.45)

    def predict(self, features):
        return self.r


def analyzer(sources, ml=None):
    return URLAnalyzer(Settings(ml_enabled=False), sources=sources, ml_loader=ml)


async def test_invalid_url_raises():
    with pytest.raises(ValueError):
        await analyzer([]).analyze("ftp://x.com")


async def test_private_target_makes_no_outbound_connection_but_still_uses_ti():
    src = FakeSource("S", default=SourceResult("S", verdict="MALICIOUS", authoritative=True))
    r = await analyzer([src]).analyze("http://127.0.0.1/admin")
    assert r["target"]["public"] is False
    assert "ssl" not in r and "redirects" not in r and r["ml"]["enabled"] is False
    assert r["notes"] and r["risk"]["verdict"] == "CONFIRMED_MALICIOUS"


async def test_authoritative_hit_overrides_benign_ml_end_to_end(monkeypatch):
    monkeypatch.setattr("bt_url.analyzer.check_ssl", lambda h: {"valid": True})
    async def no_redirects(url, **k):
        return {"chain": [url], "final_url": url, "blocked": None, "error": None}
    monkeypatch.setattr("bt_url.netguard.follow_redirects", no_redirects)
    async def public(host):
        return True
    monkeypatch.setattr("bt_url.netguard.host_is_public", public)

    ml = FakeML(0.01, "BENIGN")
    monkeypatch.setattr("bt_url.ml.features.collect_all_features", lambda u: {"x": 1})
    a = URLAnalyzer(Settings(ml_enabled=True), sources=[
        FakeSource("URLhaus", default=SourceResult("URLhaus", verdict="MALICIOUS", authoritative=True)),
        FakeSource("VirusTotal")], ml_loader=ml)
    r = await a.analyze("https://example.org/x")
    assert r["ml"]["label"] == "BENIGN"
    assert r["risk"]["verdict"] == "CONFIRMED_MALICIOUS"
    assert r["risk"]["decisive_source"] == "URLhaus"


async def test_source_exception_becomes_error_not_crash():
    class Boom(FakeSource):
        async def check_url(self, url):
            raise RuntimeError("boom")
    r = await analyzer([Boom("B")]).analyze("http://127.0.0.1/")
    assert r["sources"][0]["verdict"] == "ERROR"
    assert r["risk"]["verdict"] == "UNKNOWN"


async def test_shortener_queries_original_and_final_and_keeps_worst(monkeypatch):
    async def public(host):
        return True
    monkeypatch.setattr("bt_url.netguard.host_is_public", public)
    async def follow(url, **k):
        return {"chain": [url, "https://evil.test/p"], "final_url": "https://evil.test/p",
                "blocked": None, "error": None}
    monkeypatch.setattr("bt_url.netguard.follow_redirects", follow)
    monkeypatch.setattr("bt_url.analyzer.check_ssl", lambda h: {})

    src = FakeSource("PhishTank", by_url={"https://evil.test/p": SourceResult(
        "PhishTank", verdict="MALICIOUS", authoritative=True)})
    r = await analyzer([src]).analyze("https://bit.ly/abc")
    assert set(src.calls) == {"https://bit.ly/abc", "https://evil.test/p"}
    assert r["risk"]["verdict"] == "CONFIRMED_MALICIOUS"


def test_merge_keeps_most_severe_per_source():
    merged = merge_source_results([
        [SourceResult("A", verdict="CLEAN"), SourceResult("B", verdict="ERROR")],
        [SourceResult("A", verdict="SUSPICIOUS"), SourceResult("B", verdict="CLEAN")]])
    assert {s.source_name: s.verdict for s in merged} == {"A": "SUSPICIOUS", "B": "CLEAN"}


async def test_ml_disabled_is_reported_as_training_and_verdict_uses_ti_only():
    src = FakeSource("S", default=SourceResult("S", verdict="CLEAN"))
    r = await analyzer([src]).analyze("http://127.0.0.1/x")
    assert r["ml"] == {"enabled": False, "status": "training"}
