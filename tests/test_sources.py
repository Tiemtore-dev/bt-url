"""Parsing des sources TI avec réponses simulées (aucun réseau, aucune clé)."""

import pytest

from bt_url.sources.otx import OTXSource
from bt_url.sources.phishtank import PhishTankSource
from bt_url.sources.safebrowsing import GoogleSafeBrowsingSource
from bt_url.sources.threatfox import ThreatFoxSource
from bt_url.sources.urlhaus import URLhausSource
from bt_url.sources.virustotal import VirusTotalSource, verdict_from_stats


def fake(source, data=None, status=200, error=None):
    async def _request(*a, **k):
        return data, status, error
    source._request = _request
    return source


async def test_urlhaus_listed_is_authoritative_malicious():
    r = await fake(URLhausSource("k"), {"query_status": "is_listed", "threat": "malware_download"}
                   ).check_url("http://x")
    assert r.verdict == "MALICIOUS" and r.authoritative


async def test_urlhaus_real_api_shape_ok_with_threat_is_malicious():
    """Réponse réelle observée : query_status='ok' + threat/url_status pour une URL listée."""
    data = {"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": None}
    r = await fake(URLhausSource("k"), data).check_url("http://x")
    assert r.verdict == "MALICIOUS" and r.authoritative


async def test_urlhaus_ok_without_threat_is_not_listed():
    assert (await fake(URLhausSource("k"), {"query_status": "ok"}).check_url("http://x")).verdict == "CLEAN"


async def test_otx_url_is_percent_encoded_in_path():
    seen = []
    s = OTXSource("k")

    async def _request(method, url, **k):
        seen.append(url)
        return {"pulse_info": {"count": 0}}, 200, None
    s._request = _request
    await s.check_url("http://a.com/p?x=1&y=2")
    assert seen[0].endswith("/url/http%3A%2F%2Fa.com%2Fp%3Fx%3D1%26y%3D2/general")


async def test_urlhaus_not_listed_is_clean():
    r = await fake(URLhausSource("k"), {"query_status": "no_results"}).check_url("http://x")
    assert r.verdict == "CLEAN" and not r.authoritative


async def test_urlhaus_bad_key_is_error_not_clean():
    r = await fake(URLhausSource("k"), None, 401, "HTTP 401").check_url("http://x")
    assert r.verdict == "ERROR" and "ABUSECH_API_KEY" in r.error


async def test_phishtank_verified_valid_is_authoritative():
    data = {"results": {"in_database": "true", "verified": "true", "valid": "true", "phish_id": "1"}}
    r = await fake(PhishTankSource(), data).check_url("http://x")
    assert r.verdict == "MALICIOUS" and r.authoritative


async def test_phishtank_unverified_is_only_suspicious():
    data = {"results": {"in_database": True, "verified": False, "valid": True}}
    r = await fake(PhishTankSource(), data).check_url("http://x")
    assert r.verdict == "SUSPICIOUS" and not r.authoritative


async def test_phishtank_invalidated_entry_is_clean():
    data = {"results": {"in_database": "true", "verified": "true", "valid": "false"}}
    assert (await fake(PhishTankSource(), data).check_url("http://x")).verdict == "CLEAN"


async def test_gsb_match_is_authoritative():
    data = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
    r = await fake(GoogleSafeBrowsingSource("k"), data).check_url("http://x")
    assert r.verdict == "MALICIOUS" and r.authoritative and "SOCIAL_ENGINEERING" in r.detections


async def test_gsb_no_match_is_clean():
    assert (await fake(GoogleSafeBrowsingSource("k"), {}).check_url("http://x")).verdict == "CLEAN"


@pytest.mark.parametrize("conf,auth", [(90, True), (50, True), (30, False)])
async def test_threatfox_authority_depends_on_confidence(conf, auth):
    data = {"query_status": "ok", "data": [{"confidence_level": conf, "malware_printable": "Emotet"}]}
    r = await fake(ThreatFoxSource("k"), data).check_url("http://x")
    assert r.verdict == "MALICIOUS" and r.authoritative is auth


async def test_threatfox_no_result_clean():
    r = await fake(ThreatFoxSource("k"), {"query_status": "no_result", "data": "x"}).check_url("http://x")
    assert r.verdict == "CLEAN"


@pytest.mark.parametrize("count,verdict", [(0, "CLEAN"), (2, "SUSPICIOUS"), (9, "MALICIOUS")])
async def test_otx_is_never_authoritative(count, verdict):
    r = await fake(OTXSource("k"), {"pulse_info": {"count": count}}).check_url("http://x")
    assert r.verdict == verdict and not r.authoritative


@pytest.mark.parametrize("stats,expected", [
    ({"malicious": 5, "harmless": 60}, ("MALICIOUS", True)),
    ({"malicious": 3}, ("MALICIOUS", True)),
    ({"malicious": 2, "harmless": 60}, ("SUSPICIOUS", False)),
    ({"malicious": 0, "suspicious": 2}, ("SUSPICIOUS", False)),
    ({"malicious": 0, "suspicious": 1, "harmless": 70}, ("CLEAN", False)),
])
def test_virustotal_consensus_threshold(stats, expected):
    assert verdict_from_stats(stats, 3) == expected


async def test_virustotal_uses_existing_report_without_submitting():
    calls = []
    vt = VirusTotalSource("k")

    async def _request(method, url, **k):
        calls.append(method)
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "harmless": 60}}}}, 200, None
    vt._request = _request
    r = await vt.check_url("https://evil.test/?a=1&b=2")
    assert r.verdict == "MALICIOUS" and r.authoritative and calls == ["GET"]


async def test_local_quota_wait_is_capped_instead_of_blocking(monkeypatch):
    import time as _t
    from bt_url.sources.base import _RateLimiter
    monkeypatch.setattr(_RateLimiter, "_times", {"VirusTotal": [_t.monotonic()] * 4})
    started = _t.monotonic()
    data, status, err = await VirusTotalSource("k")._request("GET", "https://unused.invalid")
    assert data is None and "Quota local" in err and _t.monotonic() - started < 1


async def test_otx_whitelisted_domain_pulses_are_ignored():
    data = {"pulse_info": {"count": 50}, "validation": [{"source": "whitelist", "name": "Whitelisted domain"}]}
    r = await fake(OTXSource("k"), data).check_url("https://github.com")
    assert r.verdict == "CLEAN" and "liste blanche" in r.detections


async def test_otx_pulses_without_whitelist_still_count():
    r = await fake(OTXSource("k"), {"pulse_info": {"count": 50}, "validation": []}).check_url("http://x")
    assert r.verdict == "MALICIOUS" and not r.authoritative
