"""Règles de pondération : la TI autoritaire doit toujours prédominer."""

import pytest

from bt_url.models import MLResult, SourceResult
from bt_url.scoring import assess_risk, structural_score


def src(name, verdict, auth=False):
    return SourceResult(name, verdict=verdict, authoritative=auth)


def ml(score, label=None, thr=0.457):
    label = label or ("MALICIOUS" if score >= thr else "BENIGN")
    return MLResult(score=score, label=label, confidence=max(score, 1 - score), threshold=thr)


@pytest.mark.parametrize("ml_score", [0.0, 0.05, 0.5, 0.99])
def test_authoritative_malicious_wins_over_any_ml(ml_score):
    r = assess_risk([src("URLhaus", "MALICIOUS", auth=True)], ml(ml_score))
    assert r["verdict"] == "CONFIRMED_MALICIOUS"
    assert r["score"] >= 0.9
    assert r["decisive_source"] == "URLhaus"


def test_authoritative_malicious_wins_over_many_clean_sources():
    sources = [src("VirusTotal", "CLEAN"), src("OTX", "CLEAN"), src("GSB", "CLEAN"),
               src("PhishTank", "MALICIOUS", auth=True)]
    r = assess_risk(sources, ml(0.01))
    assert r["verdict"] == "CONFIRMED_MALICIOUS"


def test_authoritative_malicious_alone_without_ml():
    r = assess_risk([src("Google Safe Browsing", "MALICIOUS", auth=True)], None)
    assert r["verdict"] == "CONFIRMED_MALICIOUS"


def test_two_authoritative_sources_max_score_and_confidence():
    r = assess_risk([src("URLhaus", "MALICIOUS", True), src("PhishTank", "MALICIOUS", True)], ml(0.1))
    assert r["score"] == 1.0 and r["confidence"] >= 0.99


def test_authoritative_flag_required_for_override():
    """Un MALICIOUS non autoritaire (ex. OTX) ne confirme pas seul : HIGH_RISK minimum."""
    r = assess_risk([src("OTX AlienVault", "MALICIOUS", auth=False)], ml(0.0))
    assert r["verdict"] == "HIGH_RISK"
    assert 0.6 <= r["score"] < 0.9


def test_suspicious_source_sets_floor_even_if_ml_benign():
    r = assess_risk([src("VirusTotal", "SUSPICIOUS")], ml(0.0))
    assert r["verdict"] == "SUSPICIOUS"


def test_ml_alone_never_confirms():
    r = assess_risk([], ml(1.0))
    assert r["verdict"] == "HIGH_RISK"
    assert r["score"] < 0.9


def test_ml_at_threshold_is_suspicious():
    assert assess_risk([], ml(0.46))["verdict"] == "SUSPICIOUS"


def test_clean_sources_do_not_lower_a_high_ml_score():
    with_clean = assess_risk([src("VirusTotal", "CLEAN"), src("PhishTank", "CLEAN")], ml(0.95))
    without = assess_risk([], ml(0.95))
    assert with_clean["score"] == without["score"]
    assert with_clean["verdict"] == "HIGH_RISK"


def test_errors_are_ignored_not_counted_as_clean():
    r = assess_risk([SourceResult("VirusTotal", verdict="ERROR", error="HTTP 500")], None)
    assert r["verdict"] == "UNKNOWN" and r["score"] is None


def test_authoritative_error_does_not_trigger_override():
    bad = SourceResult("URLhaus", verdict="ERROR", authoritative=True)
    assert assess_risk([bad], ml(0.05))["verdict"] == "CLEAN"


def test_no_data_is_unknown_not_clean():
    assert assess_risk([], None)["verdict"] == "UNKNOWN"


def test_all_clean_and_benign_ml_is_clean():
    r = assess_risk([src("VirusTotal", "CLEAN")], ml(0.02))
    assert r["verdict"] == "CLEAN" and r["score"] < 0.35


def test_heuristics_alone_are_capped_below_high_risk():
    feats = {"has_ip_in_url": True, "has_userinfo": True, "is_punycode": True,
             "suspicious_keywords": ["a", "b", "c"], "uses_https": False}
    h, reasons = structural_score(feats, [{"legitimate_domain": "paypal.com", "distance": 1}], 1)
    assert h <= 0.5 and reasons
    assert assess_risk([], None, h, reasons)["verdict"] in ("SUSPICIOUS",)


def test_heuristics_boost_ml_via_noisy_or():
    base = assess_risk([], ml(0.5))["score"]
    boosted = assess_risk([], ml(0.5), 0.25, ["x"])["score"]
    assert boosted > base


def test_score_never_exceeds_cap_without_authoritative():
    r = assess_risk([src("OTX", "MALICIOUS")], ml(1.0), 0.5, ["x"])
    assert r["score"] <= 0.89
