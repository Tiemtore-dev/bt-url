"""Charge le VRAI modèle (nécessite BT_URL_MODEL_PATH ; exclu par défaut : -m network)."""

import os

import pytest

from bt_url.ml.model import ModelLoader

PATH = os.environ.get("BT_URL_MODEL_PATH", "")
META = os.environ.get("BT_URL_MODEL_META", "")
SHA = os.environ.get("BT_URL_MODEL_SHA256", "")
pytestmark = [pytest.mark.network,
              pytest.mark.skipif(not os.path.exists(PATH), reason="BT_URL_MODEL_PATH absent (modèle non livré)")]

BENIGN = {"ttl_A": 300, "ttl_MX": 3600, "nb_A_records": 2, "nb_ips": 2, "average_rtt": 20.0,
          "tls_cert_count": 1, "cert_valid_len_days": 90, "domain_age_days": 9000,
          "domain_remaining_days": 400, "nb_rdap_status": 3, "nb_nameservers": 4,
          "primary_prefix_len": 24, "url_length": 18, "domain_length": 10,
          "count_unique_chars": 12, "url_entropy": 3.2, "count_dots": 1, "count_slashes": 0,
          "num_subdomains": 0, "tld": "com", "primary_country_code": "us", "is_alive": 1,
          "has_AAAA": 1, "has_MX": 1, "dns_had_no_ips": 0}


def test_real_model_loads_and_predicts_in_range():
    loader = ModelLoader(PATH, META)
    loader.load(SHA)
    r = loader.predict(BENIGN)
    assert 0.0 <= r.score <= 1.0 and r.label in ("BENIGN", "SUSPICIOUS", "MALICIOUS")
    assert r.label == "BENIGN"


def test_real_model_flags_a_throwaway_young_domain_as_riskier():
    loader = ModelLoader(PATH, META)
    loader.load(SHA)
    risky = {**BENIGN, "domain_age_days": 2, "domain_remaining_days": 300, "tls_cert_count": 0,
             "cert_valid_len_days": 0, "tld": "xyz", "url_length": 90, "url_entropy": 4.6,
             "count_dots": 5, "num_subdomains": 4, "has_MX": 0, "nb_nameservers": 2}
    assert loader.predict(risky).score > loader.predict(BENIGN).score
