"""Paramètres du service web (variables d'environnement)."""

import os
from dataclasses import dataclass, field


def _i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class ApiSettings:
    rate_per_ip_minute: int = field(default_factory=lambda: _i("BT_URL_RATE_PER_MIN", 3))
    rate_per_ip_hour: int = field(default_factory=lambda: _i("BT_URL_RATE_PER_HOUR", 20))
    # 4/min = quota du plan gratuit VirusTotal
    rate_global_minute: int = field(default_factory=lambda: _i("BT_URL_GLOBAL_PER_MIN", 4))
    daily_budget: int = field(default_factory=lambda: _i("BT_URL_DAILY_BUDGET", 300))
    cache_ttl: int = field(default_factory=lambda: _i("BT_URL_CACHE_TTL", 3600))
    cache_ttl_degraded: int = field(default_factory=lambda: _i("BT_URL_CACHE_TTL_DEGRADED", 60))
    cache_max_entries: int = field(default_factory=lambda: _i("BT_URL_CACHE_MAX", 1000))
    max_concurrent: int = field(default_factory=lambda: _i("BT_URL_MAX_CONCURRENT", 4))
    analysis_timeout: int = field(default_factory=lambda: _i("BT_URL_ANALYSIS_TIMEOUT", 75))
    # Derrière un reverse proxy (Render, Fly…) : lire l'IP cliente dans X-Forwarded-For
    trust_proxy: bool = field(default_factory=lambda: os.environ.get(
        "BT_URL_TRUST_PROXY", "false").lower() in ("1", "true", "yes"))
    max_url_length: int = 2048
