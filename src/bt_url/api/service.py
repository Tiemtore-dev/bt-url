"""Service d'analyse : cache + single-flight + limites + concurrence bornée + timeout."""

import asyncio
import time
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from bt_url import lexical
from bt_url.api.limits import DailyBudget, Limits, RateLimited, SlidingWindow, TTLCache, new_inflight
from bt_url.api.settings import ApiSettings


class InvalidURL(ValueError):
    pass


class Busy(Exception):
    """Trop d'analyses simultanées."""


class AnalysisTimeout(Exception):
    pass


def cache_key(url: str) -> str:
    """Clé canonique : schéma et hôte en minuscules, fragment retiré."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))


class AnalysisService:
    def __init__(self, analyzer, settings: Optional[ApiSettings] = None):
        self.analyzer = analyzer
        self.cfg = settings or ApiSettings()
        self.cache = TTLCache(self.cfg.cache_max_entries)
        self.limits = Limits(
            per_ip_minute=SlidingWindow(self.cfg.rate_per_ip_minute, 60),
            per_ip_hour=SlidingWindow(self.cfg.rate_per_ip_hour, 3600),
            global_minute=SlidingWindow(self.cfg.rate_global_minute, 60),
            daily=DailyBudget(self.cfg.daily_budget),
        )
        self._slots = asyncio.Semaphore(self.cfg.max_concurrent)
        self._inflight = new_inflight()
        self.stats = {"analyses": 0, "cache_hits": 0, "coalesced": 0, "rate_limited": 0}

    def prepare(self, raw: str) -> str:
        url = lexical.normalize_url(raw)
        if len(url) > self.cfg.max_url_length or not lexical.is_valid_url(url):
            raise InvalidURL("URL invalide : http(s) attendu, 2048 caractères maximum")
        return cache_key(url)

    def _ttl(self, result: dict) -> int:
        degraded = (result["risk"]["verdict"] == "UNKNOWN"
                    or any(s.get("error") for s in result.get("sources", [])))
        return self.cfg.cache_ttl_degraded if degraded else self.cfg.cache_ttl

    async def analyze(self, raw_url: str, client_ip: str) -> tuple[dict, dict]:
        """Retourne (résultat, infos de cache). Lève InvalidURL, RateLimited, Busy, AnalysisTimeout."""
        key = self.prepare(raw_url)

        hit = self.cache.get(key)
        if hit:
            self.stats["cache_hits"] += 1
            return hit[0], {"hit": True, "age_seconds": hit[1]}

        pending = self._inflight.get(key)  # même URL déjà en cours : on partage, sans consommer de quota
        if pending is not None:
            self.stats["coalesced"] += 1
            return await self._wait(pending), {"hit": False, "coalesced": True}

        if self._slots.locked():  # avant de consommer du quota
            raise Busy()
        try:
            self.limits.check_and_consume(client_ip)
        except RateLimited:
            self.stats["rate_limited"] += 1
            raise

        task = asyncio.ensure_future(self._run(key))
        self._inflight[key] = task
        task.add_done_callback(lambda _t, k=key: self._inflight.pop(k, None))
        return await self._wait(task), {"hit": False}

    async def _wait(self, task) -> dict:
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout=self.cfg.analysis_timeout)
        except asyncio.TimeoutError:
            raise AnalysisTimeout() from None

    async def _run(self, key: str) -> dict:
        async with self._slots:
            self.stats["analyses"] += 1
            result = await self.analyzer.analyze(key)
        result["meta"]["cached_at"] = time.time()
        self.cache.set(key, result, self._ttl(result))
        return result

    def snapshot(self) -> dict:
        return {**self.stats, "cache_entries": len(self.cache),
                "daily_remaining": self.limits.daily.remaining(), "daily_limit": self.cfg.daily_budget}
