"""VirusTotal v3 — consensus multi-moteurs (autoritaire à partir de N moteurs)."""

import asyncio
import base64
import time

from bt_url.models import SourceResult
from bt_url.sources.base import BaseSource

API = "https://www.virustotal.com/api/v3"


def verdict_from_stats(stats: dict, min_engines: int) -> tuple[str, bool]:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious >= min_engines:
        return "MALICIOUS", True
    if malicious >= 1 or suspicious >= 2:
        return "SUSPICIOUS", False
    return "CLEAN", False


class VirusTotalSource(BaseSource):
    rate_per_minute = 4  # plan gratuit

    def __init__(self, api_key: str, min_engines: int = 3, timeout: int = 10):
        super().__init__(timeout)
        self._key = api_key
        self._min = min_engines

    @property
    def name(self) -> str:
        return "VirusTotal"

    def _headers(self) -> dict:
        return {"x-apikey": self._key, "Accept": "application/json"}

    def _result(self, stats: dict, started: float) -> SourceResult:
        verdict, auth = verdict_from_stats(stats, self._min)
        malicious, total = stats.get("malicious", 0), sum(stats.values())
        return SourceResult(
            self.name, verdict=verdict, authoritative=auth,
            detections=f"{malicious}/{total}", score=malicious / max(total, 1), raw=stats,
            response_time_ms=int((time.time() - started) * 1000))

    async def check_url(self, url: str) -> SourceResult:
        started = time.time()
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        # 1) rapport existant (ne consomme pas de soumission)
        data, status, error = await self._request("GET", f"{API}/urls/{url_id}", headers=self._headers())
        if data:
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats:
                return self._result(stats, started)
        elif status != 404:
            return self._error(error or f"HTTP {status}", started)

        # 2) soumission (le corps est correctement encodé par aiohttp : « & » dans l'URL)
        data, status, error = await self._request(
            "POST", f"{API}/urls", headers=self._headers(), form_data={"url": url})
        if error:
            return self._error(error, started)
        analysis_id = (data or {}).get("data", {}).get("id", "")
        if not analysis_id:
            return self._error("Pas d'ID d'analyse retourné", started)

        # 3) polling court : l'analyse peut ne pas être terminée
        for _ in range(4):
            await asyncio.sleep(3)
            data, status, error = await self._request(
                "GET", f"{API}/analyses/{analysis_id}", headers=self._headers())
            if error:
                return self._error(error, started)
            attrs = data.get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                return self._result(attrs.get("stats", {}), started)
        return SourceResult(self.name, verdict="UNKNOWN", detections="Analyse VT non terminée",
                            response_time_ms=int((time.time() - started) * 1000))
