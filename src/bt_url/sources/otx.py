"""AlienVault OTX — pulses communautaires (indicatif, non autoritaire)."""

import time
from urllib.parse import quote

from bt_url.models import SourceResult
from bt_url.sources.base import BaseSource

MALICIOUS_PULSES = 5


class OTXSource(BaseSource):
    rate_per_minute = 20

    def __init__(self, api_key: str, timeout: int = 10):
        super().__init__(timeout)
        self._key = api_key

    @property
    def name(self) -> str:
        return "OTX AlienVault"

    async def check_url(self, url: str) -> SourceResult:
        started = time.time()
        data, status, error = await self._request(
            "GET", f"https://otx.alienvault.com/api/v1/indicators/url/{quote(url, safe='')}/general",
            headers={"X-OTX-API-KEY": self._key})
        if error:
            return self._error(error, started)
        count = (data.get("pulse_info") or {}).get("count", 0)
        verdict = "MALICIOUS" if count >= MALICIOUS_PULSES else "SUSPICIOUS" if count >= 1 else "CLEAN"
        return SourceResult(self.name, verdict=verdict, authoritative=False,
                            score=min(count / 10, 1.0), detections=f"{count} pulses",
                            raw={"pulse_count": count},
                            response_time_ms=int((time.time() - started) * 1000))
