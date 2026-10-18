"""PhishTank — phishing vérifié par la communauté."""

import time

from bt_url.models import SourceResult
from bt_url.sources.base import BaseSource


def _flag(value) -> bool:
    return str(value).lower() in ("true", "1")


class PhishTankSource(BaseSource):
    rate_per_minute = 10

    def __init__(self, api_key: str = "", timeout: int = 10):
        super().__init__(timeout)
        self._key = api_key

    @property
    def name(self) -> str:
        return "PhishTank"

    async def check_url(self, url: str) -> SourceResult:
        started = time.time()
        data, status, error = await self._request(
            "POST", "https://checkurl.phishtank.com/checkurl/",
            headers={"User-Agent": "phishtank/bt-url"},
            form_data={"url": url, "format": "json", "app_key": self._key})
        if error:
            return self._error(error, started)
        elapsed = int((time.time() - started) * 1000)
        res = data.get("results", {}) if isinstance(data, dict) else {}
        in_db, verified, valid = (_flag(res.get("in_database")), _flag(res.get("verified")),
                                  _flag(res.get("valid", "true")))
        if in_db and verified and valid:
            return SourceResult(self.name, verdict="MALICIOUS", authoritative=True, score=1.0,
                                detections="Phishing vérifié",
                                raw={"phish_id": res.get("phish_id")}, response_time_ms=elapsed)
        if in_db and not verified:
            return SourceResult(self.name, verdict="SUSPICIOUS", score=0.5,
                                detections="Signalé, non vérifié", response_time_ms=elapsed)
        return SourceResult(self.name, verdict="CLEAN",
                            detections="Entrée invalidée" if in_db else "Non trouvé",
                            response_time_ms=elapsed)
