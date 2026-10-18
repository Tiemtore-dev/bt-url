"""Google Safe Browsing v4."""

import time

from bt_url.models import SourceResult
from bt_url.sources.base import BaseSource


class GoogleSafeBrowsingSource(BaseSource):
    def __init__(self, api_key: str, timeout: int = 10):
        super().__init__(timeout)
        self._key = api_key

    @property
    def name(self) -> str:
        return "Google Safe Browsing"

    async def check_url(self, url: str) -> SourceResult:
        started = time.time()
        payload = {
            "client": {"clientId": "bt-url", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        data, status, error = await self._request(
            "POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": self._key}, json_data=payload)
        if error:
            return self._error(error, started)
        elapsed = int((time.time() - started) * 1000)
        matches = data.get("matches", [])
        if not matches:
            return SourceResult(self.name, verdict="CLEAN", score=0.0,
                                detections="Aucune menace détectée", response_time_ms=elapsed)
        types = sorted({m.get("threatType", "") for m in matches})
        return SourceResult(self.name, verdict="MALICIOUS", authoritative=True, score=1.0,
                            detections=", ".join(types), raw={"threat_types": types},
                            response_time_ms=elapsed)
