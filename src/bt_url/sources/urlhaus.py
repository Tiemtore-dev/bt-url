"""URLhaus (abuse.ch) — URLs de distribution de malware confirmées."""

import time

from bt_url.models import SourceResult
from bt_url.sources.base import BaseSource


class URLhausSource(BaseSource):
    def __init__(self, api_key: str, timeout: int = 10):
        super().__init__(timeout)
        self._key = api_key

    @property
    def name(self) -> str:
        return "URLhaus"

    async def check_url(self, url: str) -> SourceResult:
        started = time.time()
        data, status, error = await self._request(
            "POST", "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Auth-Key": self._key}, form_data={"url": url})
        if error:
            return self._error("Clé ABUSECH_API_KEY invalide" if status in (401, 403) else error, started)
        elapsed = int((time.time() - started) * 1000)
        # L'API renvoie « ok » (ou « is_listed ») avec les champs threat/url_status quand l'URL est listée.
        listed = data.get("query_status") in ("ok", "is_listed") and bool(
            data.get("threat") or data.get("url_status"))
        if not listed:
            return SourceResult(self.name, verdict="CLEAN", detections=data.get("query_status"),
                                response_time_ms=elapsed)
        return SourceResult(
            self.name, verdict="MALICIOUS", authoritative=True, score=1.0,
            detections=data.get("threat") or "URL malveillante",
            raw={"url_status": data.get("url_status"), "tags": data.get("tags") or [],
                 "date_added": data.get("date_added")},
            response_time_ms=elapsed)
