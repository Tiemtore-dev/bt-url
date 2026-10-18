"""ThreatFox (abuse.ch) — IOCs communautaires avec niveau de confiance."""

import time

from bt_url.models import SourceResult
from bt_url.sources.base import BaseSource

MIN_AUTHORITATIVE_CONFIDENCE = 50


class ThreatFoxSource(BaseSource):
    def __init__(self, api_key: str, timeout: int = 10):
        super().__init__(timeout)
        self._key = api_key

    @property
    def name(self) -> str:
        return "ThreatFox"

    async def check_url(self, url: str) -> SourceResult:
        started = time.time()
        data, status, error = await self._request(
            "POST", "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": self._key},
            json_data={"query": "search_ioc", "search_term": url, "exact_match": True})
        if error:
            return self._error("Clé ABUSECH_API_KEY invalide" if status in (401, 403) else error, started)
        elapsed = int((time.time() - started) * 1000)
        iocs = data.get("data") if isinstance(data.get("data"), list) else []
        if data.get("query_status") != "ok" or not iocs:
            return SourceResult(self.name, verdict="CLEAN", detections="Non trouvé", response_time_ms=elapsed)
        conf = max((i.get("confidence_level", 0) for i in iocs), default=0)
        families = sorted({i["malware_printable"] for i in iocs if i.get("malware_printable")})
        return SourceResult(
            self.name, verdict="MALICIOUS", authoritative=conf >= MIN_AUTHORITATIVE_CONFIDENCE,
            score=conf / 100, detections=f"IOC ({', '.join(families[:3]) or 'inconnu'}), confiance {conf}%",
            raw={"max_confidence": conf, "families": families}, response_time_ms=elapsed)
