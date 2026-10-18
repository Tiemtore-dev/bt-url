"""Socle des sources TI : requêtes HTTP avec timeout, retry/backoff et rate limiting."""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Optional

import aiohttp

from bt_url.models import SourceResult

_RETRYABLE = {429, 500, 502, 503}
_MAX_RETRIES = 3
_BACKOFF = 1.5


class _RateLimiter:
    """Fenêtre glissante de 60 s, partagée par nom de source."""

    _times: dict[str, list[float]] = {}

    @classmethod
    async def wait(cls, name: str, per_minute: int) -> None:
        now = time.monotonic()
        window = [t for t in cls._times.get(name, []) if now - t < 60]
        if len(window) >= per_minute:
            await asyncio.sleep(60 - (now - window[0]) + 0.1)
            now = time.monotonic()
            window = [t for t in window if now - t < 60]
        window.append(now)
        cls._times[name] = window


class BaseSource(ABC):
    rate_per_minute = 30

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def check_url(self, url: str) -> SourceResult: ...

    def _error(self, msg: str, started: float) -> SourceResult:
        return SourceResult(self.name, verdict="ERROR", error=msg,
                            response_time_ms=int((time.time() - started) * 1000))

    async def _request(self, method: str, url: str, *, headers: Optional[dict] = None,
                       json_data: Optional[dict] = None, form_data: Optional[dict] = None,
                       params: Optional[dict] = None) -> tuple[Optional[dict], int, Optional[str]]:
        """Retourne (json, status, erreur). 404 n'est pas retenté."""
        await _RateLimiter.wait(self.name, self.rate_per_minute)
        status, error = 0, None
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 5))
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.request(method, url, headers=headers or {}, json=json_data,
                                               data=form_data, params=params) as resp:
                        status = resp.status
                        if 200 <= status < 300:
                            try:
                                return await resp.json(content_type=None), status, None
                            except Exception:
                                return {"raw_text": await resp.text()}, status, None
                        if status in _RETRYABLE and attempt < _MAX_RETRIES:
                            await asyncio.sleep(_BACKOFF ** attempt)
                            continue
                        return None, status, f"HTTP {status}"
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                error = f"Erreur réseau : {type(e).__name__}"
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(_BACKOFF ** attempt)
        return None, status, error
