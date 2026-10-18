"""Briques de protection du service : limitation de débit, budget quotidien, cache (single-flight)."""

import asyncio
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable, Optional


class RateLimited(Exception):
    def __init__(self, retry_after: int, scope: str):
        super().__init__(f"limite atteinte ({scope})")
        self.retry_after = max(1, int(retry_after))
        self.scope = scope


class SlidingWindow:
    """Fenêtre glissante : au plus `limit` événements sur `window` secondes, par clé."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic,
                 max_keys: int = 10_000):
        self.limit, self.window, self._clock, self._max_keys = limit, window, clock, max_keys
        self._events: "OrderedDict[str, deque[float]]" = OrderedDict()

    def _prune(self, key: str, now: float) -> deque:
        dq = self._events.setdefault(key, deque())
        while dq and now - dq[0] >= self.window:
            dq.popleft()
        return dq

    def retry_after(self, key: str = "") -> int:
        """0 si un événement est permis maintenant, sinon secondes à attendre."""
        now = self._clock()
        dq = self._prune(key, now)
        if len(dq) < self.limit:
            return 0
        return int(self.window - (now - dq[0])) + 1

    def record(self, key: str = "") -> None:
        now = self._clock()
        self._prune(key, now).append(now)
        self._events.move_to_end(key)
        while len(self._events) > self._max_keys:  # borne mémoire
            self._events.popitem(last=False)


class DailyBudget:
    """Compteur réinitialisé à minuit UTC : protège les quotas des API tierces."""

    def __init__(self, limit: int, today: Callable[[], int] = lambda: int(time.time() // 86400)):
        self.limit, self._today = limit, today
        self._day, self.used = today(), 0

    def _roll(self) -> None:
        if self._today() != self._day:
            self._day, self.used = self._today(), 0

    def remaining(self) -> int:
        self._roll()
        return max(0, self.limit - self.used)

    def seconds_until_reset(self) -> int:
        return int(86400 - (time.time() % 86400)) + 1

    def consume(self) -> None:
        self._roll()
        self.used += 1


@dataclass
class Limits:
    per_ip_minute: SlidingWindow
    per_ip_hour: SlidingWindow
    global_minute: SlidingWindow
    daily: DailyBudget

    def check_and_consume(self, ip: str) -> None:
        """Vérifie TOUS les plafonds avant d'en consommer un seul (pas de consommation partielle)."""
        for scope, win, key in (("ip_minute", self.per_ip_minute, ip),
                                ("ip_hour", self.per_ip_hour, ip),
                                ("global_minute", self.global_minute, "*")):
            wait = win.retry_after(key)
            if wait:
                raise RateLimited(wait, scope)
        if self.daily.remaining() <= 0:
            raise RateLimited(self.daily.seconds_until_reset(), "daily_budget")
        self.per_ip_minute.record(ip)
        self.per_ip_hour.record(ip)
        self.global_minute.record("*")
        self.daily.consume()


class TTLCache:
    """Cache LRU borné avec expiration par entrée."""

    def __init__(self, max_entries: int = 1000, clock: Callable[[], float] = time.monotonic):
        self._data: "OrderedDict[str, tuple[float, float, dict]]" = OrderedDict()
        self._max, self._clock = max_entries, clock

    def get(self, key: str) -> Optional[tuple[dict, int]]:
        item = self._data.get(key)
        if item is None:
            return None
        stored, expires, value = item
        now = self._clock()
        if now >= expires:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value, int(now - stored)

    def set(self, key: str, value: dict, ttl: float) -> None:
        now = self._clock()
        self._data[key] = (now, now + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


def new_inflight() -> dict[str, "asyncio.Future"]:
    return {}
