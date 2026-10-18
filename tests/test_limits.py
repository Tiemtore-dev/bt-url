import pytest

from bt_url.api.limits import DailyBudget, Limits, RateLimited, SlidingWindow, TTLCache


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_sliding_window_blocks_then_releases():
    c = Clock()
    w = SlidingWindow(2, 60, clock=c)
    for _ in range(2):
        assert w.retry_after("a") == 0
        w.record("a")
    assert 0 < w.retry_after("a") <= 61
    c.t += 61
    assert w.retry_after("a") == 0


def test_sliding_window_is_per_key():
    w = SlidingWindow(1, 60, clock=Clock())
    w.record("a")
    assert w.retry_after("a") > 0 and w.retry_after("b") == 0


def test_sliding_window_bounds_memory():
    w = SlidingWindow(1, 60, clock=Clock(), max_keys=3)
    for i in range(10):
        w.record(f"ip{i}")
    assert len(w._events) == 3


def make_limits(c, ip_min=2, ip_hour=5, glob=3, daily=4, today=lambda: 0):
    return Limits(SlidingWindow(ip_min, 60, c), SlidingWindow(ip_hour, 3600, c),
                  SlidingWindow(glob, 60, c), DailyBudget(daily, today))


def test_limits_per_ip_minute():
    c = Clock()
    lim = make_limits(c)
    lim.check_and_consume("1.1.1.1")
    lim.check_and_consume("1.1.1.1")
    with pytest.raises(RateLimited) as e:
        lim.check_and_consume("1.1.1.1")
    assert e.value.scope == "ip_minute" and e.value.retry_after >= 1
    lim.check_and_consume("2.2.2.2")  # un autre client n'est pas bloqué


def test_global_limit_protects_third_party_quota():
    lim = make_limits(Clock(), ip_min=10, ip_hour=10, glob=2)
    lim.check_and_consume("a")
    lim.check_and_consume("b")
    with pytest.raises(RateLimited) as e:
        lim.check_and_consume("c")
    assert e.value.scope == "global_minute"


def test_daily_budget_exhaustion_and_reset():
    day = [0]
    lim = make_limits(Clock(), ip_min=99, ip_hour=99, glob=99, daily=2, today=lambda: day[0])
    lim.check_and_consume("a")
    lim.check_and_consume("b")
    with pytest.raises(RateLimited) as e:
        lim.check_and_consume("c")
    assert e.value.scope == "daily_budget"
    day[0] = 1
    lim.check_and_consume("c")


def test_rejected_request_consumes_nothing():
    c = Clock()
    lim = make_limits(c, ip_min=1, glob=10, daily=10)
    lim.check_and_consume("a")
    used = lim.daily.used
    with pytest.raises(RateLimited):
        lim.check_and_consume("a")
    assert lim.daily.used == used and lim.global_minute.retry_after("*") == 0


def test_cache_expiry_and_age():
    c = Clock()
    cache = TTLCache(10, clock=c)
    cache.set("k", {"v": 1}, ttl=10)
    c.t += 4
    value, age = cache.get("k")
    assert value == {"v": 1} and age == 4
    c.t += 7
    assert cache.get("k") is None and len(cache) == 0


def test_cache_lru_eviction():
    cache = TTLCache(2, clock=Clock())
    cache.set("a", {}, 100)
    cache.set("b", {}, 100)
    cache.get("a")
    cache.set("c", {}, 100)
    assert cache.get("b") is None and cache.get("a") is not None
