"""Single-process operational quota counters; no incidents, indicators or secrets."""

import threading
import time
from collections import deque


class IntelBudget:
    """Reserve immediately or decline; never sleep inside an investigation.

    Rolling 24h is deliberately conservative relative to a provider calendar day.
    This process cannot account for other workers, restarts or external key users.
    """

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._requests = deque(maxlen=500)
        self._blocked_until = 0.0
        self._lock = threading.Lock()

    def reserve(self):
        with self._lock:
            now = self._clock()
            while self._requests and now - self._requests[0] >= 86400:
                self._requests.popleft()
            if now < self._blocked_until:
                return "unavailable_provider_cooldown"
            if len(self._requests) >= 500:
                return "unavailable_daily_limit"
            if sum(now - sent < 60 for sent in self._requests) >= 4:
                return "unavailable_minute_limit"
            self._requests.append(now)
            return None

    def cool_down(self, seconds=60):
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._clock() + min(max(seconds, 1), 86400))
