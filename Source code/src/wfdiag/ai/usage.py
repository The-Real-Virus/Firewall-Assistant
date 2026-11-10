"""In-memory request counter with an optional explicit test allowance."""

import threading

from wfdiag.ai.contracts import AiErrorCode
from wfdiag.ai.policy import AiFailure


class Allowance:
    def __init__(self, limit: int | None = None) -> None:
        if limit is not None and not 1 <= limit <= 1000:
            raise ValueError("Invalid session request limit")
        self.limit = limit
        self._attempts = 0
        self._active = False
        self._lock = threading.Lock()

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

    def begin(self) -> None:
        with self._lock:
            if self._active:
                raise AiFailure(AiErrorCode.CONFIGURATION)
            if self.limit is not None and self._attempts >= self.limit:
                raise AiFailure(AiErrorCode.QUOTA)
            self._attempts += 1
            self._active = True

    def finish(self) -> None:
        with self._lock:
            self._active = False

    def reset(self) -> None:
        with self._lock:
            if self._active:
                raise AiFailure(AiErrorCode.CONFIGURATION)
            self._attempts = 0
