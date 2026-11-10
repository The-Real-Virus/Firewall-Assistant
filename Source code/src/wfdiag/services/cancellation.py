"""Cooperative cancellation; does not claim a Windows child has already stopped."""

from threading import Event

from wfdiag.errors import DiagnosticError, ExitCode


class Cancelled(DiagnosticError):
    def __init__(self) -> None:
        super().__init__(
            ExitCode.INCOMPLETE, "Operation cancelled; output is not a completed result."
        )


class CancellationToken:
    def __init__(self) -> None:
        self._requested = Event()

    @property
    def requested(self) -> bool:
        return self._requested.is_set()

    def request(self) -> None:
        self._requested.set()

    def check(self) -> None:
        if self.requested:
            raise Cancelled()
