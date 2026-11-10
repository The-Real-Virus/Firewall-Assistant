"""Typed service boundary shared by CLI and future desktop worker."""

from typing import Protocol

from wfdiag.contracts.desktop_job import DesktopRequest
from wfdiag.contracts.enums import Completeness
from wfdiag.services.cancellation import CancellationToken


class ProgressSink(Protocol):
    def __call__(self, stage: str, completed: int | None, total: int | None) -> None: ...


class OperationService(Protocol):
    def execute(
        self,
        request: DesktopRequest,
        cancellation: CancellationToken,
        progress: ProgressSink,
    ) -> Completeness: ...
