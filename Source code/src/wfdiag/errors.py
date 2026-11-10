"""Stable public errors without raw exception or case disclosure."""

from enum import IntEnum


class ExitCode(IntEnum):
    COMPLETED = 0
    INVALID_INPUT = 2
    UNSUPPORTED = 3
    ACCESS_DENIED = 4
    INCOMPLETE = 5
    INTERNAL = 6


class DiagnosticError(Exception):
    def __init__(self, code: ExitCode, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


class OperationUnavailable(DiagnosticError):
    def __init__(self, operation: str) -> None:
        super().__init__(
            ExitCode.UNSUPPORTED,
            f"The {operation} operation is not implemented in this development build.",
        )
