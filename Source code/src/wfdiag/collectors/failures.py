"""Classify bounded collector failures without persisting private stderr."""

from wfdiag.collectors.process_runner import ProcessResult
from wfdiag.contracts.enums import SourceState
from wfdiag.errors import DiagnosticError, ExitCode

FAILURE_MESSAGES = {
    "COLLECTOR_RESOURCE_INVALID": "A fixed collector resource does not match this engine. Restore the complete matching trusted application folder; modified scripts were not executed.",
    "COLLECTOR_SCRIPT_POLICY_BLOCKED": "Windows blocked the collector script under its script-signing or execution policy. No policy was changed. Use your administrator's approved signed-collector setup.",
    "COLLECTOR_ACCESS_DENIED": "Windows denied access to a required source. Use an authorized collection process; the application does not elevate itself.",
    "COLLECTOR_DEPENDENCY_MISSING": "A required Windows collection component or module is unavailable.",
    "COLLECTOR_SCRIPT_INVALID": "The installed collection script could not be parsed. Restore the complete matching application folder and report this code.",
    "COLLECTOR_START_FAILED": "Windows could not start or safely own the collector process. Check the matching application installation and endpoint protection with your administrator.",
    "COLLECTOR_STREAM_INVALID": "The collector output was incomplete or invalid. Keep the matching application files together and preserve this incomplete capture for review.",
    "COLLECTOR_PROCESS_OR_STREAM_FAILED": "A Windows collector failed or returned an invalid stream. The capture is incomplete; no successful diagnosis is claimed.",
    "COLLECTOR_TIMEOUT": "The Windows collector exceeded its time limit. The capture is incomplete.",
    "COLLECTOR_OUTPUT_CAP": "The evidence window exceeded its output limit. Use a shorter lookback or review the incomplete capture.",
}


class ResourceIntegrityError(ValueError):
    """A fixed collection resource differs from the engine's reviewed content."""


class CollectorProbeFailure(DiagnosticError):
    def __init__(self, reason: str, *, process_exit: int | None = None) -> None:
        self.reason = reason if reason in FAILURE_MESSAGES else "COLLECTOR_PROCESS_OR_STREAM_FAILED"
        super().__init__(
            ExitCode.ACCESS_DENIED
            if self.reason in ("COLLECTOR_SCRIPT_POLICY_BLOCKED", "COLLECTOR_ACCESS_DENIED")
            else ExitCode.UNSUPPORTED,
            FAILURE_MESSAGES[self.reason]
            + (
                f" Process status: 0x{process_exit & 0xFFFFFFFF:08X}."
                if process_exit is not None
                else ""
            ),
        )


def exception_failure(error: OSError | ValueError) -> tuple[str, SourceState]:
    # Classify only stable numeric OS errors, never a path/message/traceback.
    if isinstance(error, ResourceIntegrityError):
        return "COLLECTOR_RESOURCE_INVALID", SourceState.ERROR
    if isinstance(error, OSError):
        if isinstance(error, PermissionError) or getattr(error, "winerror", None) in (5, 1314):
            return "COLLECTOR_ACCESS_DENIED", SourceState.ACCESS_DENIED
        if isinstance(error, FileNotFoundError) or getattr(error, "winerror", None) in (2, 3, 126):
            return "COLLECTOR_DEPENDENCY_MISSING", SourceState.ERROR
        return "COLLECTOR_START_FAILED", SourceState.ERROR
    return "COLLECTOR_STREAM_INVALID", SourceState.ERROR


def classify_failure(result: ProcessResult) -> tuple[str, SourceState]:
    if result.output_truncated:
        return "COLLECTOR_OUTPUT_CAP", SourceState.TRUNCATED
    if result.timed_out:
        return "COLLECTOR_TIMEOUT", SourceState.ERROR
    raw = result.stderr[:16384]
    # Recognize stable exception/code identifiers and a few standard messages.
    # Neither the decoded text nor arguments/paths are returned or persisted.
    text = (
        raw.decode("utf-8", errors="ignore") + raw.decode("utf-16-le", errors="ignore")
    ).casefold()
    if any(
        s in text
        for s in ("pssecurityexception", "running scripts is disabled", "is not digitally signed")
    ):
        return "COLLECTOR_SCRIPT_POLICY_BLOCKED", SourceState.ACCESS_DENIED
    if any(
        s in text for s in ("unauthorizedaccessexception", "access is denied", "permissiondenied")
    ):
        return "COLLECTOR_ACCESS_DENIED", SourceState.ACCESS_DENIED
    if any(
        s in text
        for s in ("modules_modulenotfound", "couldnotautoloadmodule", "commandnotfoundexception")
    ):
        return "COLLECTOR_DEPENDENCY_MISSING", SourceState.ERROR
    if "parsererror" in text:
        return "COLLECTOR_SCRIPT_INVALID", SourceState.ERROR
    return "COLLECTOR_PROCESS_OR_STREAM_FAILED", SourceState.ERROR
