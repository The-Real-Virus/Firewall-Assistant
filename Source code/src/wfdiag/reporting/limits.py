"""Explicit output budgets; HTML expansion does not change input or analysis limits."""

from typing import Literal

from wfdiag.storage.records import MAX_ANALYSIS_BYTES

MAX_JSON_REPORT_BYTES = MAX_ANALYSIS_BYTES
MAX_HTML_REPORT_BYTES = 256 * 1024 * 1024


def report_byte_limit(format: Literal["html", "json"]) -> int:
    if format == "html":
        return MAX_HTML_REPORT_BYTES
    if format == "json":
        return MAX_JSON_REPORT_BYTES
    raise ValueError("Select a supported report format")
