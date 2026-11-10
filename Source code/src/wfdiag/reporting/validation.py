"""Validate complete generated share files without retaining every viewless report row."""

from pathlib import Path

from wfdiag.reporting.limits import MAX_JSON_REPORT_BYTES
from wfdiag.reporting.share import ShareFinding, ShareReport
from wfdiag.storage.analysis_json import model_array_data_from_checked_json
from wfdiag.storage.records import read_checked_record

MAX_INLINE_REPORT_BYTES = 4 * 1024 * 1024
MAX_METADATA_CHARACTERS = 256 * 1024
MAX_FINDING_CHARACTERS = 64 * 1024


def validate_share_report(path: Path) -> int:
    """Every row/header validates; count is checked against the actual declared schema.

    ShareReport currently has no cross-row invariant beyond max count. Review this
    incremental validator whenever that contract gains one. This returns no partial
    ShareReport as a full report; callers retain only the original validated file path.
    """
    count = 0
    maximum = ShareReport.model_json_schema()["properties"]["findings"]["maxItems"]
    if type(maximum) is not int:
        raise ValueError("Declared report row budget is unavailable")

    def consume(_finding: ShareFinding, _start: int, _end: int) -> None:
        nonlocal count
        count += 1

    def decode(text: str) -> ShareReport:
        fields = model_array_data_from_checked_json(
            text,
            ShareReport,
            ShareFinding,
            maximum_items=maximum,
            item_consumer=consume,
            retain_items=False,
            metadata_character_limit=MAX_METADATA_CHARACTERS,
            item_character_limit=MAX_FINDING_CHARACTERS,
        )
        return ShareReport.model_validate(fields, strict=True)

    read_checked_record(path, byte_limit=MAX_JSON_REPORT_BYTES, decode=decode)
    return count
