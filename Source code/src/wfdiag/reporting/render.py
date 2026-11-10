"""Escaped streaming static reports; no scripts, external assets or active data links."""

from collections.abc import Iterable, Iterator
from importlib.resources import files
from typing import Literal

from jinja2 import Environment, StrictUndefined

from wfdiag.contracts.enums import Category
from wfdiag.contracts.models import Analysis, Finding, TextLogResult
from wfdiag.reporting.limits import report_byte_limit
from wfdiag.reporting.share import share_report_parts
from wfdiag.services.cancellation import CancellationToken
from wfdiag.storage.analysis_json import analysis_json_chunks, text_log_json_chunks

REPORT_BUFFER_BYTES = 64 * 1024

SUMMARY = {
    Category.EXPLICIT_BLOCK: "Explicit block evidence; route to the policy owner.",
    Category.DEFAULT_BLOCK: "Default block evidence; review the private eligibility details.",
    Category.PROFILE_MISMATCH: "Allow candidates cover another profile.",
    Category.LOCAL_RULE_MERGE_RESTRICTED: "Local rule merging is restricted.",
    Category.UNRESOLVED_WFP_BLOCK: "The blocking filter is unresolved.",
    Category.EVIDENCE_GAP: "Required evidence is missing or unsupported.",
    Category.NO_RELEVANT_EVENT: "No relevant event was established; this does not prove a healthy connection.",
}


class _EventTexts:
    def __init__(self, findings: tuple[Finding, ...]) -> None:
        self.findings = findings

    def __getitem__(self, index: int) -> str:
        event = self.findings[index].event
        return event.model_dump_json(indent=2) if event is not None else "null"


def _text_log_chunks(log: TextLogResult | None, token: CancellationToken) -> Iterator[str]:
    if log is None:
        return
    for chunk in text_log_json_chunks(log, token):
        yield chunk.decode("utf-8")


def _encoded_chunks(parts: Iterable[str], token: CancellationToken) -> Iterator[bytes]:
    buffer = bytearray()
    for part in parts:
        token.check()
        raw = part.encode("utf-8")
        offset = 0
        while offset < len(raw):
            token.check()
            count = min(REPORT_BUFFER_BYTES - len(buffer), len(raw) - offset)
            buffer.extend(raw[offset : offset + count])
            offset += count
            if len(buffer) == REPORT_BUFFER_BYTES:
                yield bytes(buffer)
                buffer.clear()
    token.check()
    if buffer:
        yield bytes(buffer)


def iter_report_chunks(
    analysis: Analysis,
    *,
    mode: Literal["share", "full"],
    format: Literal["html", "json"],
    cancellation: CancellationToken | None = None,
) -> Iterator[bytes]:
    """Services write these chunks atomically under their declared output byte cap."""
    if mode not in ("share", "full") or format not in ("html", "json"):
        raise ValueError("Select a supported report mode and format")
    token = cancellation or CancellationToken()
    token.check()
    if mode == "full" and format == "json":
        yield from analysis_json_chunks(analysis, token, include_metadata_defaults=True)
        return
    if mode == "share":
        header, findings = share_report_parts(analysis, token)
        if format == "json":
            yield header.model_dump_json(exclude={"findings"}).encode("utf-8")[:-1]
            yield b',"findings":['
            for index, finding in enumerate(findings):
                token.check()
                if index:
                    yield b","
                yield finding.model_dump_json().encode("utf-8")
            yield b"]}\n"
            return
        payload = header.model_dump(mode="json", exclude={"findings"})
        payload["findings"] = (finding.model_dump(mode="json") for finding in findings)
    else:
        payload = analysis.model_dump(
            mode="json", exclude={"findings", "policy_rules", "firewall_log"}
        )
        payload["findings"] = (finding.model_dump(mode="json") for finding in analysis.findings)
        payload["firewall_log"] = analysis.firewall_log is not None
    environment = Environment(autoescape=True, undefined=StrictUndefined, auto_reload=False)
    template = environment.from_string(
        files("wfdiag").joinpath("resources/templates/report.html.j2").read_text(encoding="utf-8")
    )
    parts = template.generate(
        mode=mode,
        data=payload,
        summaries=SUMMARY,
        intent_text=analysis.intent.model_dump_json(indent=2)
        if mode == "full" and analysis.intent is not None
        else "",
        event_texts=_EventTexts(analysis.findings),
        text_log_chunks=_text_log_chunks(analysis.firewall_log, token),
    )
    yield from _encoded_chunks(parts, token)


def render_report(
    analysis: Analysis,
    *,
    mode: Literal["share", "full"],
    format: Literal["html", "json"],
    byte_limit: int | None = None,
) -> bytes:
    """Bounded compatibility helper; operations use the streaming iterator directly."""
    maximum = report_byte_limit(format)
    limit = maximum if byte_limit is None else byte_limit
    if type(limit) is not int or not 0 < limit <= maximum:
        raise ValueError("Invalid report byte budget")
    body = bytearray()
    for chunk in iter_report_chunks(analysis, mode=mode, format=format):
        if len(body) + len(chunk) > limit:
            raise ValueError("Report output exceeds its byte budget")
        body.extend(chunk)
    return bytes(body)
