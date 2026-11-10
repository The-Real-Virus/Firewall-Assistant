"""Private bounded case construction. Native resources are called only on explicit collect."""

import hashlib
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from wfdiag.collectors.preflight import observed_host
from wfdiag.collectors.process_runner import ProcessResult
from wfdiag.collectors.protocol import (
    CollectionFrame,
    CollectionStream,
    FinishedFrame,
    RecordFrame,
    Source,
    StartedFrame,
)
from wfdiag.collectors.windows import ResourceId, current_device_mappings, run_resource
from wfdiag.contracts.enums import Completeness, Profile, SourceState
from wfdiag.contracts.models import (
    CollectionError,
    FirewallProfile,
    Host,
    Manifest,
    ManifestFile,
    NetworkInterface,
    NetworkSnapshot,
    SourceFile,
    SourceStatus,
)
from wfdiag.contracts.platform import desktop_target_eligible
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.parsers.event_xml import parse_event_xml
from wfdiag.parsers.policy_json import NativeRule, normalize_profile, normalize_rule
from wfdiag.services.cancellation import CancellationToken
from wfdiag.services.interfaces import ProgressSink
from wfdiag.storage.atomic_write import write_new_bytes
from wfdiag.storage.bundle import (
    MAX_EVENT_LINE_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_SOURCE_BYTES,
    MAX_TOTAL_BYTES,
    VerifiedBundle,
)
from wfdiag.storage.private_output import create_private_directory, verify_permission_output
from wfdiag.storage.stream_output import NewSource
from wfdiag.version import __version__


class ResourceRunner(Protocol):
    def __call__(
        self,
        resource: ResourceId,
        cancellation: CancellationToken,
        *,
        minutes: int = 10,
        stdout_consumer: Callable[[bytes], None] | None = None,
    ) -> ProcessResult: ...


FILES: dict[Source, SourceFile] = {
    "host": "host.json",
    "network": "network.json",
    "profiles": "profiles.json",
    "rules": "rules.json",
    "events": "events.ndjson",
}
STAGES: tuple[tuple[ResourceId, tuple[Source, ...]], ...] = (
    ("host", ("host", "network")),
    ("policy", ("profiles", "rules")),
    ("events", ("events",)),
)
LARGE_SOURCES: tuple[Source, ...] = ("rules", "events")


class _AuthoringBundle(VerifiedBundle):
    """Private writer validation; ordinary imports still reject interrupted directories."""

    def _check_inventory(self, expected: set[str]) -> None:
        super()._check_inventory(expected | {".incomplete"})
        assert self._directory is not None
        with self._directory.open_relative(".incomplete") as marker:
            if marker.read(256) != b'{"operation":"collect","status":"incomplete"}\n':
                raise ValueError("Authoring marker differs")


PRIORITY = {
    SourceState.EMPTY: 0,
    SourceState.COMPLETE: 0,
    SourceState.UNAVAILABLE: 1,
    SourceState.UNSUPPORTED: 2,
    SourceState.ERROR: 3,
    SourceState.ACCESS_DENIED: 4,
    SourceState.CANCELLED: 5,
    SourceState.TRUNCATED: 6,
}


class CaseBuilder:
    def __init__(
        self,
        path: Path,
        host: Host,
        mappings: Mapping[str, str],
        rules: NewSource,
        events: NewSource,
        cancellation: CancellationToken,
    ) -> None:
        self.path, self.host, self.mappings = path, host, mappings
        self.rules_output, self.events_output = rules, events
        self.cancellation = cancellation
        self.started: dict[Source, StartedFrame] = {}
        self.finished_at: dict[Source, datetime] = {}
        self.status: dict[Source, SourceStatus] = {}
        self.failures: dict[Source, SourceState] = {}
        self.codes: dict[Source, set[str]] = {}
        self.errors: dict[tuple[Source, str], int] = {}
        self.seen: dict[Source, int] = {}
        self.counts: dict[Source, int] = dict.fromkeys(FILES, 0)
        self.network: list[NetworkInterface] = []
        self.profiles: list[FirewallProfile] = []
        self.rule_ids: set[str] = set()
        self.total = 2  # Opening rules array. Reserve the footer on every record append.
        self.capped: set[Source] = set()
        self.native_host_received = False
        self.manifest_files: list[ManifestFile] = []
        self.rules_output.write(b"[\n")

    def warn(self, source: Source, code: str, state: SourceState = SourceState.ERROR) -> None:
        codes = self.codes.setdefault(source, set())
        if code in codes or len(codes) < 99:
            codes.add(code)
        else:
            codes.add("ADDITIONAL_WARNINGS_CAPPED")
            state = SourceState.TRUNCATED
        key = source, code
        if key in self.errors or len(self.errors) < 1000:
            self.errors[key] = min(100000, self.errors.get(key, 0) + 1)
        previous = self.failures.get(source, SourceState.COMPLETE)
        if PRIORITY[state] > PRIORITY[previous]:
            self.failures[source] = state

    def consume(self, frame: CollectionFrame) -> None:
        self.cancellation.check()
        source = frame.source
        if isinstance(frame, StartedFrame):
            self.started[source] = frame
        elif isinstance(frame, FinishedFrame):
            self.finished_at[source] = frame.at_utc
            self.finish_source(source, SourceState(frame.state))
            for code in frame.codes:
                # Informational audit uncertainty still appears even on an empty read.
                codes = self.codes.setdefault(source, set())
                if code in codes or len(codes) < 99:
                    codes.add(code)
                else:
                    self.warn(source, "ADDITIONAL_WARNINGS_CAPPED", SourceState.TRUNCATED)
            if frame.state not in ("complete", "empty"):
                self.warn(source, "NATIVE_SOURCE_" + frame.state.upper(), SourceState(frame.state))
        else:
            self.seen[source] = self.seen.get(source, 0) + 1
            try:
                self.record(frame)
            except ValueError:
                self.warn(source, "NORMALIZED_RECORD_REJECTED")

    def active(self, profile: Profile) -> bool | None:
        if any(i.state == "up" and i.active_profile == profile for i in self.network):
            return True
        status = self.status.get("network")
        if (
            status is not None
            and status.state in (SourceState.COMPLETE, SourceState.EMPTY)
            and all(i.active_profile is not None for i in self.network if i.state == "up")
        ):
            return False
        return None

    def append(self, source: Source, content: bytes) -> bool:
        output = self.rules_output if source == "rules" else self.events_output
        footer = 2 if source == "rules" else 0
        if source in self.capped:
            return False
        if (
            output.byte_length + len(content) + footer > MAX_SOURCE_BYTES
            or self.total + len(content) + footer
            > MAX_TOTAL_BYTES - MAX_MANIFEST_BYTES - 1024 * 1024
        ):
            self.capped.add(source)
            self.warn(source, "SOURCE_OR_TOTAL_BYTE_CAP", SourceState.TRUNCATED)
            return False
        output.write(content)
        self.total += len(content)
        return True

    def record(self, frame: RecordFrame) -> None:
        source, value = frame.source, frame.data
        number = self.seen[source]
        reference = f"{source}:{number}"
        if source == "host" and isinstance(value, Host):
            if (
                any(
                    getattr(value, field) != getattr(self.host, field)
                    for field in ("os", "architecture", "build", "windows_product_type")
                )
                or value.supported_build
            ):
                raise ValueError("Native and runtime platform observations disagree")
            self.host = value
            self.native_host_received = True
            self.counts[source] = 1
        elif source == "network" and isinstance(value, NetworkInterface):
            if value.source_ref != reference or value.interface_index in {
                i.interface_index for i in self.network
            }:
                raise ValueError("Duplicate or mismatched interface identity")
            self.network.append(value)
            self.counts[source] += 1
        elif source == "profiles" and isinstance(value, dict):
            parsed = normalize_profile(value, None, reference)
            profile = normalize_profile(value, self.active(parsed.profile), reference)
            if profile.profile in {p.profile for p in self.profiles}:
                raise ValueError("Duplicate profile")
            self.profiles.append(profile)
            self.counts[source] += 1
        elif source == "rules" and isinstance(value, NativeRule):
            rule = normalize_rule(value, frame.at_utc, reference)
            if rule.rule_id.casefold() in self.rule_ids:
                raise ValueError("Duplicate persistent rule identifier")
            if rule.filter_errors or any(fields is None for fields in value.filters.values()):
                self.warn(source, "ASSOCIATED_FILTER_INCOMPLETE")
            if "ADDITIONAL_UNSUPPORTED_CONDITION_DETAILS_CAPPED" in (
                *(rule.conditions.security or ()),
                *rule.filter_errors,
            ):
                self.warn(source, "NORMALIZED_CONDITION_DETAILS_CAPPED", SourceState.TRUNCATED)
            content = (b",\n" if self.counts[source] else b"") + rule.model_dump_json().encode()
            if self.append(source, content):
                self.rule_ids.add(rule.rule_id.casefold())
                self.counts[source] += 1
        elif source == "events" and isinstance(value, str):
            event = parse_event_xml(value.encode("utf-8"), reference, device_mappings=self.mappings)
            if (
                event.application_raw is not None
                and event.application_raw.casefold().startswith("\\device\\")
                and event.application_canonical is not None
            ):
                event = event.model_copy(
                    update={
                        "warnings": (*event.warnings[:49], "CURRENT_DEVICE_MAPPING_OBSERVATION")
                    }
                )
            content = (event.model_dump_json() + "\n").encode()
            if len(content) > MAX_EVENT_LINE_BYTES:
                self.warn(source, "NORMALIZED_EVENT_LINE_BYTE_CAP", SourceState.TRUNCATED)
            elif self.append(source, content):
                self.counts[source] += 1
        else:
            raise ValueError("Collector record type differs from its source")

    def finish_source(self, source: Source, native_state: SourceState) -> None:
        started = self.started.get(source)
        first, last = (
            (started.window_start_utc, started.window_end_utc)
            if started is not None and started.window_start_utc is not None
            else (started.at_utc, self.finished_at.get(source, datetime.now(UTC)))
            if started is not None
            else (None, None)
        )
        if first is not None and last is not None and first > last:
            first, last = None, None
            self.warn(source, "SOURCE_CLOCK_INCONSISTENT")
        failure = self.failures.get(source, SourceState.COMPLETE)
        state = failure if PRIORITY[failure] > PRIORITY[native_state] else native_state
        self.status[source] = SourceStatus(
            source=source,
            state=state,
            window_start_utc=first,
            window_end_utc=last,
            records=self.counts[source],
            warnings=tuple(sorted(self.codes.get(source, set())))[:100],
        )

    def resource_finished(
        self, sources: tuple[Source, ...], code: str | None, state: SourceState = SourceState.ERROR
    ) -> None:
        for source in sources:
            if code is not None:
                self.warn(source, code, state)
            existing = self.status.get(source)
            self.finish_source(
                source, existing.state if existing is not None else SourceState.ERROR
            )

    def write_metadata(self, source: Source, content: bytes) -> None:
        if self.total + len(content) > MAX_TOTAL_BYTES - MAX_MANIFEST_BYTES:
            raise ValueError("Case metadata exceeds the actual total byte budget")
        filename = FILES[source]
        write_new_bytes(self.path / filename, content, byte_limit=MAX_SOURCE_BYTES)
        self.total += len(content)
        self.manifest_files.append(
            ManifestFile(
                filename=filename,
                byte_length=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )

    def host_finished(self) -> None:
        if not self.native_host_received:
            self.warn("host", "PYTHON_PLATFORM_METADATA_ONLY")
            self.counts["host"] = (
                1  # Actual prior runtime observation; never a fabricated empty Host.
            )
            self.finish_source("host", SourceState.ERROR)
        self.write_metadata("host", (self.host.model_dump_json() + "\n").encode())
        observed = (
            self.started["network"].at_utc if "network" in self.started else datetime.now(UTC)
        )
        network = NetworkSnapshot(observed_at_utc=observed, interfaces=tuple(self.network))
        self.write_metadata("network", (network.model_dump_json() + "\n").encode())


def collect_case(
    path: Path,
    minutes: int,
    cancellation: CancellationToken,
    progress: ProgressSink,
    *,
    host: Host,
    runner: ResourceRunner,
    mappings: Mapping[str, str],
    audit_codes: tuple[str, ...] = (),
    permission_directory: bool = False,
) -> Manifest:
    """Internal orchestration seam for explicit fixture adapters; CLI cannot select a runner."""
    if type(minutes) is not int or not 1 <= minutes <= 60:
        raise ValueError("Lookback must be one to sixty minutes")
    if not desktop_target_eligible(host):
        raise DiagnosticError(
            ExitCode.UNSUPPORTED,
            "Native collection requires an eligible Windows10/11 x64 desktop host; offline analysis remains available.",
        )
    cancellation.check()
    held = (
        verify_permission_output(path) if permission_directory else create_private_directory(path)
    )
    try:
        write_new_bytes(path / ".incomplete", b'{"operation":"collect","status":"incomplete"}\n')
        with (
            NewSource(path / "rules.json", MAX_SOURCE_BYTES) as rules,
            NewSource(path / "events.ndjson", MAX_SOURCE_BYTES) as events,
        ):
            builder = CaseBuilder(path, host, mappings, rules, events, cancellation)
            builder.codes["events"] = set(audit_codes)
            for resource, sources in STAGES:
                progress("collect-" + resource, None, None)
                stream = CollectionStream(sources, builder.consume)
                result: ProcessResult | None = None
                issue = None
                state = SourceState.ERROR
                try:
                    result = runner(
                        resource, cancellation, minutes=minutes, stdout_consumer=stream.feed
                    )
                    cancellation.check()
                    stream.finish()
                except (OSError, ValueError) as error:
                    from wfdiag.collectors.failures import exception_failure

                    issue, state = exception_failure(error)
                cancellation.check()
                if result is not None:
                    if result.cancelled:
                        raise DiagnosticError(
                            ExitCode.INCOMPLETE,
                            "Collector stopped before completion; output remains interrupted.",
                        )
                    elif (
                        result.output_truncated
                        or result.timed_out
                        or result.read_failed
                        or result.return_code != 0
                    ):
                        from wfdiag.collectors.failures import classify_failure

                        issue, state = classify_failure(result)
                    if result.return_code != 0:
                        for source in sources:
                            builder.warn(
                                source,
                                f"COLLECTOR_EXIT_{result.return_code & 0xFFFFFFFF:08X}",
                                state,
                            )
                builder.resource_finished(sources, issue, state)
                if resource == "host":
                    builder.host_finished()
                elif resource == "policy":
                    builder.write_metadata(
                        "profiles",
                        (
                            "[" + ",".join(p.model_dump_json() for p in builder.profiles) + "]\n"
                        ).encode(),
                    )
            rules.write(b"]\n")
            builder.total += 2
        for source, output in zip(LARGE_SOURCES, (rules, events), strict=True):
            builder.manifest_files.append(
                ManifestFile(
                    filename=FILES[source],
                    byte_length=output.byte_length,
                    sha256=output.digest.hexdigest(),
                )
            )
        from wfdiag.collectors.failures import FAILURE_MESSAGES

        errors = tuple(
            CollectionError(
                source=source,
                code=code,
                summary=FAILURE_MESSAGES.get(
                    code,
                    "Recorded evidence limitation; review the source status and approved collection conditions.",
                ),
                occurrences=count,
            )
            for (source, code), count in sorted(builder.errors.items())
        )
        content = ("[" + ",".join(e.model_dump_json() for e in errors) + "]\n").encode()
        write_new_bytes(path / "collection-errors.json", content, byte_limit=1024 * 1024)
        builder.total += len(content)
        builder.manifest_files.append(
            ManifestFile(
                filename="collection-errors.json",
                byte_length=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
        statuses = tuple(builder.status[source] for source in FILES) + (
            SourceStatus(
                source="collection-errors",
                state=SourceState.COMPLETE if errors else SourceState.EMPTY,
                window_start_utc=None,
                window_end_utc=None,
                records=len(errors),
            ),
        )
        incomplete = any(
            s.state == SourceState.TRUNCATED
            or (s.source != "network" and s.state not in (SourceState.COMPLETE, SourceState.EMPTY))
            for s in statuses
        )
        manifest = Manifest(
            run_id=str(uuid4()),
            collector_version=__version__,
            collected_at_utc=datetime.now(UTC),
            policy_snapshot_utc=builder.started["rules"].at_utc
            if "rules" in builder.started
            else None,
            policy_change_observed=None,
            host=builder.host,
            completeness=Completeness.INCOMPLETE if incomplete else Completeness.COMPLETE,
            sources=statuses,
            files=tuple(builder.manifest_files),
        )
        encoded = (manifest.model_dump_json(indent=2) + "\n").encode()
        if builder.total + len(encoded) > MAX_TOTAL_BYTES:
            raise ValueError("Actual complete case exceeds the total byte budget")
        cancellation.check()
        write_new_bytes(path / "manifest.json", encoded, byte_limit=MAX_MANIFEST_BYTES)
        # Validate the produced data through the same held-file reader used on import.
        # The marker stays present until this check and cancellation check both finish.
        with _AuthoringBundle(path, cancellation) as verified:
            for _ in verified.iter_events():
                pass
        cancellation.check()
        if held is not None:
            held.close()
            held = None
        (path / ".incomplete").unlink()
        return manifest
    finally:
        if held is not None:
            held.close()


def collect_native_case(
    path: Path,
    minutes: int,
    cancellation: CancellationToken,
    progress: ProgressSink,
    *,
    permission_directory: bool = False,
) -> Manifest:
    if type(minutes) is not int or not 1 <= minutes <= 60:
        raise ValueError("Lookback must be one to sixty minutes")
    cancellation.check()
    if sys.platform != "win32":
        raise DiagnosticError(
            ExitCode.UNSUPPORTED,
            "Local collection requires Windows; offline analysis remains available.",
        )
    window_end = datetime.now(UTC)
    host = observed_host()
    if not desktop_target_eligible(host):
        raise DiagnosticError(
            ExitCode.UNSUPPORTED, "Host is outside the configured Windows10/11 x64 desktop target."
        )
    from wfdiag.collectors.audit_policy import failure_audit_codes

    audit_codes = failure_audit_codes()

    def native_runner(
        resource: ResourceId,
        cancellation: CancellationToken,
        *,
        minutes: int = 10,
        stdout_consumer: Callable[[bytes], None] | None = None,
    ) -> ProcessResult:
        return run_resource(
            resource,
            cancellation,
            minutes=minutes,
            event_end=window_end if resource == "events" else None,
            stdout_consumer=stdout_consumer,
        )

    manifest = collect_case(
        path,
        minutes,
        cancellation,
        progress,
        host=host,
        runner=native_runner,
        mappings=current_device_mappings(),
        audit_codes=audit_codes,
        permission_directory=permission_directory,
    )
    return manifest
