"""Local synthetic engine measurements; never certifies the reference VM or native collection.

Run from Product with its reviewed Python: scripts/benchmark_analysis.py --events 100000
--samples 3. Smaller inputs are explicitly labelled smoke measurements. This helper is
not shipped. It reads only bundled synthetic examples and writes a fresh ignored directory.
"""

import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from wfdiag.analysis.engine import analyze_case
from wfdiag.contracts.models import Event, Manifest
from wfdiag.storage.analysis_json import analysis_json_chunks
from wfdiag.storage.atomic_write import write_new_chunks
from wfdiag.storage.bundle import MAX_EVENTS, MAX_SOURCE_BYTES, MAX_TOTAL_BYTES, VerifiedBundle
from wfdiag.storage.records import MAX_ANALYSIS_BYTES, read_intent

ROOT = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024
SECONDS_TARGET = 60
WORKING_SET_TARGET = 512 * MIB
# Harness safety stops, distinct from the unchanged acceptance targets above.
HARNESS_SECONDS = 180
HARNESS_MEMORY = 2 * 1024 * MIB


class MemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("PageFaultCount", ctypes.c_uint32),
        *[
            (name, ctypes.c_size_t)
            for name in (
                "PeakWorkingSetSize",
                "WorkingSetSize",
                "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage",
                "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage",
                "PagefileUsage",
                "PeakPagefileUsage",
            )
        ],
    ]


def memory_counters():
    """Absolute OS counters for this process, including interpreter/import overhead."""
    if sys.platform != "win32":
        raise RuntimeError("Windows working-set measurement is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    current = kernel.GetCurrentProcess
    current.argtypes = []
    current.restype = ctypes.c_void_p
    query = kernel.K32GetProcessMemoryInfo
    query.argtypes = [ctypes.c_void_p, ctypes.POINTER(MemoryCounters), ctypes.c_uint32]
    query.restype = ctypes.c_int
    counters = MemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    if not query(current(), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return {
        "peak_working_set_bytes": counters.PeakWorkingSetSize,
        "working_set_bytes": counters.WorkingSetSize,
        "peak_commit_bytes": counters.PeakPagefileUsage,
    }


def host_facts():
    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_uint32),
            ("load", ctypes.c_uint32),
            *[
                (n, ctypes.c_uint64)
                for n in (
                    "total_physical",
                    "available_physical",
                    "total_pagefile",
                    "available_pagefile",
                    "total_virtual",
                    "available_virtual",
                    "available_extended",
                )
            ],
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GlobalMemoryStatusEx
    query.argtypes = [ctypes.POINTER(MemoryStatus)]
    query.restype = ctypes.c_int
    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not query(ctypes.byref(status)):
        raise ctypes.WinError(ctypes.get_last_error())
    return {
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "cpu": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "total_physical_bytes": status.total_physical,
        "python": sys.version,
        "reference_vm_acceptance": "blocked; development host, not approved reference VM",
    }


def save_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def generate_case(destination, count):
    if not 1 <= count <= MAX_EVENTS:
        raise ValueError("Event count must be between1 and100000")
    destination.mkdir()  # New only; no merge/overwrite of prior measurements.
    source = ROOT / "examples/synthetic-case"
    manifest = json.loads((source / "manifest.json").read_text("utf-8"))
    manifest["run_id"] = f"synthetic-benchmark-{count}"
    for entry in manifest["files"]:
        if entry["filename"] != "events.ndjson":
            with (destination / entry["filename"]).open("xb") as stream:
                stream.write((source / entry["filename"]).read_bytes())
    prototype = Event.model_validate_json((source / "events.ndjson").read_bytes())
    base = prototype.model_dump(mode="json")
    moment = datetime(2026, 11, 1, 0, 5, tzinfo=UTC)
    size = 0
    with (destination / "events.ndjson").open("xb") as stream:
        for index in range(1, count + 1):
            # record/time differ, not just provenance (which dedup intentionally excludes).
            raw = {
                **base,
                "record_id": index,
                "source_ref": f"events:{index}",
                "timestamp_utc": (moment + timedelta(microseconds=index)).isoformat(),
            }
            data = (Event.model_validate_json(json.dumps(raw)).model_dump_json() + "\n").encode()
            size += len(data)
            if size > MAX_SOURCE_BYTES:
                raise ValueError("Generated source exceeds the actual engine input cap")
            stream.write(data)
    for entry in manifest["files"]:
        path = destination / entry["filename"]
        entry["byte_length"] = path.stat().st_size
        entry["sha256"] = sha(path)
    for source_status in manifest["sources"]:
        if source_status["source"] == "events":
            source_status["records"] = count
    # Round-trip validates hashes/count metadata; normal reader validates source bytes later.
    content = (
        Manifest.model_validate_json(json.dumps(manifest)).model_dump_json(indent=2) + "\n"
    ).encode()
    if sum(p.stat().st_size for p in destination.iterdir()) + len(content) > MAX_TOTAL_BYTES:
        raise ValueError("Generated case exceeds the actual total input cap")
    with (destination / "manifest.json").open("xb") as stream:
        stream.write(content)


def revision():
    git = ["git", "-c", f"safe.directory={ROOT.as_posix()}"]
    names = (
        subprocess.check_output(
            [*git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    hashes = {n: sha(ROOT / n) for n in sorted(set(names)) if n and (ROOT / n).is_file()}
    return {
        "commit": subprocess.check_output([*git, "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status": subprocess.check_output([*git, "status", "--porcelain"], cwd=ROOT, text=True),
        "source_files": hashes,
        "locks": {
            n: sha(ROOT / n)
            for n in ("requirements.txt", "requirements-desktop-ai.txt", "requirements-dev.txt")
        },
    }


def child(case, directory):
    """No collector, ACL setup, network, AI, or application launch is involved."""
    stop = threading.Event()

    def guard():
        try:
            while not stop.wait(0.1):
                if memory_counters()["working_set_bytes"] > HARNESS_MEMORY:
                    save_new(directory / "memory-safety-stop.json", memory_counters())
                    os._exit(8)
        except (OSError, ValueError, RuntimeError):
            # Missing safety instrumentation cannot become an unbounded/pass run.
            os._exit(9)

    watcher = threading.Thread(target=guard, name="synthetic-benchmark-safety")
    watcher.start()
    report = {
        "schema_version": 1,
        "pid": os.getpid(),
        "started_at_utc": datetime.now(UTC).isoformat(),
        "status": "in_progress",
        "stages": [],
        "memory_method": "K32GetProcessMemoryInfo PROCESS_MEMORY_COUNTERS; absolute lifetime PeakWorkingSetSize",
    }

    def stage(name, started, **values):
        item = {
            "stage": name,
            "seconds": time.perf_counter() - started,
            **memory_counters(),
            **values,
        }
        report["stages"].append(item)
        save_new(directory / f"stage-{len(report['stages'])}.json", item)

    try:
        started = time.perf_counter()
        intent = read_intent(ROOT / "examples/intent-synthetic-confirmed.json")
        with VerifiedBundle(case) as bundle:
            stage("manifest_hash_and_small_source_validation", started)
            count = 0

            def events():
                nonlocal count
                for event in bundle.iter_events():
                    count += 1
                    if event.record_id != count or event.source_ref != f"events:{count}":
                        raise ValueError("Fixture distinct record/provenance sequence mismatch")
                    yield event

            started = time.perf_counter()
            result = analyze_case(
                bundle.manifest,
                bundle.profiles,
                bundle.rules,
                events(),
                intent=intent,
                network=bundle.network,
                analyzed_at_utc=datetime(2026, 11, 1, 0, 10, tzinfo=UTC),
            )
            bundle.check_unchanged()
            if count != next(s.records for s in bundle.manifest.sources if s.source == "events"):
                raise ValueError("Actual event count mismatch")
            if len(result.findings) != count or any(f.event is None for f in result.findings):
                raise ValueError("Distinct fixture observations were lost or unexpectedly grouped")
            stage(
                "analysis_including_streamed_event_validation",
                started,
                actual_events=count,
                findings=len(result.findings),
            )
            started = time.perf_counter()
            # Same serializer/writer as the service. This new ignored output is wholly
            # synthetic: ordinary local output here is not a native privacy test.
            output_bytes = 0
            digest = hashlib.sha256()

            def chunks():
                nonlocal output_bytes
                for chunk in analysis_json_chunks(result):
                    output_bytes += len(chunk)
                    digest.update(chunk)
                    yield chunk

            write_new_chunks(
                directory / "synthetic-analysis.json", chunks(), byte_limit=MAX_ANALYSIS_BYTES
            )
            stage(
                "service_serialization",
                started,
                output_bytes=output_bytes,
                output_budget_met=output_bytes <= MAX_ANALYSIS_BYTES,
            )
            report["output_sha256"] = digest.hexdigest()
            report["completeness"] = result.completeness.value
            report["status"] = (
                "measured" if output_bytes <= MAX_ANALYSIS_BYTES else "output_budget_failed"
            )
            report["output_written"] = True
        report["elapsed_measured_stages_seconds"] = sum(s["seconds"] for s in report["stages"])
        report["peak_working_set_bytes"] = memory_counters()["peak_working_set_bytes"]
        report["time_target_met"] = report["elapsed_measured_stages_seconds"] <= SECONDS_TARGET
        report["memory_target_met"] = report["peak_working_set_bytes"] <= WORKING_SET_TARGET
        save_new(directory / "sample.json", report)
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["exception_type"] = type(exc).__name__
        report.update(memory_counters())
        save_new(directory / "sample.json", report)
        raise
    finally:
        stop.set()
        watcher.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--events", type=int, default=100000, choices=range(1, 100001), metavar="1..100000"
    )
    parser.add_argument("--samples", type=int, default=3, choices=range(1, 11))
    parser.add_argument("--child", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--case", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows OS memory counters are required; no allocation-counter substitute")
    if args.child is not None:
        for path in (args.child, args.case):
            if path is None or not path.resolve().is_relative_to(ROOT / ".build"):
                parser.error("Internal measurements must stay below Product/.build")
        return child(args.case, args.child)
    label = "100k" if args.events == MAX_EVENTS else f"smoke-{args.events}"
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    directory = ROOT / ".build" / f"benchmark-{stamp}-{label}"
    directory.mkdir()
    save_new(
        directory / "environment.json",
        {
            **host_facts(),
            **revision(),
            "requested_events": args.events,
            "requested_samples": args.samples,
            "label": label,
            "target_seconds": SECONDS_TARGET,
            "target_peak_working_set_bytes": WORKING_SET_TARGET,
            "output_limit_bytes": MAX_ANALYSIS_BYTES,
            "harness_seconds": HARNESS_SECONDS,
            "harness_memory_bytes": HARNESS_MEMORY,
            "arguments": sys.argv,
        },
    )
    case = directory / "synthetic-case"
    generate_case(case, args.events)
    save_new(
        directory / "inputs.json",
        {p.name: {"bytes": p.stat().st_size, "sha256": sha(p)} for p in case.iterdir()},
    )
    samples = []
    for index in range(1, args.samples + 1):
        sample_dir = directory / f"sample-{index}"
        sample_dir.mkdir()
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--child",
            str(sample_dir),
            "--case",
            str(case),
        ]
        started = time.monotonic()
        with (
            (sample_dir / "stdout.txt").open("xb") as out,
            (sample_dir / "stderr.txt").open("xb") as err,
        ):
            try:
                outcome = subprocess.run(
                    command,
                    check=False,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    shell=False,
                    timeout=HARNESS_SECONDS,
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                )
                code = outcome.returncode
            except subprocess.TimeoutExpired:
                code = "harness_timeout"
        data = {
            "command_argv": command,
            "exit_code": code,
            "wall_seconds": time.monotonic() - started,
        }
        if (sample_dir / "sample.json").exists():
            data["measurement"] = json.loads((sample_dir / "sample.json").read_text("utf-8"))
        samples.append(data)
        save_new(sample_dir / "execution.json", data)
        print(json.dumps({"sample": index, "directory": str(sample_dir), **data}), flush=True)
    save_new(
        directory / "summary.json",
        {
            "label": label,
            "samples": samples,
            "reference_vm_acceptance": "blocked",
            "source_after": revision(),
        },
    )
    return (
        0
        if all(
            s["exit_code"] == 0
            and s.get("measurement", {}).get("status") == "measured"
            and s["measurement"]["time_target_met"]
            and s["measurement"]["memory_target_met"]
            for s in samples
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
