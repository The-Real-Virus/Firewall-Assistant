"""Record a local engineering command and its actual outcome, without interpreting a pass."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.label.replace("-", "").replace("_", "").isalnum() or not args.command:
        parser.error("Use a short alphanumeric label and a command")
    root = Path(__file__).resolve().parents[1]
    logs = root / ".build/logs"
    logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC)
    log_path = logs / f"{stamp.strftime('%Y%m%dT%H%M%S%fZ')}-{args.label}.txt"
    git = ["git", "-c", f"safe.directory={root.as_posix()}"]
    revision_result = subprocess.run(
        [*git, "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    revision = revision_result.stdout.strip() if revision_result.returncode == 0 else None
    status_result = subprocess.run(
        [*git, "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    changed = status_result.stdout if status_result.returncode == 0 else None
    names = subprocess.run(
        [*git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    fingerprints = {}
    if names.returncode == 0:
        for name in sorted(set(names.stdout.decode("utf-8").split("\0")) - {""}):
            path = root / name
            if path.is_file():
                path.resolve().relative_to(root)
                fingerprints[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    working_hash = hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest()
    start = time.monotonic()
    startup_error = None
    with log_path.open("wb") as output:
        try:
            result = subprocess.run(
                args.command,
                cwd=root,
                stdout=output,
                stderr=subprocess.STDOUT,
                check=False,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
        except OSError as exc:
            startup_error = f"{type(exc).__name__}: {exc}"
            output.write(("Command did not start: " + startup_error + "\n").encode("utf-8"))
            result = subprocess.CompletedProcess(args.command, 127)
    record = {
        "command_argv": args.command,
        "cwd": str(root),
        "platform": platform.platform(),
        "python": sys.version,
        "timestamp_utc": stamp.isoformat(),
        "exit_code": result.returncode,
        "startup_error": startup_error,
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "log": str(log_path.relative_to(root)),
        "source_revision": revision,
        "working_changes": changed,
        "working_files_sha256": working_hash,
        "source_files": fingerprints,
        "revision_probe_error": revision_result.stderr if revision_result.returncode else None,
        "log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
        "actor": "codex",
        "output_encoding": "utf-8",
        "artifact_sha256": None,
    }
    log_path.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: record[key]
                for key in (
                    "command_argv",
                    "exit_code",
                    "elapsed_seconds",
                    "log",
                    "source_revision",
                    "working_files_sha256",
                )
            }
        )
    )
    print(log_path.read_text(encoding="utf-8", errors="replace")[-5000:])
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
