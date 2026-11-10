"""Run real local repository checks; no lab, credentials, signing or remote publication."""

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from defusedxml import ElementTree

ROOT = Path(__file__).resolve().parents[1]
PYTHON = str(Path(sys.executable).resolve())
SUITES = ("quality", "unit-contract", "dependency-audit", "package-smoke")
# Reviewed baseline 727 before P14; lower counts require a reviewed explanation/change.
MINIMUM_TESTS = {"contract": 79, "unit": 322, "gui": 64, "ai": 262}
MINIMUM_TOTAL = 727


def execute(argv: list[str], *, capture: bool = False, timeout: int = 600) -> str:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=timeout,
        env={**os.environ, "PYTHONUTF8": "1", "QT_QPA_PLATFORM": "offscreen"},
    )
    if capture and result.stdout:
        print(result.stdout, end="", flush=True)
    if capture and result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    if result.returncode:
        raise RuntimeError(f"Required check failed: {Path(argv[0]).name}; exit {result.returncode}")
    return result.stdout if capture else ""


def require_collected_suites(output: str) -> dict[str, int]:
    nodes = {line.strip().replace("\\", "/") for line in output.splitlines() if "::" in line}
    counts = {name: sum(n.startswith(f"tests/{name}/") for n in nodes) for name in MINIMUM_TESTS}
    if len(nodes) < MINIMUM_TOTAL or any(counts[n] < m for n, m in MINIMUM_TESTS.items()):
        raise ValueError("Required test suite is absent or below the reviewed collection baseline")
    return counts


def require_passed_junit(path: Path, expected: int) -> None:
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Unexpected oversized local test report")
    root = ElementTree.parse(path).getroot()
    suites = list(root.iter("testsuite"))
    tests = sum(int(s.get("tests", "0")) for s in suites)
    incomplete = sum(
        int(s.get(field, "0")) for s in suites for field in ("skipped", "errors", "failures")
    )
    if tests != expected or incomplete or tests < MINIMUM_TOTAL:
        raise ValueError("Required source test execution is missing, failed or skipped")


def quality() -> None:
    if sys.platform == "win32":
        execute([PYTHON, "scripts/parse_collectors.py"])
    for command in (
        ["-m", "ruff", "check", "."],
        ["-m", "ruff", "format", "--check", "."],
        ["-m", "mypy"],
        ["scripts/export_schemas.py", "--check"],
        ["scripts/check_theme_contrast.py"],
        [
            "scripts/prepare_ai_live_packet.py",
            "--out",
            "docs/ai/live-fixtures/2026-11-05-r2",
            "--check",
        ],
        [
            "scripts/verify_release_evidence.py",
            "gate",
            "--record",
            "docs/evidence/G1-contracts-20261104.json",
        ],
    ):
        execute([PYTHON, *command])


def unit_contract() -> None:
    output = execute(
        [PYTHON, "-m", "pytest", "--collect-only", "-q", "tests", "-m", "not lab and not live_ai"],
        capture=True,
    )
    counts = require_collected_suites(output)
    print(json.dumps({"collected_required_suites": counts}), flush=True)
    execute(
        [
            PYTHON,
            "-m",
            "pytest",
            "tests",
            "-q",
            "-m",
            "not lab and not live_ai",
            "--junitxml=.build/checks/unit-contract.xml",
        ]
    )
    require_passed_junit(ROOT / ".build/checks/unit-contract.xml", sum(counts.values()))


def dependency_audit() -> Path:
    folder = ROOT / ".build/checks"
    folder.mkdir(parents=True, exist_ok=True)
    report = folder / f"audit-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.cdx.json"
    execute(
        [
            PYTHON,
            "-m",
            "pip_audit",
            "--disable-pip",
            "--no-deps",
            "--require-hashes",
            "--strict",
            "-r",
            "requirements-dev.txt",
            "--cache-dir",
            str(folder / "audit-cache"),
            "--format",
            "cyclonedx-json",
            "--output",
            str(report),
        ],
        timeout=300,
    )
    # The build helper independently checks exact nonempty audit inventory and zero findings.
    return report


def package_smoke() -> None:
    audit = dependency_audit()
    output = execute(
        [PYTHON, "scripts/build_windows.py", "--audit-report", str(audit)],
        capture=True,
        timeout=900,
    )
    records = []
    for line in output.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and "candidate" in record:
            records.append(record)
    if len(records) != 1:
        raise ValueError("The actual build did not produce one identifiable candidate")
    execute(
        [PYTHON, "scripts/verify_local_package.py", "--candidate", records[0]["candidate"]],
        timeout=300,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=(*SUITES, "all"), default="quality")
    args = parser.parse_args()
    (ROOT / ".build/checks").mkdir(parents=True, exist_ok=True)
    print(
        "Local source/fixture checks only; hosted Windows is not endpoint/lab certification.",
        flush=True,
    )
    functions = dict(
        zip(SUITES, (quality, unit_contract, dependency_audit, package_smoke), strict=True)
    )
    try:
        for name in SUITES if args.suite == "all" else (args.suite,):
            functions[name]()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Repository check failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
