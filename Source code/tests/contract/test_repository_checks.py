"""Required suite guards must fail even when pytest exits successfully with too few tests."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def checks():
    path = Path(__file__).parents[2] / "scripts/check_repository.py"
    spec = importlib.util.spec_from_file_location("wfdiag_repository_checks_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def invented_collection():
    return "\n".join(
        f"tests/{group}/test_invented.py::test_only_fixture[{n}]"
        for group, count in {"contract": 100, "unit": 400, "gui": 150, "ai": 300}.items()
        for n in range(count)
    )


def test_sufficient_collection_passes_guard(checks):
    assert checks.require_collected_suites(invented_collection()) == {
        "contract": 100,
        "unit": 400,
        "gui": 150,
        "ai": 300,
    }


@pytest.mark.parametrize("missing", ["contract", "unit", "gui", "ai"])
def test_missing_suite_fails_even_with_many_other_nodes(checks, missing):
    output = "\n".join(
        n for n in invented_collection().splitlines() if not n.startswith(f"tests/{missing}/")
    )
    with pytest.raises(ValueError, match="absent"):
        checks.require_collected_suites(output)


def test_empty_duplicate_or_small_suite_does_not_pass(checks):
    for output in (
        "no tests collected",
        "tests/unit/test_only.py::test_one\n" * 800,
        "tests/unit/test_only.py::test_one",
    ):
        with pytest.raises(ValueError):
            checks.require_collected_suites(output)


@pytest.mark.parametrize("attribute", ['skipped="800"', 'errors="1"', 'failures="1"', 'tests="0"'])
def test_empty_skipped_or_failed_execution_cannot_pass(checks, tmp_path, attribute):
    report = tmp_path / "invented-junit.xml"
    attrs = f'tests="800" {attribute}' if not attribute.startswith("tests") else attribute
    report.write_text(f"<testsuites><testsuite {attrs}/></testsuites>", encoding="utf-8")
    with pytest.raises(ValueError, match="missing, failed or skipped"):
        checks.require_passed_junit(report, 800)


def test_actual_successful_junit_count_required(checks, tmp_path):
    report = tmp_path / "invented-junit.xml"
    report.write_text(
        '<testsuites><testsuite tests="800" failures="0" skipped="0"/></testsuites>',
        encoding="utf-8",
    )
    checks.require_passed_junit(report, 800)
    with pytest.raises(ValueError):
        checks.require_passed_junit(report, 801)
