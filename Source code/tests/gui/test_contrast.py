"""Numeric source-token budgets. Native focus/Narrator/high-contrast acceptance stays separate."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def checker():
    path = Path(__file__).parents[2] / "scripts/check_theme_contrast.py"
    spec = importlib.util.spec_from_file_location("wfdiag_contrast_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reference_black_white_and_equal_colors(checker):
    assert checker.contrast("#000000", "#FFFFFF") == pytest.approx(21.0)
    assert checker.contrast("#123456", "#123456") == pytest.approx(1.0)
    assert checker.contrast("#FFFFFF", "#000000") == pytest.approx(21.0)


def test_both_theme_text_focus_and_control_budgets(checker):
    rows = checker.observations()
    assert len(rows) == 38
    assert {row["theme"] for row in rows} == {"Light", "Dark"}
    assert all(row["contrast_ratio"] >= row["required"] for row in rows)
    assert all(row["status"] == "pass" for row in rows)
