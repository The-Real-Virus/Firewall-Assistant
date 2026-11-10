import os
import subprocess
import sys
from pathlib import Path

import pytest


def cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, NO_COLOR="1", COLUMNS="80", PYTHON_COLORS="0")
    return subprocess.run(
        [sys.executable, "-m", "wfdiag", *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )


def test_help_matches_reviewed_public_contract() -> None:
    result = cli("--help")
    expected = Path(__file__).parents[1] / "fixtures/cli-help.txt"
    assert result.returncode == 0
    assert result.stdout == expected.read_text(encoding="utf-8")
    assert not result.stderr
    assert "desktop-job" not in result.stdout


def test_installed_module_version() -> None:
    result = cli("--version")
    assert result.returncode == 0
    assert result.stdout == "wfdiag 1.0.0rc1\n"


@pytest.mark.parametrize(
    "args",
    [
        ("collect", "--minutes", "0", "--out", "new"),
        ("collect", "--minutes", "61", "--out", "new"),
        ("report", "--analysis", "old", "--mode", "unknown", "--out", "new"),
        ("propose", "--analysis", "old", "--finding-id", "F001", "--out", "new"),
        ("apply",),
        ("disable",),
        ("upload",),
        (),
    ],
)
def test_invalid_command_is_not_success(args: tuple[str, ...]) -> None:
    result = cli(*args)
    assert result.returncode == 2
    assert not result.stdout


def test_collect_unsupported_host_never_invokes_a_native_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from wfdiag.cli import main
    from wfdiag.collectors import capture
    from wfdiag.contracts.models import Host

    monkeypatch.setattr(
        capture,
        "observed_host",
        lambda: Host(
            os="linux", edition=None, build=None, architecture="x64", supported_build=False
        ),
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Unsupported collect must not access native sources")

    monkeypatch.setattr(capture, "run_resource", forbidden)
    monkeypatch.setattr(capture, "current_device_mappings", forbidden)
    assert main(["collect", "--out", str(tmp_path / "new")]) == 3
    result = capsys.readouterr()
    assert "Windows" in result.err and not result.out
    assert not list(tmp_path.iterdir())


def test_doctor_service_records_unsupported_without_native_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    from wfdiag.cli import main
    from wfdiag.contracts.models import Host
    from wfdiag.services import operations

    monkeypatch.setattr(
        operations,
        "observed_host",
        lambda: Host(
            os="linux", edition=None, build=None, architecture="x64", supported_build=False
        ),
    )

    def forbidden(token: object) -> bytes:
        raise AssertionError("No native probe on unsupported host")

    monkeypatch.setattr(operations, "native_probe", forbidden)
    destination = tmp_path / "doctor.json"
    assert main(["doctor", "--out", str(destination)]) == 3
    report = json.loads(destination.read_text(encoding="utf-8"))
    assert report["eligible_target"] is False
    assert report["security_events_collected"] is False
    assert main(["doctor", "--out", str(destination)]) == 2
