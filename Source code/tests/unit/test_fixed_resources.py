import shutil
from contextlib import nullcontext
from importlib.resources import files
from pathlib import Path

import pytest

from wfdiag.collectors import windows
from wfdiag.collectors.failures import ResourceIntegrityError
from wfdiag.collectors.process_runner import ProcessResult
from wfdiag.services.cancellation import CancellationToken


@pytest.mark.parametrize(
    "policy,override", [("AllSigned", False), ("Restricted", False), ("RemoteSigned", True)]
)
def test_explicit_stricter_user_policy_is_preserved(monkeypatch, policy, override):
    import winreg

    monkeypatch.setattr(winreg, "OpenKey", lambda *args: nullcontext(object()))
    monkeypatch.setattr(winreg, "QueryValueEx", lambda *args: (policy, winreg.REG_SZ))
    assert bool(windows.collector_policy_arguments()) is override


def test_fixed_resource_has_typed_arguments_and_clean_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = tmp_path / "System32 Ω"
    executable = system / "WindowsPowerShell/v1.0/powershell.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"Synthetic path fixture; never executed")
    monkeypatch.setattr(windows, "system_directory", lambda: system)
    seen = []

    def observe(argv, **kwargs):
        seen.append((argv, kwargs))
        return ProcessResult(b"", b"", 0, False, False, False, False)

    monkeypatch.setattr(windows, "_bounded_process", observe)
    windows.run_resource("events", CancellationToken(), minutes=17)
    argv, config = seen[0]
    assert argv[0] == str(executable)
    assert argv[1:6] == [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "RemoteSigned",
        "-File",
    ]
    assert Path(argv[6]).name == "Collect-Events.ps1"
    assert argv[-2:] == ["-Minutes", "17"]
    assert "-Command" not in argv and "Bypass" not in argv and "Unrestricted" not in argv
    assert config["timeout"] == 120
    assert set(config["environment"]) == {"SystemRoot", "WINDIR", "PATH", "PSModulePath"}


@pytest.mark.parametrize("minutes", [0, 61, True, "10; Write-Host injected"])
def test_invalid_resource_parameters_are_rejected_before_discovery(
    minutes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(windows, "system_directory", lambda: pytest.fail("No native discovery"))
    with pytest.raises(ValueError):
        windows.run_resource("events", CancellationToken(), minutes=minutes)


@pytest.mark.parametrize("modified", ["Collect-Events.ps1", "Collection.Common.ps1"])
def test_modified_collector_or_helper_is_refused_before_process_start(
    tmp_path, monkeypatch, modified
):
    system = tmp_path / "System32"
    exe = system / "WindowsPowerShell/v1.0/powershell.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"not executed")
    destination = tmp_path / "resources/powershell"
    shutil.copytree(files("wfdiag").joinpath("resources/powershell"), destination)
    path = destination / modified
    path.write_bytes(path.read_bytes() + b"\nWrite-Output 'unapproved'\n")
    monkeypatch.setattr(windows, "system_directory", lambda: system)
    monkeypatch.setattr(windows, "files", lambda _: tmp_path)
    monkeypatch.setattr(
        windows,
        "_bounded_process",
        lambda *args, **kwargs: pytest.fail("Modified script must not start"),
    )
    with pytest.raises(ResourceIntegrityError):
        windows.run_resource("events", CancellationToken())


def test_collector_and_helper_stay_write_locked_until_process_completion(tmp_path, monkeypatch):
    system = tmp_path / "System32"
    exe = system / "WindowsPowerShell/v1.0/powershell.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"not executed")
    destination = tmp_path / "resources/powershell"
    shutil.copytree(files("wfdiag").joinpath("resources/powershell"), destination)
    monkeypatch.setattr(windows, "system_directory", lambda: system)
    monkeypatch.setattr(windows, "files", lambda _: tmp_path)

    def observed(*args, **kwargs):
        for name in ("Collect-Events.ps1", "Collection.Common.ps1"):
            with pytest.raises(PermissionError):
                (destination / name).write_bytes(b"changed")
        return ProcessResult(b"", b"", 0, False, False, False, False)

    monkeypatch.setattr(windows, "_bounded_process", observed)
    windows.run_resource("events", CancellationToken())
