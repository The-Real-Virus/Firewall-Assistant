"""Read-only capability preflight; unsupported hosts never query evidence channels."""

import json
import platform
import sys
from collections.abc import Callable
from datetime import UTC, datetime

from wfdiag.collectors.failures import CollectorProbeFailure
from wfdiag.contracts.doctor import Capability, DoctorReport, ProbePayload
from wfdiag.contracts.models import Host
from wfdiag.contracts.platform import desktop_target_eligible
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.services.cancellation import CancellationToken
from wfdiag.version import __version__


def observed_host() -> Host:
    if sys.platform == "win32":
        from wfdiag.collectors.architecture import native_architecture

        architecture = native_architecture()
    else:
        architecture = {
            "AMD64": "x64",
            "x86_64": "x64",
            "ARM64": "arm64",
            "aarch64": "arm64",
            "x86": "x86",
            "i386": "x86",
        }.get(platform.machine(), "unknown")
    os_name = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(
        sys.platform, "unknown"
    )
    edition = None
    build = None
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            ) as key:
                edition_value = winreg.QueryValueEx(key, "EditionID")[0]
                ubr = winreg.QueryValueEx(key, "UBR")[0]
            edition = str(edition_value)[:100]
            build = f"{sys.getwindowsversion().build}.{int(ubr)}"
        except (OSError, ValueError, TypeError):
            build = str(sys.getwindowsversion().build)
    return Host.model_validate_json(
        json.dumps(
            {
                "os": os_name,
                "edition": edition,
                "build": build,
                "architecture": architecture,
                "supported_build": False,
                "hostname": None,
                "windows_product_type": sys.getwindowsversion().product_type
                if sys.platform == "win32"
                else None,
            }
        )
    )


def target_family_matches(host: Host) -> bool:
    # Explicit owner amendment: standard x64 desktop editions, Windows10 1809+/Windows11.
    # Product type1 distinguishes workstation OS from Server/domain controller. Edition
    # names are descriptive and never a reason to reject Home/N/Education/LTSC variants.
    return desktop_target_eligible(host)


def doctor(
    host: Host,
    probe: Callable[[CancellationToken], bytes],
    cancellation: CancellationToken,
) -> tuple[DoctorReport, ExitCode]:
    cancellation.check()
    eligible = target_family_matches(host)
    note = (
        "Compatible Windows target. Review the capability results before collection."
        if eligible
        else "This host is outside the Windows10 1809+/Windows11 x64 desktop target or its platform facts are unknown. Offline analysis remains independent."
    )
    values = {
        name: "unknown"
        for name in [
            "powershell_51",
            "netsecurity",
            "security_events",
            "audit_visibility",
            "private_output",
        ]
    }
    administrator = None
    audit_raw = None
    exit_code = ExitCode.UNSUPPORTED
    if eligible:
        try:
            raw = probe(cancellation)
            if len(raw) > 1024 * 1024:
                raise ValueError("Capability output exceeded its byte budget")
            payload = ProbePayload.model_validate_json(raw)
            administrator = payload.administrator_token
            audit_raw = payload.audit_raw
            values.update(
                powershell_51="supported"
                if payload.powershell_version.startswith("5.1.")
                else "unavailable",
                netsecurity=payload.netsecurity,
                security_events=payload.security_events,
                audit_visibility=payload.audit_visibility,
            )
            if "denied" in (values["netsecurity"], values["security_events"]):
                exit_code = ExitCode.ACCESS_DENIED
            elif all(
                values[key] == "supported"
                for key in ("powershell_51", "netsecurity", "security_events")
            ):
                exit_code = ExitCode.COMPLETED
        except CollectorProbeFailure as error:
            cancellation.check()
            note = error.public_message
            exit_code = error.code
            if error.reason == "COLLECTOR_SCRIPT_POLICY_BLOCKED":
                values["powershell_51"] = "denied"
        except (OSError, ValueError, DiagnosticError):
            cancellation.check()
            note = "A required capability probe could not be validated; collection readiness is unknown."
    explanations = {
        "powershell_51": "Windows PowerShell 5.1 is the fixed collector baseline.",
        "netsecurity": "Command availability does not prove a complete effective-policy capture.",
        "security_events": "A readable event query does not prove that auditing or relevant events are available.",
        "audit_visibility": "Localized audit status is retained locally when available; enabled state is not guessed.",
        "private_output": "Raw case collection requires Windows ACL validation before output; preflight does not claim it here.",
    }
    capabilities = [
        Capability.model_validate_json(
            json.dumps({"name": name, "state": state, "explanation": explanations[name]})
        )
        for name, state in values.items()
    ]
    report = DoctorReport(
        engine_version=__version__,
        checked_at_utc=datetime.now(UTC),
        host=host,
        eligible_target=eligible,
        release_certified=False,
        support_note=note,
        administrator_token=administrator,
        capabilities=tuple(capabilities),
        audit_raw=audit_raw,
    )
    return report, exit_code


def native_probe(cancellation: CancellationToken) -> bytes:
    if sys.platform != "win32":
        raise OSError("Windows capability probe unavailable")
    from wfdiag.collectors.failures import CollectorProbeFailure, exception_failure
    from wfdiag.collectors.windows import run_resource

    try:
        result = run_resource("preflight", cancellation)
    except (OSError, ValueError) as error:
        reason, _ = exception_failure(error)
        raise CollectorProbeFailure(reason) from None
    cancellation.check()
    if result.timed_out or result.output_truncated or result.read_failed or result.return_code != 0:
        from wfdiag.collectors.failures import classify_failure

        reason, _ = classify_failure(result)
        raise CollectorProbeFailure(reason, process_exit=result.return_code)
    return result.stdout.decode("utf-8-sig", errors="strict").encode("utf-8")
