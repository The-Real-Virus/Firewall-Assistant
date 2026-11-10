import json
from pathlib import Path

import pytest

from wfdiag.collectors.preflight import doctor, target_family_matches
from wfdiag.contracts.models import Host
from wfdiag.errors import ExitCode
from wfdiag.services.cancellation import CancellationToken


def host(*, target: bool = True) -> Host:
    return Host(
        os="windows" if target else "linux",
        edition="Professional" if target else None,
        build="26200.9818" if target else None,
        architecture="x64",
        supported_build=False,
        windows_product_type=1 if target else None,
    )


def payload(**changes: object) -> bytes:
    data = {
        "schema_version": "1.0",
        "administrator_token": False,
        "powershell_version": "5.1.26200.1",
        "netsecurity": "supported",
        "security_events": "supported",
        "audit_visibility": "unknown",
        "audit_raw": None,
    }
    data.update(changes)
    return json.dumps(data).encode()


def test_unsupported_host_never_probes_security_or_policy() -> None:
    def forbidden(token: CancellationToken) -> bytes:
        raise AssertionError("Native probe must not run")

    report, code = doctor(host(target=False), forbidden, CancellationToken())
    assert code == ExitCode.UNSUPPORTED
    assert not report.eligible_target and not report.release_certified
    assert all(cap.state == "unknown" for cap in report.capabilities)


@pytest.mark.parametrize("administrator", [False, True])
def test_synthetic_normal_and_administrator_tokens_stay_distinct(administrator: bool) -> None:
    report, code = doctor(
        host(), lambda token: payload(administrator_token=administrator), CancellationToken()
    )
    assert code == ExitCode.COMPLETED
    assert report.administrator_token is administrator
    assert not report.release_certified
    assert not report.security_events_collected and not report.firewall_policy_collected
    assert (
        next(cap for cap in report.capabilities if cap.name == "private_output").state == "unknown"
    )


def test_denied_source_is_not_empty_success() -> None:
    report, code = doctor(
        host(), lambda token: payload(security_events="denied"), CancellationToken()
    )
    assert code == ExitCode.ACCESS_DENIED
    assert (
        next(cap for cap in report.capabilities if cap.name == "security_events").state == "denied"
    )


def test_missing_netsecurity_is_unsupported_capability() -> None:
    report, code = doctor(
        host(), lambda token: payload(netsecurity="unavailable"), CancellationToken()
    )
    assert code == ExitCode.UNSUPPORTED
    assert (
        next(cap for cap in report.capabilities if cap.name == "netsecurity").state == "unavailable"
    )


@pytest.mark.parametrize("raw", [b"not json", b"{}", b"[]", b"x" * (1024 * 1024 + 1)])
def test_invalid_probe_cannot_invent_readiness(raw: bytes) -> None:
    report, code = doctor(host(), lambda token: raw, CancellationToken())
    assert code == ExitCode.UNSUPPORTED
    assert report.administrator_token is None
    assert all(cap.state == "unknown" for cap in report.capabilities)


def test_fixed_preflight_resource_has_no_policy_write_or_elevation_path() -> None:
    source = (
        Path(__file__).parents[2] / "src/wfdiag/resources/powershell/Preflight.ps1"
    ).read_text(encoding="utf-8")
    for forbidden in [
        "Set-NetFirewall",
        "New-NetFirewall",
        "Remove-NetFirewall",
        "-Verb RunAs",
        "/failure:enable",
        "ExecutionPolicy",
        "ReadEvent(",
    ]:
        assert forbidden not in source


@pytest.mark.parametrize(
    "edition",
    [
        "Core",
        "CoreN",
        "CoreSingleLanguage",
        "Professional",
        "ProfessionalN",
        "ProfessionalEducation",
        "ProfessionalWorkstation",
        "Enterprise",
        "EnterpriseN",
        "EnterpriseS",
        "EnterpriseSN",
        "Education",
        "EducationN",
    ],
)
@pytest.mark.parametrize("build", ["17763.0", "19045.5131", "22000.1", "22621.4317", "26200.9818"])
def test_owner_approved_desktop_editions_and_builds_are_eligible_not_certified(
    edition: str, build: str
) -> None:
    facts = Host(
        os="windows",
        edition=edition,
        build=build,
        architecture="x64",
        supported_build=False,
        windows_product_type=1,
    )
    assert target_family_matches(facts)
    report, code = doctor(facts, lambda token: payload(), CancellationToken())
    assert code == ExitCode.COMPLETED and report.eligible_target
    assert not report.release_certified and not report.host.supported_build


@pytest.mark.parametrize(
    "changes",
    [
        {"build": "17134.1"},
        {"architecture": "x86"},
        {"architecture": "arm64"},
        {"windows_product_type": 2},
        {"windows_product_type": 3},
        {"windows_product_type": None},
        {"build": "not-a-build"},
    ],
)
def test_outside_or_unknown_platform_facts_do_not_trigger_native_probes(
    changes: dict[str, object],
) -> None:
    data = host().model_dump(mode="json")
    data.update(changes)
    facts = Host.model_validate_json(json.dumps(data))

    def forbidden(token: CancellationToken) -> bytes:
        raise AssertionError("No native probe for outside/unknown facts")

    report, code = doctor(facts, forbidden, CancellationToken())
    assert code == ExitCode.UNSUPPORTED and not report.eligible_target
