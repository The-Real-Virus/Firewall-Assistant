"""Source guards supplement (and do not replace) required native read-only evidence."""

import re
from importlib.resources import files


def test_shipped_collection_scripts_have_no_policy_mutation_or_dynamic_execution() -> None:
    resources = files("wfdiag").joinpath("resources/powershell")
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in resources.iterdir()
        if path.name.endswith(".ps1")
    )
    forbidden = re.compile(
        r"\b(?:New|Set|Remove|Enable|Disable)-NetFirewall\w*|\bInvoke-Expression\b|\bStart-Process\b|\b(?:netsh|cmd|curl|wget)(?:\.exe)?\b|/failure:enable|ExecutionPolicy\s+(?:Bypass|Unrestricted)",
        re.IGNORECASE,
    )
    assert forbidden.search(text) is None
    policy = resources.joinpath("Collect-Policy.ps1").read_text(encoding="utf-8")
    assert "-PolicyStore ActiveStore -TracePolicyStore" in policy
    assert "Show-NetFirewallRule -PolicyStore ActiveStore" in policy
    assert "'MSFT_NetFirewallRuleFilters'" in policy
    assert "Get-PolicyIdentity $link.GroupComponent" in policy
    assert "Get-PolicyIdentity $link.PartComponent" in policy
    assert "Microsoft.Management.Infrastructure.CimFlags]::Key" in policy
    assert "GroupComponent.InstanceID" not in policy
    assert "SetCustomOption('PolicyStore', 'ActiveStore', $false)" in policy
    assert (
        "Create('localhost', [Microsoft.Management.Infrastructure.Options.DComSessionOptions]::new())"
        in policy
    )
    for kind in (
        "Application",
        "Address",
        "ProtocolPort",
        "Service",
        "Interface",
        "InterfaceType",
        "NetworkLayerSecurity",
    ):
        assert f"MSFT_Net{kind}Filter" in policy
    event = resources.joinpath("Collect-Events.ps1").read_text(encoding="utf-8")
    assert "$event.ToXml()" in event and "5157,5152" in event
    assert ".Message" not in event and ".Properties[" not in event
    assert "-MaxEvents 100001" in event and "$count -ge 100000" in event
