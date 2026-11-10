"""Pure target eligibility from recorded facts, separate from release certification."""

import re

from wfdiag.contracts.models import Host


def desktop_target_eligible(host: Host | None) -> bool:
    if host is None:
        return False
    match = re.fullmatch(r"([0-9]{5,6})(?:\.[0-9]{1,8})?", host.build or "")
    return (
        host.os == "windows"
        and host.architecture == "x64"
        and host.windows_product_type == 1
        and match is not None
        and int(match.group(1)) >= 17763
    )
