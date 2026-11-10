"""Three-valued candidate matching. Unknown constraints can never become a full match."""

import ntpath
import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address, ip_network

from wfdiag.contracts.enums import Direction, Profile, Relevance
from wfdiag.contracts.models import Event, Intent, Rule


class Match(StrEnum):
    YES = "match"
    NO = "different"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RuleMatch:
    rule: Rule
    result: Match
    reasons: tuple[str, ...]
    profile_only_mismatch: bool = False


def program_equal(left: str, right: str) -> bool:
    return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(ntpath.normpath(right))


def _combine(values: tuple[Match, ...]) -> Match:
    if Match.NO in values:
        return Match.NO
    if Match.UNKNOWN in values:
        return Match.UNKNOWN
    return Match.YES


def flow_endpoints(event: Event) -> tuple[str | None, int | None, str | None, int | None]:
    if event.direction == Direction.INBOUND:
        return (
            event.destination_address,
            event.destination_port,
            event.source_address,
            event.source_port,
        )
    if event.direction == Direction.OUTBOUND:
        return (
            event.source_address,
            event.source_port,
            event.destination_address,
            event.destination_port,
        )
    return None, None, None, None


def relevance(event: Event, intent: Intent | None) -> Relevance:
    if intent is None:
        return Relevance.UNKNOWN
    comparisons: list[Match] = []
    comparisons.append(
        Match.UNKNOWN
        if event.application_canonical is None
        else Match.YES
        if program_equal(event.application_canonical, intent.application_path)
        else Match.NO
    )
    comparisons.append(
        Match.UNKNOWN
        if event.direction == Direction.UNKNOWN
        else Match.YES
        if event.direction.value == intent.direction
        else Match.NO
    )
    comparisons.append(
        Match.UNKNOWN if event.protocol is None else Match.YES if event.protocol == 6 else Match.NO
    )
    _, local_port, peer, remote_port = flow_endpoints(event)
    comparisons.append(_addresses(tuple(intent.remote_addresses), peer, allow_any=False))
    port = local_port if intent.direction == "inbound" else remote_port
    expected = intent.local_port if intent.direction == "inbound" else intent.remote_port
    comparisons.append(
        Match.UNKNOWN if port is None else Match.YES if port == expected else Match.NO
    )
    result = _combine(tuple(comparisons))
    return {
        Match.YES: Relevance.RELEVANT,
        Match.NO: Relevance.UNRELATED,
        Match.UNKNOWN: Relevance.UNKNOWN,
    }[result]


def _alternatives(values: tuple[Match, ...]) -> Match:
    if Match.YES in values:
        return Match.YES
    if Match.UNKNOWN in values or not values:
        return Match.UNKNOWN
    return Match.NO


def _programs(values: tuple[str, ...] | None, program: str | None) -> Match:
    if not values:
        return Match.UNKNOWN
    matches = []
    for value in values:
        if value.casefold() == "any":
            matches.append(Match.YES)
        elif program is None or any(c in value for c in ("*", "?", "%")) or not ntpath.isabs(value):
            matches.append(Match.UNKNOWN)
        else:
            matches.append(Match.YES if program_equal(value, program) else Match.NO)
    return _alternatives(tuple(matches))


def _protocols(values: tuple[str, ...] | None, protocol: int | None) -> Match:
    if not values:
        return Match.UNKNOWN
    matches = []
    known = {"tcp": 6, "udp": 17, "icmpv4": 1, "icmpv6": 58}
    for value in values:
        text = value.casefold()
        if text == "any" or text == "256":
            matches.append(Match.YES)
            continue
        number = known.get(text)
        if number is None and re.fullmatch(r"[0-9]{1,3}", text) and int(text) <= 255:
            number = int(text)
        matches.append(
            Match.UNKNOWN
            if number is None or protocol is None
            else Match.YES
            if number == protocol
            else Match.NO
        )
    return _alternatives(tuple(matches))


def _ports(values: tuple[str, ...] | None, port: int | None) -> Match:
    if not values:
        return Match.UNKNOWN
    matches = []
    for value in values:
        if value.casefold() == "any":
            matches.append(Match.YES)
            continue
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", value):
            matches.append(Match.UNKNOWN)
            continue
        numbers = tuple(int(n) for n in value.split("-"))
        low, high = numbers[0], numbers[-1]
        if not 0 <= low <= high <= 65535 or port is None:
            matches.append(Match.UNKNOWN)
        else:
            matches.append(Match.YES if low <= port <= high else Match.NO)
    return _alternatives(tuple(matches))


def _addresses(
    values: tuple[str, ...] | None, address: str | None, *, allow_any: bool = True
) -> Match:
    if not values:
        return Match.UNKNOWN
    matches = []
    for value in values:
        if allow_any and value.casefold() == "any":
            matches.append(Match.YES)
            continue
        if address is None:
            matches.append(Match.UNKNOWN)
            continue
        try:
            if "%" in value or "%" in address:
                raise ValueError("unverified interface")
            observed = ip_address(address)
            if "-" in value:
                low_text, high_text = value.split("-", 1)
                low, high = ip_address(low_text), ip_address(high_text)
                if low.version != high.version or int(low) > int(high):
                    raise ValueError("invalid address range")
                matches.append(
                    Match.YES
                    if observed.version == low.version and int(low) <= int(observed) <= int(high)
                    else Match.NO
                )
            else:
                network = ip_network(value, strict=False)
                matches.append(
                    Match.YES
                    if observed.version == network.version and observed in network
                    else Match.NO
                )
        except ValueError:
            # LocalSubnet, Internet, dynamic keywords and unresolved names need native context.
            matches.append(Match.UNKNOWN)
    return _alternatives(tuple(matches))


def _unrestricted(values: tuple[str, ...] | None) -> Match:
    # Empty is a captured absence. Null is a failed/missing filter read.
    if values is None:
        return Match.UNKNOWN
    return Match.YES if not values or all(v.casefold() == "any" for v in values) else Match.UNKNOWN


def match_rule(event: Event, rule: Rule, active_profile: Profile | None) -> RuleMatch:
    local, local_port, remote, remote_port = flow_endpoints(event)
    conditions = rule.conditions
    tests = {
        "ENABLED": Match.UNKNOWN
        if rule.enabled is None
        else Match.YES
        if rule.enabled
        else Match.NO,
        "DIRECTION": Match.UNKNOWN
        if Direction.UNKNOWN in (event.direction, rule.direction)
        else Match.YES
        if event.direction == rule.direction
        else Match.NO,
        "PROGRAM": _programs(conditions.programs, event.application_canonical),
        "PROTOCOL": _protocols(conditions.protocols, event.protocol),
        "LOCAL_PORT": _ports(conditions.local_ports, local_port),
        "REMOTE_PORT": _ports(conditions.remote_ports, remote_port),
        "LOCAL_ADDRESS": _addresses(conditions.local_addresses, local),
        "REMOTE_ADDRESS": _addresses(conditions.remote_addresses, remote),
        "SERVICE": _unrestricted(conditions.services),
        "INTERFACE": _unrestricted(conditions.interfaces),
        "INTERFACE_TYPE": _unrestricted(conditions.interface_types),
        "SECURITY": _unrestricted(conditions.security),
        "FILTER_READ": Match.UNKNOWN if rule.filter_errors else Match.YES,
    }
    base = _combine(tuple(tests.values()))
    profile = (
        Match.UNKNOWN
        if active_profile is None or not rule.profiles
        else Match.YES
        if active_profile in rule.profiles
        else Match.NO
    )
    tests["PROFILE"] = profile
    result = _combine(tuple(tests.values()))
    return RuleMatch(
        rule,
        result,
        tuple(f"{name}_{value.name}" for name, value in tests.items() if value != Match.YES),
        base == Match.YES and profile == Match.NO,
    )


def scope_overlap(intent: Intent, rule: Rule) -> Match:
    """Check every potential peer in the proposed scope, not only one observed address.

    Intent does not constrain local addresses, client ports, services or interfaces. A
    rule constrained there may still intersect it; unsupported constraints stay unknown.
    """
    c = rule.conditions
    peer_checks: list[Match] = []
    for token in c.remote_addresses or ():
        if token.casefold() == "any":
            peer_checks.append(Match.YES)
            continue
        try:
            if "-" in token:
                start, end = (ip_address(v) for v in token.split("-", 1))
                if start.version != end.version or int(start) > int(end):
                    raise ValueError("invalid range")
            else:
                net = ip_network(token, strict=False)
                start, end = net.network_address, net.broadcast_address
            peer_checks.append(
                Match.YES
                if any(
                    (peer := ip_network(p)).version == start.version
                    and int(peer.network_address) <= int(end)
                    and int(start) <= int(peer.broadcast_address)
                    for p in intent.remote_addresses
                )
                else Match.NO
            )
        except ValueError:
            peer_checks.append(Match.UNKNOWN)
    checks = (
        Match.UNKNOWN if rule.enabled is None else Match.YES if rule.enabled else Match.NO,
        Match.UNKNOWN
        if rule.direction == Direction.UNKNOWN
        else Match.YES
        if rule.direction.value == intent.direction
        else Match.NO,
        _programs(c.programs, intent.application_path),
        _protocols(c.protocols, 6),
        Match.UNKNOWN
        if not rule.profiles
        else Match.YES
        if intent.profile in rule.profiles
        else Match.NO,
        _ports(
            c.local_ports if intent.direction == "inbound" else c.remote_ports,
            intent.local_port if intent.direction == "inbound" else intent.remote_port,
        ),
        _alternatives(tuple(peer_checks)),
        *(_unrestricted(v) for v in (c.services, c.interfaces, c.interface_types, c.security)),
        Match.UNKNOWN if rule.filter_errors else Match.YES,
    )
    return _combine(checks)
