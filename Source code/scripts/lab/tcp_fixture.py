"""Standalone, fixed-content TCP lab fixture. Never imported by the shipped application."""

import argparse
import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from uuid import UUID

PAYLOAD = b"WFDiagLab fixed fixture v1\n"
NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)


def private_literal(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if "%" in value:
        raise ValueError("Use a literal private host-only address without a zone or hostname")
    address = ipaddress.ip_address(value)
    if not any(address.version == network.version and address in network for network in NETWORKS):
        raise ValueError("Only the approved RFC1918/ULA host-only lab addresses are permitted")
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("A concrete private lab interface is required")
    return address


@dataclass(frozen=True)
class Settings:
    lab_only: bool
    bind: str
    peer: str
    port: int
    mode: str
    seconds: int
    run_id: str

    def validate(self) -> int:
        if self.lab_only is not True:
            raise ValueError("Explicit --lab-only and separately approved A01 are required")
        local, peer = private_literal(self.bind), private_literal(self.peer)
        if local == peer or local.version != peer.version:
            raise ValueError("Use distinct local/peer interfaces of the same address family")
        if type(self.port) is not int or not 1024 <= self.port <= 65535:
            raise ValueError("Use one exact approved nonprivileged service port")
        if type(self.seconds) is not int or not 1 <= self.seconds <= 60:
            raise ValueError("The fixture lifetime is bounded to1–60 seconds")
        if self.mode not in ("listen", "connect") or str(UUID(self.run_id)) != self.run_id:
            raise ValueError("Invalid fixed mode or canonical run UUID")
        return socket.AF_INET if local.version == 4 else socket.AF_INET6


def remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("Lab fixture lifetime expired")
    return min(value, 1.0)


def exchange(stream: socket.socket, deadline: float) -> bool:
    # A total deadline applies to every partial read; no unbounded peer-controlled body/echo.
    stream.settimeout(remaining(deadline))
    stream.sendall(PAYLOAD)
    received = bytearray()
    while len(received) < len(PAYLOAD):
        stream.settimeout(remaining(deadline))
        part = stream.recv(len(PAYLOAD) - len(received))
        if not part:
            return False
        received.extend(part)
    return bytes(received) == PAYLOAD


def run(settings: Settings) -> bool:
    family = settings.validate()  # Refuse invalid destinations before creating any socket.
    deadline = time.monotonic() + settings.seconds
    with socket.socket(family, socket.SOCK_STREAM) as endpoint:
        if family == socket.AF_INET6:
            endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        endpoint.settimeout(remaining(deadline))
        if settings.mode == "connect":
            endpoint.bind((settings.bind, 0))
            endpoint.connect((settings.peer, settings.port))
            return exchange(endpoint, deadline)
        endpoint.bind((settings.bind, settings.port))
        endpoint.listen(1)
        for _ in range(16):
            endpoint.settimeout(remaining(deadline))
            try:
                connection, address = endpoint.accept()
            except TimeoutError:
                continue
            with connection:
                if ipaddress.ip_address(address[0]) != private_literal(settings.peer):
                    continue
                return exchange(connection, deadline)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-only", action="store_true")
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--peer-address", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--mode", choices=("listen", "connect"), required=True)
    parser.add_argument("--lifetime", type=int, default=15)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    settings = Settings(
        args.lab_only,
        args.bind_address,
        args.peer_address,
        args.port,
        args.mode,
        args.lifetime,
        args.run_id,
    )
    try:
        success = run(settings)
    except (OSError, ValueError):
        print(json.dumps({"fixture": "failed_or_blocked", "no_policy_changes": True}))
        return 2
    print(
        json.dumps(
            {
                "fixture": "fixed_exchange_completed" if success else "no_exchange",
                "run_id": settings.run_id,
                "no_policy_changes": True,
            }
        )
    )
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
