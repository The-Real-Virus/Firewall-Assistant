"""Only synthetic socket doubles. No lab sockets, policy or native script execution."""

import importlib.util
import socket
import sys
from dataclasses import replace
from pathlib import Path

import pytest


@pytest.fixture
def fixture_module():
    path = Path(__file__).parents[2] / "scripts/lab/tcp_fixture.py"
    spec = importlib.util.spec_from_file_location("wfdiag_test_standalone_fixture", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def settings(module):
    return module.Settings(
        True,
        "192.168.56.10",
        "192.168.56.20",
        54321,
        "listen",
        5,
        "12345678-1234-1234-1234-123456789abc",
    )


@pytest.mark.parametrize(
    "change",
    [
        {"lab_only": False},
        {"bind": "0.0.0.0"},
        {"bind": "::"},
        {"peer": "8.8.8.8"},
        {"peer": "example.com"},
        {"peer": "127.0.0.1"},
        {"peer": "ff02::1"},
        {"peer": "fd00::2"},
        {"peer": "192.168.56.10"},
        {"peer": "fe80::2%4"},
        {"seconds": 0},
        {"seconds": 61},
        {"seconds": True},
        {"port": 0},
        {"port": 65536},
        {"mode": "run"},
        {"run_id": "not-a-uuid"},
    ],
)
def test_invalid_scope_refused_before_socket(fixture_module, monkeypatch, change):
    def forbidden(*args, **kwargs):
        raise AssertionError("A socket was created before validation")

    monkeypatch.setattr(fixture_module.socket, "socket", forbidden)
    with pytest.raises(ValueError):
        fixture_module.run(replace(settings(fixture_module), **change))


def test_ula_and_ipv4_select_exact_family(fixture_module):
    assert settings(fixture_module).validate() == socket.AF_INET
    assert (
        replace(settings(fixture_module), bind="fd00::1", peer="fd00::2").validate()
        == socket.AF_INET6
    )


class FakeStream:
    def __init__(self, parts):
        self.parts, self.sent, self.timeouts = list(parts), [], []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, value):
        self.sent.append(value)

    def recv(self, count):
        value = self.parts.pop(0)
        assert len(value) <= count
        return value


def test_fixed_partial_exchange_no_echo_or_unbounded_read(fixture_module):
    payload = fixture_module.PAYLOAD
    stream = FakeStream([payload[:4], payload[4:]])
    assert fixture_module.exchange(stream, fixture_module.time.monotonic() + 5)
    assert stream.sent == [payload]
    assert all(0 < value <= 1 for value in stream.timeouts)
    assert not fixture_module.exchange(FakeStream([b""]), fixture_module.time.monotonic() + 5)
    assert not fixture_module.exchange(
        FakeStream([b"x" * len(payload)]), fixture_module.time.monotonic() + 5
    )


def test_slow_peer_cannot_extend_total_deadline(fixture_module, monkeypatch):
    values = iter((0.0, 0.5, 2.0))
    monkeypatch.setattr(fixture_module.time, "monotonic", lambda: next(values))
    with pytest.raises(TimeoutError):
        fixture_module.exchange(FakeStream([b"W"]), 1.0)


def test_listener_binds_only_configured_interface_and_ignores_wrong_peer(
    fixture_module, monkeypatch
):
    wrong = FakeStream([])
    right = FakeStream([fixture_module.PAYLOAD])

    class Listener(FakeStream):
        def __init__(self):
            super().__init__([])
            self.bound, self.backlog = None, None
            self.connections = iter(
                ((wrong, ("192.168.56.99", 1234)), (right, ("192.168.56.20", 1234)))
            )

        def bind(self, address):
            self.bound = address

        def listen(self, backlog):
            self.backlog = backlog

        def accept(self):
            return next(self.connections)

    listener = Listener()
    monkeypatch.setattr(fixture_module.socket, "socket", lambda *args: listener)
    assert fixture_module.run(settings(fixture_module))
    assert listener.bound == ("192.168.56.10", 54321) and listener.backlog == 1
    assert wrong.sent == [] and right.sent == [fixture_module.PAYLOAD]
    assert wrong.closed and right.closed and listener.closed
