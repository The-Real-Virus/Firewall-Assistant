"""Native audit-policy doubles observe flags and never enable a privilege or policy."""

import ctypes
from types import SimpleNamespace
from unittest.mock import Mock

from wfdiag.collectors import audit_policy


def test_audit_observer_distinguishes_failure_flags_and_frees_native_buffer(monkeypatch):
    kept = []

    def query(guids, count, pointer):
        assert count == 2
        values = (audit_policy.AuditInformation * 2)()
        for i in range(2):
            values[i].subcategory = guids[i]
        values[0].options = 3
        values[1].options = 1
        kept.append(values)
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = ctypes.addressof(
            values
        )
        return True

    api = SimpleNamespace(AuditQuerySystemPolicy=Mock(side_effect=query), AuditFree=Mock())
    monkeypatch.setattr(audit_policy.sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: api)
    assert audit_policy.failure_audit_codes() == (
        "AUDIT_5157_FAILURE_ENABLED",
        "AUDIT_5152_FAILURE_DISABLED",
    )
    api.AuditFree.assert_called_once()


def test_unreadable_audit_policy_stays_unknown_not_disabled(monkeypatch):
    api = SimpleNamespace(AuditQuerySystemPolicy=Mock(return_value=False), AuditFree=Mock())
    monkeypatch.setattr(audit_policy.sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: api)
    assert audit_policy.failure_audit_codes() == ("AUDIT_CONFIGURATION_NOT_ESTABLISHED",)
    api.AuditFree.assert_not_called()
