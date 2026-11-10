"""Creation-order regression with native boundaries doubled; no ACL acceptance."""

from pathlib import Path

import pytest

from wfdiag.storage import windows_privacy


def test_nonlocal_or_redirected_parent_is_rejected_before_any_directory_creation(
    monkeypatch,
) -> None:
    privacy = object.__new__(windows_privacy.WindowsPrivacy)
    seen = []

    def reject_parent(path, *, allow_child_writes=False):
        assert allow_child_writes is True
        seen.append(path)
        raise ValueError("synthetic nonlocal parent rejection")

    def forbidden():
        pytest.fail("Creation reached native security/directory APIs before parent locality check")

    monkeypatch.setattr(windows_privacy, "WindowsDirectory", reject_parent)
    monkeypatch.setattr(privacy, "_operator_sid", forbidden)
    destination = Path("C:/Synthetic-Only/NewPrivateOutput")
    with pytest.raises(ValueError, match="nonlocal"):
        privacy.create(destination)
    assert seen == [destination.parent]
