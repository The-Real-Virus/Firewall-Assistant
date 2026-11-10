import pytest

from wfdiag.storage.windows_privacy import directory_sddl


def test_sddl_is_protected_with_only_operator_administrators_and_system() -> None:
    value = directory_sddl("S-1-5-21-100-200-300-400")
    assert value == (
        "O:S-1-5-21-100-200-300-400D:P"
        "(A;OICI;FA;;;S-1-5-21-100-200-300-400)"
        "(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)"
    )


@pytest.mark.parametrize("sid", ["Everyone", "S-1-5-21)(A;;FA;;;WD)", "", "S-1-5-x"])
def test_only_a_bounded_sid_can_enter_security_descriptor(sid: str) -> None:
    with pytest.raises(ValueError):
        directory_sddl(sid)


def test_system_token_does_not_create_duplicate_aces() -> None:
    assert directory_sddl("S-1-5-18").count("(A;") == 2
