import pytest

from wfdiag.services.cancellation import CancellationToken, Cancelled


def test_cancellation_stops_next_bounded_service_stage() -> None:
    token = CancellationToken()
    token.check()
    token.request()
    assert token.requested
    with pytest.raises(Cancelled):
        token.check()
