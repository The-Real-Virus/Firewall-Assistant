import asyncio
import gzip
import json
from dataclasses import replace

import httpx
import pytest

from wfdiag.ai.contracts import AiErrorCode
from wfdiag.ai.credentials import KeyMaterial
from wfdiag.ai.models import MODELS
from wfdiag.ai.policy import AiFailure
from wfdiag.ai.transport import endpoint, post
from wfdiag.ai.usage import Allowance


@pytest.mark.parametrize("reason", ["API_KEY_INVALID", "API_KEY_EXPIRED"])
def test_google_key_error_is_authentication_without_echoing_provider_details(reason):
    payload = {
        "error": {"code": 400, "message": "PRIVATE_KEY_CANARY", "details": [{"reason": reason}]}
    }
    with pytest.raises(AiFailure) as error:
        asyncio.run(
            post(
                MODELS[2],
                b"{}",
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(
                    lambda _: httpx.Response(
                        400,
                        headers={"content-type": "application/json"},
                        stream=Stream(json.dumps(payload).encode()),
                    )
                ),
            )
        )
    assert error.value.code == AiErrorCode.AUTHENTICATION
    assert "PRIVATE_KEY_CANARY" not in str(error.value)


class Stream(httpx.AsyncByteStream):
    def __init__(self, data: bytes, *, delay: float = 0) -> None:
        self.data, self.delay, self.closed = data, delay, False

    async def __aiter__(self):
        for start in range(0, len(self.data), 4096):
            if self.delay:
                await asyncio.sleep(self.delay)
            yield self.data[start : start + 4096]

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "evil.example"),
        ("host", "api.openai.com:444"),
        ("host", "user@api.openai.com"),
        ("route", "/v1/responses?key=bad"),
        ("route", "//evil.example"),
        ("provider", MODELS[1].provider),
    ],
)
def test_forged_destination_never_receives_credentials(field, value) -> None:
    with pytest.raises(AiFailure):
        endpoint(replace(MODELS[0], **{field: value}))


@pytest.mark.parametrize(
    "status,code",
    [
        (301, AiErrorCode.NETWORK),
        (307, AiErrorCode.NETWORK),
        (400, AiErrorCode.CONFIGURATION),
        (401, AiErrorCode.AUTHENTICATION),
        (403, AiErrorCode.POLICY),
        (404, AiErrorCode.MODEL_UNAVAILABLE),
        (429, AiErrorCode.RATE_LIMIT),
        (500, AiErrorCode.PROVIDER_FAILURE),
    ],
)
def test_status_is_safe_no_redirect_retry_or_error_body_display(status, code) -> None:
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(
            status,
            headers={"location": "https://evil.example"},
            content=b"SECRET_PROVIDER_ERROR_BODY",
        )

    with pytest.raises(AiFailure) as error:
        asyncio.run(
            post(
                MODELS[0],
                b"{}",
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(handle),
            )
        )
    assert error.value.code == code and len(seen) == 1
    assert "SECRET" not in str(error.value)


@pytest.mark.parametrize(
    "compress,declared", [(False, None), (False, "1"), (True, None), (True, "999999999")]
)
def test_actual_decoded_bytes_bounded_without_trusting_content_length(compress, declared) -> None:
    data = b"x" * (256 * 1024 + 1)
    if compress:
        data = gzip.compress(data)
    stream = Stream(data)
    headers = {"content-type": "application/json"}
    if compress:
        headers["content-encoding"] = "gzip"
    if declared:
        headers["content-length"] = declared
    with pytest.raises(AiFailure) as error:
        asyncio.run(
            post(
                MODELS[0],
                b"{}",
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(
                    lambda _: httpx.Response(200, headers=headers, stream=stream)
                ),
            )
        )
    assert error.value.code == AiErrorCode.RESPONSE_INVALID and stream.closed


def test_gzip_success_and_truncated_or_concatenated_gzip_refused() -> None:
    data = b'{"complete":true}'
    compressed = gzip.compress(data)
    for content, succeeds in (
        (compressed, True),
        (compressed[:-3], False),
        (compressed + gzip.compress(b"extra"), False),
    ):
        stream = Stream(content)
        call = post(
            MODELS[0],
            b"{}",
            KeyMaterial("invented-key"),
            _test_transport=httpx.MockTransport(
                lambda _, current=stream: httpx.Response(
                    200,
                    headers={"content-type": "application/json", "content-encoding": "gzip"},
                    stream=current,
                )
            ),
        )
        if succeeds:
            assert asyncio.run(call) == data
        else:
            with pytest.raises(AiFailure):
                asyncio.run(call)
        assert stream.closed


def test_independent_total_deadline_ends_a_trickling_response(monkeypatch) -> None:
    from wfdiag.ai import transport

    monkeypatch.setattr(transport, "TOTAL_DEADLINE", 0.03)
    stream = Stream(b"x" * 20000, delay=0.02)
    with pytest.raises(AiFailure) as error:
        asyncio.run(
            post(
                MODELS[0],
                b"{}",
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(
                    lambda _: httpx.Response(
                        200, headers={"content-type": "application/json"}, stream=stream
                    )
                ),
            )
        )
    assert error.value.code == AiErrorCode.TIMEOUT and stream.closed


def test_cancel_closes_stream_and_does_not_retry() -> None:
    stream = Stream(b"x" * 20000, delay=1)

    async def run():
        task = asyncio.create_task(
            post(
                MODELS[0],
                b"{}",
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(
                    lambda _: httpx.Response(
                        200, headers={"content-type": "application/json"}, stream=stream
                    )
                ),
            )
        )
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(AiFailure) as error:
            await task
        assert error.value.code == AiErrorCode.CANCELLED

    asyncio.run(run())
    assert stream.closed


def test_default_request_counter_has_no_session_ceiling() -> None:
    value = Allowance()
    for _ in range(1001):
        value.begin()
        value.finish()
    assert value.limit is None and value.attempts == 1001


def test_allowance_counts_attempts_not_just_success_and_reset_is_explicit() -> None:
    value = Allowance(limit=20)
    value.begin()
    with pytest.raises(AiFailure):
        value.begin()
    with pytest.raises(AiFailure):
        value.reset()
    value.finish()
    for _ in range(19):
        value.begin()
        value.finish()
    assert value.attempts == 20
    with pytest.raises(AiFailure) as error:
        value.begin()
    assert error.value.code == AiErrorCode.QUOTA
    value.reset()
    value.begin()
    value.finish()
    assert value.attempts == 1


@pytest.mark.parametrize(
    "code,expected",
    [
        ("insufficient_quota", AiErrorCode.CREDIT),
        ("rate_limit_error", AiErrorCode.RATE_LIMIT),
        ("unknown", AiErrorCode.RATE_LIMIT),
    ],
)
def test_credit_and_rate_errors_are_distinct_without_displaying_raw_error(code, expected) -> None:
    import json

    data = json.dumps({"error": {"code": code, "message": "CANARY_RAW_PROVIDER_ERROR"}}).encode()
    with pytest.raises(AiFailure) as error:
        asyncio.run(
            post(
                MODELS[0],
                b"{}",
                KeyMaterial("invented-key"),
                _test_transport=httpx.MockTransport(
                    lambda _: httpx.Response(
                        429, headers={"content-type": "application/json"}, stream=Stream(data)
                    )
                ),
            )
        )
    assert error.value.code == expected and "CANARY" not in str(error.value)


def test_tls_proxy_redirect_and_timeout_configuration_is_fixed(monkeypatch) -> None:
    from wfdiag.ai import transport

    original = httpx.AsyncClient
    settings = []

    def client(**kwargs):
        settings.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(transport.httpx, "AsyncClient", client)
    monkeypatch.setenv("HTTPS_PROXY", "http://invalid.example:8080")
    monkeypatch.setenv("SSL_CERT_FILE", "not-a-real-certificate")
    data = asyncio.run(
        post(
            MODELS[0],
            b"{}",
            KeyMaterial("invented-key"),
            _test_transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200, headers={"content-type": "application/json"}, stream=Stream(b"{}")
                )
            ),
        )
    )
    assert data == b"{}" and len(settings) == 1
    assert settings[0]["verify"] is True
    assert settings[0]["trust_env"] is settings[0]["follow_redirects"] is False
    timeout = settings[0]["timeout"]
    assert (timeout.connect, timeout.write, timeout.read, timeout.pool) == (10, 10, 30, 5)
