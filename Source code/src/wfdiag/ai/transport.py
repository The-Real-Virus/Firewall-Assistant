"""Only this optional module imports HTTPX. No client exists until an approved send."""

import asyncio
import logging
import zlib
from urllib.parse import urlsplit

import httpx

from wfdiag.ai.contracts import AiErrorCode, Provider
from wfdiag.ai.credentials import KeyMaterial
from wfdiag.ai.models import Model, selected_model
from wfdiag.ai.policy import MAX_BODY_BYTES, AiFailure
from wfdiag.ai.providers.base import RESPONSE_LIMIT
from wfdiag.storage.json_input import checked_json

TOTAL_DEADLINE = 60.0
WIRE_LIMIT = 512 * 1024


def endpoint(model: Model) -> str:
    # A caller cannot forge an otherwise valid Model with an alternate host or path.
    if selected_model(model.provider, model.model) != model:
        raise AiFailure(AiErrorCode.CONFIGURATION)
    url = f"https://{model.host}{model.route}"
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname != model.host
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise AiFailure(AiErrorCode.CONFIGURATION)
    return url


def headers(model: Model, key: KeyMaterial) -> dict[str, str]:
    result = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    if model.provider == Provider.OPENAI:
        result["Authorization"] = "Bearer " + key.reveal_for_request()
    elif model.provider == Provider.ANTHROPIC:
        result["x-api-key"] = key.reveal_for_request()
        result["anthropic-version"] = model.api_version
    elif model.provider == Provider.GOOGLE:
        result["x-goog-api-key"] = key.reveal_for_request()
    else:
        raise AiFailure(AiErrorCode.CONFIGURATION)
    return result


async def bounded_body(response: httpx.Response, *, limit: int = RESPONSE_LIMIT) -> bytes:
    # Use raw streaming and an explicit decompressor with max_length. aiter_bytes
    # can expand a compression bomb inside its decoder before our length check.
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("identity", "gzip", "deflate"):
        raise AiFailure(AiErrorCode.RESPONSE_INVALID)
    decoder = (
        None if encoding == "identity" else zlib.decompressobj(31 if encoding == "gzip" else 15)
    )
    output = bytearray()
    wire = 0
    try:
        async for chunk in response.aiter_raw(chunk_size=16384):
            wire += len(chunk)
            if wire > WIRE_LIMIT:
                raise AiFailure(AiErrorCode.RESPONSE_INVALID)
            remaining = limit - len(output)
            if decoder is None:
                decoded = chunk
            else:
                decoded = decoder.decompress(chunk, remaining + 1)
                if decoder.unconsumed_tail or decoder.unused_data:
                    raise AiFailure(AiErrorCode.RESPONSE_INVALID)
            if len(decoded) > remaining:
                raise AiFailure(AiErrorCode.RESPONSE_INVALID)
            output.extend(decoded)
        if decoder is not None and not decoder.eof:
            raise AiFailure(AiErrorCode.RESPONSE_INVALID)
    except zlib.error:
        raise AiFailure(AiErrorCode.RESPONSE_INVALID) from None
    return bytes(output)


def status_error(status: int) -> AiErrorCode:
    if status == 401:
        return AiErrorCode.AUTHENTICATION
    if status == 403:
        return AiErrorCode.POLICY
    if status == 429:
        return AiErrorCode.RATE_LIMIT
    if status == 402:
        return AiErrorCode.CREDIT
    if status in (404, 410):
        return AiErrorCode.MODEL_UNAVAILABLE
    if status in (400, 422):
        return AiErrorCode.CONFIGURATION
    if 300 <= status < 400:
        return AiErrorCode.NETWORK
    return AiErrorCode.PROVIDER_FAILURE


async def safe_error(response: httpx.Response) -> AiErrorCode:
    fallback = status_error(response.status_code)
    if response.status_code not in (400, 402, 429) or not response.headers.get(
        "content-type", ""
    ).startswith("application/json"):
        return fallback
    try:
        body = await bounded_body(response, limit=16384)
        tree = checked_json(body, byte_limit=16384, max_depth=8, max_values=128)
        error = tree.get("error") if isinstance(tree, dict) else None
        if isinstance(error, dict):
            details = error.get("details")
            reasons = (
                [item.get("reason") for item in details if isinstance(item, dict)]
                if isinstance(details, list)
                else []
            )
            if any(reason in ("API_KEY_INVALID", "API_KEY_EXPIRED") for reason in reasons):
                return AiErrorCode.AUTHENTICATION
            code = error.get("code") or error.get("type") or error.get("status")
            if code in (
                "insufficient_quota",
                "credit_balance_too_low",
                "billing_hard_limit_reached",
            ):
                return AiErrorCode.CREDIT
    except (AiFailure, ValueError, UnicodeError):
        pass
    return fallback


async def post(
    model: Model,
    payload: bytes,
    key: KeyMaterial,
    *,
    _test_transport: httpx.AsyncBaseTransport | None = None,
) -> bytes:
    destination = endpoint(model)
    if not payload or len(payload) > MAX_BODY_BYTES:
        raise AiFailure(AiErrorCode.DISCLOSURE)
    # No body/header debug traces, including when a host application enables debug.
    for name in (
        "httpx",
        "httpcore",
        "httpcore.connection",
        "httpcore.http11",
        "httpcore.http2",
        "httpcore.proxy",
    ):
        logging.getLogger(name).disabled = True
    try:
        async with asyncio.timeout(TOTAL_DEADLINE):
            async with (
                httpx.AsyncClient(
                    verify=True,
                    trust_env=False,
                    follow_redirects=False,
                    # Initial Gemini structured-output responses can take longer
                    # than30s. Keep the independent60s total bound and cancellation.
                    timeout=httpx.Timeout(
                        connect=10,
                        write=10,
                        read=50 if model.provider == Provider.GOOGLE else 30,
                        pool=5,
                    ),
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                    transport=_test_transport,
                ) as client,
                client.stream(
                    "POST", destination, headers=headers(model, key), content=payload
                ) as response,
            ):
                if response.status_code != 200:
                    raise AiFailure(await safe_error(response))
                if (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "application/json"
                ):
                    raise AiFailure(AiErrorCode.RESPONSE_INVALID)
                return await bounded_body(response)
    except asyncio.CancelledError:
        raise AiFailure(AiErrorCode.CANCELLED) from None
    except (TimeoutError, httpx.TimeoutException):
        raise AiFailure(AiErrorCode.TIMEOUT) from None
    except AiFailure:
        raise
    except (httpx.HTTPError, OSError, ValueError):
        raise AiFailure(AiErrorCode.NETWORK) from None
    except Exception:  # noqa: BLE001 -- sanitize exceptions at the optional transport boundary.
        # Transport implementations may raise non-HTTPX exceptions containing a
        # request. The application boundary never exposes their text or traceback.
        raise AiFailure(AiErrorCode.NETWORK) from None
