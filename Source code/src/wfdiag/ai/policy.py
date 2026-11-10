"""AI-only disclosure and consent checks; no transport, file access or engine mutation."""

import base64
import binascii
import hashlib
import html
import json
import re
import unicodedata
from collections.abc import Iterable
from urllib.parse import unquote

from wfdiag.ai.contracts import (
    AiConfiguration,
    AiErrorCode,
    AiRequest,
    Consent,
    Explanation,
    Provider,
)
from wfdiag.storage.json_input import checked_json

MAX_BODY_BYTES = 64 * 1024
MAX_POLICY_VALUES = 16384
MAX_POLICY_CHARACTERS = 2 * 1024 * 1024
SENSITIVE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\|/+(?:home|users|mnt|private|etc)/|"
    r"https?\s*[:：]|[A-Za-z][A-Za-z0-9+.-]{1,20}\s*://|www\.|\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|"
    r"(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:%._/-]*|"
    r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{8,}|\bAIza[A-Za-z0-9_-]{16,}|"
    r"-----BEGIN[^\n]*PRIVATE KEY|\b(?:api[_-]?key|authorization)\s*[:=]|"
    r"\bCANARY[A-Za-z0-9_-]*|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})",
    re.IGNORECASE,
)
EXECUTABLE_OR_DIRECTIVE = re.compile(
    r"(?:\b(?:New|Set|Remove|Enable|Disable|Get)-NetFirewall\w*\b|"
    r"\b(?:netsh|powershell|pwsh|cmd)(?:\.exe)?\s+(?:-|/|advfirewall)|"
    r"```|<\s*/?\s*[A-Za-z][^>]*>|\[[^\]]+\]\s*\([^)]*\)|"
    r"\b(?:javascript|file|data)\s*:|"
    r"(?:^|[.!?]\s+)(?:please\s+)?(?:run|execute|disable|turn\s+off|create|add)\b|"
    r"\byou\s+(?:should|must|can|need\s+to)\s+(?:run|execute|disable|create|add)\b)",
    re.IGNORECASE | re.MULTILINE,
)


class AiFailure(Exception):
    def __init__(self, code: AiErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


def normalized(text: str) -> str:
    value = text
    for _ in range(2):
        value = unicodedata.normalize("NFKC", html.unescape(unquote(value)))
        value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m[1], 16)), value)
        value = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), value)
    return value


class DisclosurePolicy:
    """Bounded private identity index. It is never serialized or represented in logs."""

    def __init__(self, forbidden_values: Iterable[str] = ()) -> None:
        self._values: set[str] = set()
        characters = 0
        for value in forbidden_values:
            if not value:
                continue
            folded = normalized(value).casefold()
            if folded in self._values:
                continue
            characters += len(folded)
            if len(self._values) >= MAX_POLICY_VALUES or characters > MAX_POLICY_CHARACTERS:
                raise AiFailure(AiErrorCode.DISCLOSURE)
            self._values.add(folded)

    def __repr__(self) -> str:
        return "DisclosurePolicy(<private identity index>)"

    def check_text(self, text: str, *, character_limit: int = 65536) -> None:
        if len(text) > character_limit or len(normalized(text)) > character_limit:
            raise AiFailure(AiErrorCode.DISCLOSURE)
        self._check(text, 0)

    def _check(self, text: str, depth: int) -> None:
        value = normalized(text)
        if any(
            unicodedata.category(c) in ("Cf", "Cs") or (ord(c) < 32 and c not in "\n\t\r")
            for c in value
        ) or SENSITIVE.search(value):
            raise AiFailure(AiErrorCode.DISCLOSURE)
        folded = value.casefold()
        for private in self._values:
            if (
                private in folded
                if len(private) >= 6
                else re.search(r"(?<!\w)" + re.escape(private) + r"(?!\w)", folded)
            ):
                raise AiFailure(AiErrorCode.DISCLOSURE)
        if depth >= 2:
            return
        # Encoded case data is still data. Decode only bounded printable candidates;
        # never execute or deserialize arbitrary objects to inspect them.
        for token in re.findall(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}", value):
            if len(token) > 4096 or len(token) % 4 == 1:
                continue
            try:
                decoded = base64.b64decode(
                    token + "=" * (-len(token) % 4), altchars=b"-_", validate=True
                ).decode("utf-8")
            except (ValueError, binascii.Error, UnicodeError):
                continue
            self._check(decoded, depth + 1)
        for token in re.findall(r"\b0x([0-9a-fA-F]{16,2048})\b", value):
            try:
                decoded = bytes.fromhex(token).decode("utf-8")
            except (ValueError, UnicodeError):
                continue
            self._check(decoded, depth + 1)

    def check_json(self, data: bytes, *, byte_limit: int = MAX_BODY_BYTES) -> None:
        try:
            tree = checked_json(data, byte_limit=byte_limit, max_depth=20, max_values=20000)
        except (ValueError, UnicodeError):
            raise AiFailure(AiErrorCode.DISCLOSURE) from None
        pending = [tree]
        while pending:
            item = pending.pop()
            if isinstance(item, str):
                self.check_text(item)
            elif isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)


def context_revision(material: object) -> str:
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def consent_for(
    *, provider: Provider, model: str, payload: bytes, revision: str, prompt_version: str
) -> Consent:
    """Called by the explicit review-approval action, never by navigation/configuration."""
    return Consent(
        provider=provider,
        model=model,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        context_revision=revision,
        prompt_version=prompt_version,
    )


def verify_consent(
    consent: Consent,
    *,
    provider: Provider,
    model: str,
    payload: bytes,
    revision: str,
    prompt_version: str,
) -> None:
    try:
        current = consent_for(
            provider=provider,
            model=model,
            payload=payload,
            revision=revision,
            prompt_version=prompt_version,
        )
    except ValueError:
        raise AiFailure(AiErrorCode.STALE_CONSENT) from None
    if current != consent:
        raise AiFailure(AiErrorCode.STALE_CONSENT)


def validate_content(explanation: Explanation, policy: DisclosurePolicy) -> Explanation:
    """No model prose is authoritative; these checks supplement the human evaluation gate."""
    for text in (explanation.explanation, *explanation.limitations):
        try:
            policy.check_text(text, character_limit=4000)
        except AiFailure:
            raise AiFailure(AiErrorCode.RESPONSE_UNSAFE) from None
        if EXECUTABLE_OR_DIRECTIVE.search(normalized(text)):
            raise AiFailure(AiErrorCode.RESPONSE_UNSAFE)
        pending = [(text, 0)]
        while pending:
            current, depth = pending.pop()
            if depth >= 2:
                continue
            decoded_values = []
            for token in re.findall(r"[A-Za-z0-9+/_-]{16,}={0,2}", current):
                if len(token) > 4096 or len(token) % 4 == 1:
                    continue
                try:
                    decoded_values.append(
                        base64.b64decode(
                            token + "=" * (-len(token) % 4), altchars=b"-_", validate=True
                        ).decode("utf-8")
                    )
                except (ValueError, binascii.Error, UnicodeError):
                    continue
            for token in re.findall(r"\b0x([0-9a-fA-F]{16,2048})\b", current):
                try:
                    decoded_values.append(bytes.fromhex(token).decode("utf-8"))
                except (ValueError, UnicodeError):
                    continue
            for decoded in decoded_values:
                if EXECUTABLE_OR_DIRECTIVE.search(normalized(decoded)):
                    raise AiFailure(AiErrorCode.RESPONSE_UNSAFE)
                pending.append((decoded, depth + 1))
    return explanation


def require_provider_policy(
    configuration: AiConfiguration, request: AiRequest, *, trusted_synthetic: bool = False
) -> None:
    if not configuration.enabled:
        raise AiFailure(AiErrorCode.DISABLED)
    if configuration.provider is None or configuration.model is None:
        raise AiFailure(AiErrorCode.CONFIGURATION)
    if request.task_mode == "selected_finding" and not trusted_synthetic:
        if (
            not configuration.organization_permission_confirmed
            or not configuration.provider_policy_confirmed
        ):
            raise AiFailure(AiErrorCode.POLICY)
        if (
            configuration.provider == Provider.GOOGLE
            and configuration.policy_mode != "permitted_case"
        ):
            raise AiFailure(AiErrorCode.POLICY)
    if (
        configuration.provider == Provider.GOOGLE
        and configuration.policy_mode == "free_or_unknown"
        and request.task_mode == "general_help"
    ):
        from wfdiag.ai.context import GENERAL_QUESTIONS

        if request.question not in {question for question, _ in GENERAL_QUESTIONS.values()}:
            raise AiFailure(AiErrorCode.POLICY)
