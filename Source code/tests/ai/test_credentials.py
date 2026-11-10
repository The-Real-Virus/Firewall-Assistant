import ctypes
import json

import pytest

from wfdiag.ai.contracts import AiErrorCode, Provider
from wfdiag.ai.credentials import (
    TARGETS,
    CredentialW,
    KeyMaterial,
    SessionKeys,
    WindowsCredentialStore,
)
from wfdiag.ai.policy import AiFailure

SENTINEL = "LocalOnlySyntheticKeySentinel_12345"


class FakeStore:
    def __init__(self) -> None:
        self.values = {}
        self.calls = []

    def write(self, provider, key):
        self.calls.append(("write", provider))
        self.values[provider] = key

    def read(self, provider):
        self.calls.append(("read", provider))
        return self.values.get(provider)

    def delete(self, provider):
        self.calls.append(("delete", provider))
        self.values.pop(provider, None)


def test_default_session_storage_never_creates_a_native_store() -> None:
    keys = SessionKeys(lambda: pytest.fail("No native credential access for session-only"))
    keys.set(Provider.OPENAI, SENTINEL)
    assert keys.get(Provider.OPENAI).reveal_for_request() == SENTINEL
    assert keys.get(Provider.GOOGLE) is None
    assert SENTINEL not in repr(keys) and SENTINEL not in repr(keys.get(Provider.OPENAI))
    with pytest.raises(TypeError):
        json.dumps(keys)
    keys.clear_session()
    assert keys.get(Provider.OPENAI) is None


def test_provider_scoped_remember_load_forget_and_disable_semantics() -> None:
    store = FakeStore()
    keys = SessionKeys(lambda: store)
    keys.set(Provider.OPENAI, SENTINEL, remember=True)
    keys.set(Provider.GOOGLE, SENTINEL + "Google", remember=True)
    keys.clear_session()
    assert Provider.OPENAI in store.values
    assert keys.load_remembered(Provider.OPENAI)
    assert keys.get(Provider.GOOGLE) is None
    keys.forget(Provider.OPENAI)
    assert Provider.OPENAI not in store.values and Provider.GOOGLE in store.values
    assert len(set(TARGETS.values())) == 3
    assert all(target.startswith("WFDiag/OptionalAI/") for target in TARGETS.values())


@pytest.mark.parametrize("value", ["", "x" * 2561, "x" * 5121, "a\nb", " a", "nonasciiΩ"])
def test_invalid_key_is_not_reflected_in_errors(value: str) -> None:
    with pytest.raises(AiFailure) as error:
        KeyMaterial(value)
    assert error.value.code == AiErrorCode.CONFIGURATION
    if value:
        assert value not in str(error.value)


def test_store_failure_does_not_silently_persist_or_fall_back() -> None:
    class Denied(FakeStore):
        def write(self, provider, key):
            raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)

    keys = SessionKeys(Denied)
    with pytest.raises(AiFailure):
        keys.set(Provider.OPENAI, SENTINEL, remember=True)
    assert keys.get(Provider.OPENAI) is None
    keys.set(Provider.OPENAI, SENTINEL)  # Deliberate session-only choice remains possible.
    assert keys.get(Provider.OPENAI) is not None


def test_native_layout_and_read_buffer_release_with_explicit_api_double() -> None:
    assert ctypes.sizeof(CredentialW) == (80 if ctypes.sizeof(ctypes.c_void_p) == 8 else 52)
    blob = ctypes.create_string_buffer(SENTINEL.encode())
    native = CredentialW(
        Type=1,
        TargetName=TARGETS[Provider.ANTHROPIC],
        CredentialBlobSize=len(SENTINEL),
        CredentialBlob=ctypes.cast(blob, ctypes.c_void_p),
        Persist=2,
    )
    released = []

    class FakeApi:
        def CredReadW(self, target, kind, flags, output):
            assert target == TARGETS[Provider.ANTHROPIC] and kind == 1 and flags == 0
            ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(CredentialW)))[0] = ctypes.pointer(
                native
            )
            return True

        def CredFree(self, pointer):
            released.append(True)

    store = WindowsCredentialStore.__new__(WindowsCredentialStore)
    store.api = FakeApi()
    assert store.read(Provider.ANTHROPIC).reveal_for_request() == SENTINEL
    assert released == [True]
    native.CredentialBlobSize = 2561
    with pytest.raises(AiFailure):
        store.read(Provider.ANTHROPIC)
    assert released == [True, True]
    native.CredentialBlobSize = len(SENTINEL)
    native.TargetName = TARGETS[Provider.OPENAI]
    with pytest.raises(AiFailure):
        store.read(Provider.ANTHROPIC)
    assert released == [True, True, True]


def test_documented_blob_limit_and_provider_write_replace_delete_with_api_double() -> None:
    assert len(KeyMaterial("x" * 2560).reveal_for_request()) == 2560
    calls = []

    class FakeApi:
        def CredWriteW(self, pointer, flags):
            credential = ctypes.cast(pointer, ctypes.POINTER(CredentialW)).contents
            calls.append(
                (
                    "write",
                    credential.TargetName,
                    ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize),
                )
            )
            assert credential.Type == 1 and credential.Persist == 2
            assert credential.Flags == credential.AttributeCount == flags == 0
            return True

        def CredDeleteW(self, target, kind, flags):
            calls.append(("delete", target, kind))
            assert kind == 1 and flags == 0
            return True

    store = WindowsCredentialStore.__new__(WindowsCredentialStore)
    store.api = FakeApi()
    store.write(Provider.GOOGLE, KeyMaterial(SENTINEL))
    store.write(Provider.GOOGLE, KeyMaterial(SENTINEL + "Replacement"))
    store.delete(Provider.GOOGLE)
    assert calls[0][1] == calls[1][1] == calls[2][1] == TARGETS[Provider.GOOGLE]
    assert calls[0][2] != calls[1][2]


@pytest.mark.parametrize("error_code,missing", [(1168, True), (5, False)])
def test_missing_and_denied_native_reads_have_distinct_results(
    error_code: int, missing: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeApi:
        def CredReadW(self, target, kind, flags, pointer):
            return False

        def CredDeleteW(self, target, kind, flags):
            return False

    monkeypatch.setattr(ctypes, "get_last_error", lambda: error_code, raising=False)
    store = WindowsCredentialStore.__new__(WindowsCredentialStore)
    store.api = FakeApi()
    if missing:
        assert store.read(Provider.OPENAI) is None
        store.delete(Provider.OPENAI)
    else:
        with pytest.raises(AiFailure):
            store.read(Provider.OPENAI)
        with pytest.raises(AiFailure):
            store.delete(Provider.OPENAI)
