"""Session keys and explicitly requested provider-scoped Windows generic credentials."""

import ctypes
import sys
from collections.abc import Callable
from typing import Protocol

from wfdiag.ai.contracts import AiErrorCode, Provider
from wfdiag.ai.policy import AiFailure

MAX_KEY_BYTES = 5 * 512  # Documented CREDENTIALW blob ceiling; ASCII keys use one byte/character.
TARGETS = {provider: f"WFDiag/OptionalAI/{provider.value}/v1" for provider in Provider}


class KeyMaterial:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if (
            not value
            or len(value) > MAX_KEY_BYTES
            or not value.isascii()
            or any(not 33 <= ord(c) <= 126 for c in value)
        ):
            raise AiFailure(AiErrorCode.CONFIGURATION)
        self._value = value

    def reveal_for_request(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "KeyMaterial(<hidden>)"


class CredentialStore(Protocol):
    def read(self, provider: Provider) -> KeyMaterial | None: ...
    def write(self, provider: Provider, key: KeyMaterial) -> None: ...
    def delete(self, provider: Provider) -> None: ...


class FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class CredentialW(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", FileTime),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.c_void_p),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


class WindowsCredentialStore:
    """No enumeration or plaintext fallback. Instantiated only on an explicit store action."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)
        self.api = ctypes.WinDLL("Advapi32", use_last_error=True)
        self.api.CredWriteW.argtypes = [ctypes.POINTER(CredentialW), ctypes.c_uint32]
        self.api.CredWriteW.restype = ctypes.c_int32
        self.api.CredReadW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.POINTER(CredentialW)),
        ]
        self.api.CredReadW.restype = ctypes.c_int32
        self.api.CredDeleteW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        self.api.CredDeleteW.restype = ctypes.c_int32
        self.api.CredFree.argtypes = [ctypes.c_void_p]
        self.api.CredFree.restype = None

    def write(self, provider: Provider, key: KeyMaterial) -> None:
        raw = key.reveal_for_request().encode("ascii")
        # Keep the blob buffer alive across the synchronous native call.
        blob = ctypes.create_string_buffer(raw, len(raw))
        credential = CredentialW(
            Flags=0,
            Type=1,
            TargetName=TARGETS[provider],
            Comment="Firewall Assistant optional AI credential",
            CredentialBlobSize=len(raw),
            CredentialBlob=ctypes.cast(blob, ctypes.c_void_p),
            Persist=2,
            AttributeCount=0,
            Attributes=None,
            TargetAlias=None,
            UserName="WFDiag",
        )
        if not self.api.CredWriteW(ctypes.byref(credential), 0):
            raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)

    def read(self, provider: Provider) -> KeyMaterial | None:
        pointer = ctypes.POINTER(CredentialW)()
        if not self.api.CredReadW(TARGETS[provider], 1, 0, ctypes.byref(pointer)):
            if ctypes.get_last_error() == 1168:
                return None
            raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)
        try:
            if not pointer:
                raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)
            credential = pointer.contents
            if (
                credential.Type != 1
                or credential.TargetName != TARGETS[provider]
                or not 1 <= credential.CredentialBlobSize <= MAX_KEY_BYTES
                or not credential.CredentialBlob
            ):
                raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)
            try:
                return KeyMaterial(
                    ctypes.string_at(
                        credential.CredentialBlob, credential.CredentialBlobSize
                    ).decode("ascii")
                )
            except (ValueError, UnicodeError, AiFailure):
                raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE) from None
        finally:
            if pointer:
                self.api.CredFree(pointer)

    def delete(self, provider: Provider) -> None:
        if not self.api.CredDeleteW(TARGETS[provider], 1, 0) and ctypes.get_last_error() != 1168:
            raise AiFailure(AiErrorCode.CREDENTIAL_STORAGE)

    def __repr__(self) -> str:
        return "WindowsCredentialStore(<provider-scoped>)"


class SessionKeys:
    def __init__(
        self, store_factory: Callable[[], CredentialStore] = WindowsCredentialStore
    ) -> None:
        self._keys: dict[Provider, KeyMaterial] = {}
        self._store_factory = store_factory

    def set(self, provider: Provider, value: str, *, remember: bool = False) -> None:
        key = KeyMaterial(value)
        if remember:
            # A failed save is explicit; it is never silently persisted elsewhere.
            self._store_factory().write(provider, key)
        self._keys[provider] = key

    def get(self, provider: Provider) -> KeyMaterial | None:
        return self._keys.get(provider)

    def load_remembered(self, provider: Provider) -> bool:
        key = self._store_factory().read(provider)
        if key is None:
            return False
        self._keys[provider] = key
        return True

    def forget(self, provider: Provider) -> None:
        self._keys.pop(provider, None)
        self._store_factory().delete(provider)

    def clear_session(self) -> None:
        self._keys.clear()

    def __repr__(self) -> str:
        return "SessionKeys(<hidden>)"
