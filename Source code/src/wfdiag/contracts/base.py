"""Shared input bounds and immutable validation policy."""

from datetime import datetime, timedelta
from pathlib import Path, PureWindowsPath
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

ShortText = Annotated[str, Field(max_length=500)]
Identifier = Annotated[str, Field(min_length=1, max_length=128)]
# Windows persistent rule names can exceed the short protocol identifier bound.
# Preserve them exactly, including through findings and comparisons.
RuleIdentifier = Annotated[str, Field(min_length=1, max_length=4096)]
PathText = Annotated[str, Field(min_length=1, max_length=4096)]
Port = Annotated[int, Field(ge=0, le=65535)]
Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


def actual_integer(value: object) -> object:
    if type(value) is not int:
        raise ValueError("An integer is required; booleans and floats are not integers here")
    return value


def actual_boolean(value: object) -> object:
    if type(value) is not bool:
        raise ValueError("An actual JSON boolean is required")
    return value


NonExecutable = Annotated[Literal[False], BeforeValidator(actual_boolean)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)


def utc_only(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("A UTC timestamp with an explicit offset is required")
    return value


def absolute_local_path(value: str) -> str:
    windows = PureWindowsPath(value)
    if value.startswith(("\\\\", "//")) or "\x00" in value:
        raise ValueError("A local absolute path is required")
    if ".." in windows.parts or any(ord(c) < 32 for c in value):
        raise ValueError("Unsafe path component")
    for part in windows.parts[1:]:
        base = part.split(".")[0].upper()
        if part.endswith((" ", ".")) or base in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }:
            raise ValueError("Ambiguous Windows path alias is not accepted")
    if ":" in value[2:] or any(c in value for c in ('"', "<", ">", "|", "?", "*")):
        raise ValueError("Alternate streams and wildcard paths are not accepted")
    if not windows.is_absolute() and not Path(value).is_absolute():
        raise ValueError("An absolute path is required")
    return value


def windows_program(value: str) -> str:
    absolute_local_path(value)
    if not PureWindowsPath(value).is_absolute() or not value.lower().endswith(".exe"):
        raise ValueError("A verified absolute Windows executable identity is required")
    return value
