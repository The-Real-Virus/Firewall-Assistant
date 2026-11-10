"""Bounded standalone records opened relative to held directories."""

import os
from collections.abc import Callable
from pathlib import Path

from wfdiag.contracts.base import Contract
from wfdiag.contracts.models import Analysis, Intent
from wfdiag.errors import DiagnosticError, ExitCode
from wfdiag.storage.analysis_json import analysis_data_from_checked_json
from wfdiag.storage.atomic_write import check_plain_path
from wfdiag.storage.json_input import checked_json
from wfdiag.storage.opened_files import OpenedDirectory

MAX_ANALYSIS_BYTES = 128 * 1024 * 1024
MAX_INTENT_BYTES = 64 * 1024


class RecordByteBudgetExceeded(ValueError):
    """A smaller caller budget refused the held size or actual bytes before decoding."""


def read_record[T: Contract](path: Path, model: type[T], *, byte_limit: int) -> T:
    def decode(text: str) -> T:
        if model is Analysis:
            return model.model_validate(
                analysis_data_from_checked_json(text),
                strict=True,
            )
        return model.model_validate_json(text)

    return read_checked_record(path, byte_limit=byte_limit, decode=decode)


def read_checked_record[T](path: Path, *, byte_limit: int, decode: Callable[[str], T]) -> T:
    """Shared held-file syntax/budget/identity guards; only trusted typed decoders call this."""
    check_plain_path(path)
    held = OpenedDirectory(path.parent)
    try:
        with held.open_relative(path.name) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > byte_limit:
                raise RecordByteBudgetExceeded("Record byte budget exceeded")
            data = bytearray()
            while chunk := stream.read(65536):
                data.extend(chunk)
                if len(data) > byte_limit:
                    raise RecordByteBudgetExceeded("Actual record bytes exceed the budget")
            raw = bytes(data)
            del data
            checked_json(
                raw,
                byte_limit=byte_limit,
                max_depth=32,
                max_values=10000000,
                retain_objects=False,
            )
            text = raw.decode("utf-8-sig", errors="strict")
            del raw
            record = decode(text)
            after = os.fstat(stream.fileno())
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("Opened record changed while reading")
            return record
    finally:
        held.close()


def read_intent(path: Path) -> Intent:
    return read_record(path, Intent, byte_limit=MAX_INTENT_BYTES)


def read_analysis(path: Path, *, byte_limit: int = MAX_ANALYSIS_BYTES) -> Analysis:
    if type(byte_limit) is not int or not 0 < byte_limit <= MAX_ANALYSIS_BYTES:
        raise ValueError("Invalid analysis byte budget")
    check_plain_path(path)
    directory = path if path.is_dir() else path.parent

    def reject_incomplete() -> None:
        try:
            (directory / ".incomplete").lstat()
        except FileNotFoundError:
            return
        raise DiagnosticError(
            ExitCode.INVALID_INPUT, "The analysis directory is incomplete; use a completed result."
        )

    reject_incomplete()
    record = read_record(
        directory / "analysis.json" if path.is_dir() else path,
        Analysis,
        byte_limit=byte_limit,
    )
    reject_incomplete()
    return record
