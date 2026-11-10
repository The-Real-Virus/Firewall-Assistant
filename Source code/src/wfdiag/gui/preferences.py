"""Bounded private UI preferences, separate from diagnostic evidence and AI keys."""

import os
import tempfile
import unicodedata
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, Field, model_validator

from wfdiag.contracts.base import Contract, Identifier, PathText, absolute_local_path
from wfdiag.storage.atomic_write import check_plain_path
from wfdiag.storage.json_input import checked_json
from wfdiag.storage.opened_files import OpenedDirectory
from wfdiag.storage.private_output import create_private_directory, verify_private_directory

PREFERENCE_LIMIT = 128 * 1024
LocalPath = Annotated[PathText, AfterValidator(absolute_local_path)]


class RecentCase(Contract):
    name: Annotated[str, Field(min_length=1, max_length=80)]
    path: LocalPath
    case_id: Identifier
    kind: Literal["analysis", "case"]

    @model_validator(mode="after")
    def plain_name(self) -> Self:
        if self.name != self.name.strip() or any(
            unicodedata.category(c)[0] == "C" for c in self.name
        ):
            raise ValueError("Use a short plain case name")
        return self


class Preferences(Contract):
    schema_version: Literal["1.0"] = "1.0"
    theme: Literal["System", "Light", "Dark", "High contrast"] = "System"
    reduced_motion: bool = False
    history_enabled: bool = False
    recent: Annotated[tuple[RecentCase, ...], Field(max_length=20)] = ()
    work_root: LocalPath | None = None

    @model_validator(mode="after")
    def private_history(self) -> Self:
        if not self.history_enabled and self.recent:
            raise ValueError("History off cannot retain case paths")
        if len({item.path for item in self.recent}) != len(self.recent):
            raise ValueError("Recent case paths must be distinct")
        return self

    def changed(self, **values: object) -> "Preferences":
        import json

        return Preferences.model_validate_json(
            json.dumps({**self.model_dump(mode="json"), **values})
        )

    def remembering(self, item: RecentCase) -> "Preferences":
        if not self.history_enabled:
            raise ValueError("Enable history before remembering a case")
        recent = (item, *(row for row in self.recent if row.path != item.path))[:20]
        return self.changed(recent=[row.model_dump(mode="json") for row in recent])


class PreferenceStore:
    """Only the app-owned fixed preferences file can be replaced. No evidence cleanup."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def load(self) -> Preferences:
        if not self.root.exists():
            return Preferences()
        held = verify_private_directory(self.root)
        try:
            directory = OpenedDirectory(self.root)
            try:
                try:
                    with directory.open_relative("preferences-v1.json") as source:
                        data = source.read(PREFERENCE_LIMIT + 1)
                except FileNotFoundError:
                    return Preferences()
            finally:
                directory.close()
            checked_json(data, byte_limit=PREFERENCE_LIMIT, max_depth=8, max_values=1024)
            return Preferences.model_validate_json(data)
        finally:
            if held is not None:
                held.close()

    def save(self, preferences: Preferences) -> None:
        data = preferences.model_dump_json().encode("utf-8")
        if len(data) > PREFERENCE_LIMIT:
            raise ValueError("Preferences exceed their private byte budget")
        held = (
            verify_private_directory(self.root)
            if self.root.exists()
            else create_private_directory(self.root)
        )
        temporary: Path | None = None
        try:
            destination = self.root / "preferences-v1.json"
            check_plain_path(destination, allow_missing_leaf=True)
            if destination.exists():
                directory = OpenedDirectory(self.root)
                try:
                    with directory.open_relative(destination.name):
                        pass
                finally:
                    directory.close()
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.root, prefix=".preferences-", delete=False
            ) as output:
                temporary = Path(output.name)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            # The held private root prevents Windows directory redirection. Replacement
            # applies only to this fixed app-owned entry, never a user-selected output.
            os.replace(temporary, destination)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            if held is not None:
                held.close()
