"""Deduplicate identical observations without collapsing distinct attempts or provenance."""

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from wfdiag.contracts.models import Event


@dataclass(frozen=True, slots=True)
class EventGroup:
    event: Event
    source_refs: tuple[str, ...]


def deduplicate_events(events: Iterable[Event]) -> tuple[EventGroup, ...]:
    return tuple(iter_event_groups(events))


def iter_event_groups(events: Iterable[Event]) -> Iterator[EventGroup]:
    """Preserve first-seen order and all provenance, releasing groups as consumed.

    Deduplication must finish reading before yielding: a later duplicate can add
    provenance. Avoid retaining both all group wrappers and all resulting findings.
    """
    groups: dict[str, tuple[Event, list[str], set[str] | None]] = {}
    for event in events:
        payload = event.model_dump(mode="json", exclude={"source_ref"})
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        previous = groups.get(digest)
        if previous is None:
            groups[digest] = (event, [event.source_ref], None)
        else:
            original, refs, seen = previous
            if seen is None:
                if event.source_ref == refs[0]:
                    continue
                seen = set(refs)
                groups[digest] = (original, refs, seen)
            if event.source_ref not in seen:
                refs.append(event.source_ref)
                seen.add(event.source_ref)
    for digest in tuple(groups):
        event, refs, _ = groups.pop(digest)
        yield EventGroup(event, tuple(refs))
