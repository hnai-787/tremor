"""Offline replay of a JSONL event log -- the primary source for tests and CI.

Each line is one FileEvent, already fully formed (entropy pre-computed by
the fixture generator). Detection uses each event's own `timestamp`, never
wall-clock processing time: a log spanning an hour of real activity must
still represent an hour to the detector, even if replayed in milliseconds
-- otherwise a spread-out, low-and-slow event stream would collapse into
one artificial burst (or the reverse). See PROJECT_NOTES.md.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ..models import EntropySample, FileEvent, ProcessIdentity


def _parse_entropy(data: dict | None) -> EntropySample | None:
    if data is None:
        return None
    return EntropySample(head=data.get("head"), middle=data.get("middle"), tail=data.get("tail"))


def _parse_actor(data: dict | None) -> ProcessIdentity | None:
    if data is None:
        return None
    return ProcessIdentity(
        id=data["id"], pid=data.get("pid"), executable=data.get("executable")
    )


def parse_event(record: dict) -> FileEvent:
    return FileEvent(
        timestamp=float(record["timestamp"]),
        operation=record["operation"],
        path=record["path"],
        previous_path=record.get("previous_path"),
        size_before=record.get("size_before"),
        size_after=record.get("size_after"),
        entropy_before=_parse_entropy(record.get("entropy_before")),
        entropy_after=_parse_entropy(record.get("entropy_after")),
        actor=_parse_actor(record.get("actor")),
    )


def iter_replay_events(jsonl_path: str | Path) -> Iterator[FileEvent]:
    """Yield FileEvents from a JSONL log, in file order (expected to be time-ordered)."""
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield parse_event(json.loads(line))
