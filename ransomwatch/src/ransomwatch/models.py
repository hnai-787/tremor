"""Normalized filesystem-telemetry event model.

RansomWatch never assumes it can attribute every event to a process:
inotify-backed watchers (the portable default) provide no caller identity
at all (see README "Telemetry boundaries"), so `actor` is optional
everywhere in this model, and correlation degrades gracefully to a
host-wide pool when it's absent -- it is never fabricated.

Likewise `entropy_before` is `None`, not `0.0`, for a newly created file:
there is no "before" to sample, and a fabricated zero would manufacture a
spurious entropy jump that was never actually observed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Operation = Literal["create", "write", "rename", "delete"]


@dataclass(frozen=True)
class EntropySample:
    """Shannon entropy (bits/byte, 0-8) for up to three sampled regions of a file.

    Any region may be None -- a small file may only have `head`, and a
    live sampler may not have read every region. Never fabricate a value
    for a region that wasn't actually sampled.
    """

    head: float | None = None
    middle: float | None = None
    tail: float | None = None

    def segments(self) -> dict[str, float]:
        return {
            name: value
            for name, value in (("head", self.head), ("middle", self.middle), ("tail", self.tail))
            if value is not None
        }

    def max_value(self) -> float | None:
        values = list(self.segments().values())
        return max(values) if values else None


@dataclass(frozen=True)
class ProcessIdentity:
    """The actor a telemetry source attributes an event to, if any.

    `id` is a source-stable identity (e.g. a pidfd-backed generation id, or
    a synthetic fixture id) -- deliberately not just a bare PID, since PIDs
    are recycled and a bare-PID identity can silently conflate two
    different processes. See PROJECT_NOTES.md for why this matters.
    """

    id: str
    pid: int | None = None
    executable: str | None = None


@dataclass(frozen=True)
class FileEvent:
    timestamp: float
    operation: Operation

    path: str
    previous_path: str | None  # set for "rename"

    size_before: int | None
    size_after: int | None

    entropy_before: EntropySample | None
    entropy_after: EntropySample | None

    actor: ProcessIdentity | None

    @property
    def actor_key(self) -> str:
        return self.actor.id if self.actor else "unknown"
