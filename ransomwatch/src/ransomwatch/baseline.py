"""Lightweight per-path state used by live sources to compute before/after deltas.

Replay fixtures already carry both `entropy_before` and `entropy_after`
directly (computed once by the fixture generator) and don't use this.
This exists only for a live source: it needs to remember what a file
looked like the last time it was observed, so that a later write can be
compared against something real rather than an assumption.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import EntropySample


@dataclass
class FileState:
    size: int
    entropy: EntropySample | None


class Baseline:
    def __init__(self) -> None:
        self._state: dict[str, FileState] = {}

    def get(self, path: str) -> FileState | None:
        return self._state.get(path)

    def update(self, path: str, size: int, entropy: EntropySample | None) -> None:
        self._state[path] = FileState(size=size, entropy=entropy)

    def forget(self, path: str) -> None:
        self._state.pop(path, None)

    def rename(self, old_path: str, new_path: str) -> None:
        state = self._state.pop(old_path, None)
        if state is not None:
            self._state[new_path] = state
