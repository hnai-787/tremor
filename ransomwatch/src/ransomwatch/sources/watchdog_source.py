"""Live filesystem monitoring via the `watchdog` package (portable: Linux/macOS/Windows).

Important, deliberate limitation: `watchdog`'s portable backends (inotify
on Linux included) report WHAT changed, never WHO changed it. Linux's own
inotify(7) documentation states this explicitly. So every event produced
here has `actor=None` -- correlation degrades gracefully to a single
host-wide pool (see detector.py), rather than fabricating a fake process
identity. A more advanced Linux-only source using fanotify with
FAN_REPORT_PIDFD could add real process attribution; that's deliberately
out of scope for v1 (see README "Future enhancements").

This module imports `watchdog` lazily so the rest of the package -- and
the entire offline pytest suite -- never needs it installed.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..baseline import Baseline
from ..entropy import sample_file_entropy
from ..models import FileEvent


def run_live(
    root: str | Path,
    on_event: Callable[[FileEvent], None],
    *,
    sample_bytes: int,
    excluded_dir_names: frozenset[str] = frozenset(
        {".git", ".venv", "node_modules", "__pycache__", "cache", "build"}
    ),
) -> None:
    """Watch `root` recursively, calling on_event for every create/write/rename/delete.

    Blocks until interrupted (Ctrl+C). Requires the `watchdog` package
    (install the `live` extra: `pip install -e ".[live]"`).
    """
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
        raise RuntimeError(
            "Live monitoring requires the 'watchdog' package: pip install -e \".[live]\""
        ) from exc

    import time

    baseline = Baseline()

    def _excluded(path: str) -> bool:
        parts = Path(path).parts
        return any(part in excluded_dir_names for part in parts)

    class Handler(FileSystemEventHandler):
        def on_created(self, event) -> None:
            if event.is_directory or _excluded(event.src_path):
                return
            entropy_after = sample_file_entropy(event.src_path, sample_bytes)
            size_after = _safe_size(event.src_path)
            on_event(
                FileEvent(
                    timestamp=time.time(),
                    operation="create",
                    path=event.src_path,
                    previous_path=None,
                    size_before=None,
                    size_after=size_after,
                    entropy_before=None,
                    entropy_after=entropy_after,
                    actor=None,
                )
            )
            if size_after is not None:
                baseline.update(event.src_path, size_after, entropy_after)

        def on_modified(self, event) -> None:
            if event.is_directory or _excluded(event.src_path):
                return
            previous = baseline.get(event.src_path)
            entropy_after = sample_file_entropy(event.src_path, sample_bytes)
            size_after = _safe_size(event.src_path)
            on_event(
                FileEvent(
                    timestamp=time.time(),
                    operation="write",
                    path=event.src_path,
                    previous_path=None,
                    size_before=previous.size if previous else None,
                    size_after=size_after,
                    entropy_before=previous.entropy if previous else None,
                    entropy_after=entropy_after,
                    actor=None,
                )
            )
            if size_after is not None:
                baseline.update(event.src_path, size_after, entropy_after)

        def on_moved(self, event) -> None:
            if event.is_directory or _excluded(event.dest_path):
                return
            previous = baseline.get(event.src_path)
            on_event(
                FileEvent(
                    timestamp=time.time(),
                    operation="rename",
                    path=event.dest_path,
                    previous_path=event.src_path,
                    size_before=previous.size if previous else None,
                    size_after=previous.size if previous else None,
                    entropy_before=previous.entropy if previous else None,
                    entropy_after=previous.entropy if previous else None,
                    actor=None,
                )
            )
            baseline.rename(event.src_path, event.dest_path)

        def on_deleted(self, event) -> None:
            if event.is_directory or _excluded(event.src_path):
                return
            previous = baseline.get(event.src_path)
            on_event(
                FileEvent(
                    timestamp=time.time(),
                    operation="delete",
                    path=event.src_path,
                    previous_path=None,
                    size_before=previous.size if previous else None,
                    size_after=None,
                    entropy_before=previous.entropy if previous else None,
                    entropy_after=None,
                    actor=None,
                )
            )
            baseline.forget(event.src_path)

    observer = Observer()
    observer.schedule(Handler(), str(root), recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


def _safe_size(path: str) -> int | None:
    try:
        return Path(path).stat().st_size
    except OSError:
        return None
