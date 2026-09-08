"""Exact sliding-window boundary tests, mirroring DeauthGuard's test_windows.py.

Pin down the RansomWhere?-inspired default precisely: 5 qualifying files
within a 30-second window is a burst; 4 within the window, or the same 5
spread across a much longer span, is not.
"""

from ransomwatch.config import DetectionConfig
from ransomwatch.detector import DetectionEngine
from ransomwatch.models import EntropySample, FileEvent, ProcessIdentity

ACTOR = ProcessIdentity(id="proc-1", pid=1, executable="test.exe")
BEFORE = EntropySample(head=4.2, middle=4.1, tail=4.3)
AFTER = EntropySample(head=7.85, middle=7.83, tail=7.86)  # high delta, below abs threshold


def _event(ts: float, path: str) -> FileEvent:
    return FileEvent(
        timestamp=ts,
        operation="write",
        path=path,
        previous_path=None,
        size_before=1000,
        size_after=1000,
        entropy_before=BEFORE,
        entropy_after=AFTER,
        actor=ACTOR,
    )


def _feed(engine: DetectionEngine, count: int, spacing: float) -> list:
    alerts = []
    for i in range(count):
        alerts.extend(engine.observe(_event(i * spacing, f"/docs/f{i}.docx")))
    return alerts


def test_four_qualifying_files_in_window_does_not_fire():
    engine = DetectionEngine(DetectionConfig())
    alerts = _feed(engine, count=4, spacing=0.5)
    assert alerts == []


def test_five_qualifying_files_in_window_fires():
    engine = DetectionEngine(DetectionConfig())
    alerts = _feed(engine, count=5, spacing=0.5)
    assert len(alerts) == 1
    assert alerts[0].status == "detected"
    assert "entropy_transition_burst" in alerts[0].rules_fired


def test_five_qualifying_files_spread_beyond_window_does_not_fire():
    engine = DetectionEngine(DetectionConfig(window_seconds=30.0))
    alerts = _feed(engine, count=5, spacing=10.0)  # spans 0s-40s, window is 30s
    assert alerts == []
