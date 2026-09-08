"""Benign-workload fixtures must not produce a ransomware-like incident --
except one, deliberately: see test_backup_borderline_is_an_accepted_limitation.
"""

from pathlib import Path

from ransomwatch.config import DetectionConfig
from ransomwatch.detector import DetectionEngine
from ransomwatch.sources.replay import iter_replay_events

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"


def _run(relative_path: str, config: DetectionConfig | None = None) -> list:
    engine = DetectionEngine(config or DetectionConfig())
    alerts = []
    last_ts = 0.0
    for event in iter_replay_events(FIXTURE_DIR / relative_path):
        last_ts = event.timestamp
        alerts.extend(engine.observe(event))
    alerts.extend(engine.flush(last_ts))
    return alerts


def test_normal_interactive_produces_no_incident():
    assert _run("benign/normal_interactive.jsonl") == []


def test_git_clean_produces_no_incident():
    """Many rapid deletes alone (mass_delete is supporting-only) must never
    by itself read as ransomware-like activity."""
    assert _run("benign/git_clean.jsonl") == []


def test_archive_create_produces_no_incident():
    """The real 7-Zip false positive CryptoDrop's researchers found (one
    high-entropy archive output) never reaches this project's own
    multi-file threshold."""
    assert _run("benign/archive_create.jsonl") == []


def test_batch_image_transform_produces_no_incident():
    """CryptoDrop's own benign fixture: 1073 JPEGs rotated in place did not
    trigger their detector. Already-compressed media staying below the
    absolute high-entropy threshold with near-zero delta should not either.
    """
    assert _run("benign/batch_image_transform.jsonl") == []


def test_backup_borderline_is_an_accepted_limitation():
    """Backup software is CryptoDrop's own acknowledged hardest false-
    positive class: it legitimately reads many real documents and writes
    high-entropy compressed output, fast, across many files -- almost this
    project's entire signal set. This fixture is deliberately built to
    cross the default thresholds. The point of this test is NOT that the
    detector is broken -- it's that this specific, honest limitation is
    pinned down by a real test rather than left as an unverified claim in
    a README. See PROJECT_NOTES.md and README "Limitations".
    """
    alerts = _run("benign/backup_borderline.jsonl")
    assert alerts, "expected the documented backup false-positive to actually fire"
    assert alerts[0].severity in {"high", "critical"}
