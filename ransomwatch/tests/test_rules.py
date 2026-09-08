"""Unit tests for each individual rule, and for severity/coalescing logic."""

from pathlib import Path

from ransomwatch.config import DetectionConfig
from ransomwatch.detector import DetectionEngine
from ransomwatch.models import EntropySample, FileEvent, ProcessIdentity
from ransomwatch.sources.replay import iter_replay_events

ACTOR = ProcessIdentity(id="proc-1", pid=1, executable="test.exe")
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


def _write(ts, path, before=None, after=None, size_before=1000, size_after=1000, actor=ACTOR):
    return FileEvent(
        timestamp=ts,
        operation="write",
        path=path,
        previous_path=None,
        size_before=size_before,
        size_after=size_after,
        entropy_before=before,
        entropy_after=after,
        actor=actor,
    )


def _rename(ts, path, previous_path, size_before=1000, actor=ACTOR):
    return FileEvent(
        timestamp=ts,
        operation="rename",
        path=path,
        previous_path=previous_path,
        size_before=size_before,
        size_after=size_before,
        entropy_before=None,
        entropy_after=None,
        actor=actor,
    )


def _delete(ts, path, size_before=1000, actor=ACTOR):
    return FileEvent(
        timestamp=ts,
        operation="delete",
        path=path,
        previous_path=None,
        size_before=size_before,
        size_after=None,
        entropy_before=None,
        entropy_after=None,
        actor=actor,
    )


def _create(ts, path, size_after=1000, actor=ACTOR):
    return FileEvent(
        timestamp=ts,
        operation="create",
        path=path,
        previous_path=None,
        size_before=None,
        size_after=size_after,
        entropy_before=None,
        entropy_after=None,
        actor=actor,
    )


def test_extension_churn_requires_pre_existing_file():
    config = DetectionConfig(rename_churn_threshold=3)
    engine = DetectionEngine(config)
    alerts = []
    for i in range(3):
        alerts.extend(
            engine.observe(_rename(i * 0.1, f"/docs/f{i}.locked", f"/docs/f{i}.docx"))
        )
    assert alerts[-1].rules_fired == ["extension_churn"]
    assert alerts[-1].evidence["extension_churn"]["renamed_files"] == 3


def test_extension_churn_ignores_brand_new_files():
    config = DetectionConfig(rename_churn_threshold=3)
    engine = DetectionEngine(config)
    alerts = []
    for i in range(5):
        event = _rename(i * 0.1, f"/docs/f{i}.locked", f"/tmp/f{i}.tmp", size_before=None)
        alerts.extend(engine.observe(event))
    assert alerts == []


def test_directory_spread_fires_on_distinct_directories():
    config = DetectionConfig(directory_spread_threshold=3)
    engine = DetectionEngine(config)
    alerts = []
    for i in range(3):
        alerts.extend(engine.observe(_write(i * 0.1, f"/dept{i}/file.dat")))
    assert alerts[-1].rules_fired == ["directory_spread"]
    assert alerts[-1].evidence["directory_spread"]["directories"] == 3


def test_delete_replace_sequence():
    config = DetectionConfig(delete_replace_threshold=2)
    engine = DetectionEngine(config)
    alerts = []
    for i in range(2):
        alerts.extend(engine.observe(_create(i, f"/docs/f{i}.tmp")))
        alerts.extend(engine.observe(_delete(i + 0.1, f"/docs/f{i}.docx")))
        alerts.extend(engine.observe(_rename(i + 0.2, f"/docs/f{i}.docx", f"/docs/f{i}.tmp")))
    assert alerts[-1].rules_fired == ["delete_replace"]
    assert alerts[-1].evidence["delete_replace"]["replaced_files"] == 2


def test_ransom_note_spread_across_directories():
    config = DetectionConfig(ransom_note_min_directories=3, ransom_note_max_size_bytes=5000)
    engine = DetectionEngine(config)
    alerts = []
    for i, directory in enumerate(["/a", "/b", "/c"]):
        alerts.extend(engine.observe(_create(i * 0.1, f"{directory}/README.txt", size_after=1800)))
    assert alerts[-1].rules_fired == ["ransom_note_spread"]


def test_ransom_note_spread_ignores_large_files():
    config = DetectionConfig(ransom_note_min_directories=3, ransom_note_max_size_bytes=5000)
    engine = DetectionEngine(config)
    alerts = []
    for i, directory in enumerate(["/a", "/b", "/c"]):
        alerts.extend(
            engine.observe(_create(i * 0.1, f"{directory}/README.txt", size_after=1_000_000))
        )
    assert alerts == []


def test_canary_mutation_fires_on_single_event():
    config = DetectionConfig(canary_paths=("/docs/.canary/decoy.docx",))
    engine = DetectionEngine(config)
    alerts = engine.observe(_write(0.0, "/docs/.canary/decoy.docx"))
    assert len(alerts) == 1
    assert alerts[0].rules_fired == ["canary_mutation"]
    assert alerts[0].severity == "medium"  # alone, not combined with another core rule


def test_canary_mutation_does_not_fire_on_creation():
    """Per the research: CANARY_MUTATED/RENAMED/DELETED are valid signals;
    a plain creation at that path is not (nothing existed to mutate yet)."""
    config = DetectionConfig(canary_paths=("/docs/.canary/decoy.docx",))
    engine = DetectionEngine(config)
    alerts = engine.observe(_create(0.0, "/docs/.canary/decoy.docx"))
    assert alerts == []


def test_mass_delete_alone_never_produces_an_incident():
    """Supporting-only rule: many deletes with no other signal isn't an incident."""
    config = DetectionConfig(rename_churn_threshold=3)
    engine = DetectionEngine(config)
    alerts = []
    for i in range(10):
        alerts.extend(engine.observe(_delete(i * 0.01, f"/repo/build/f{i}.o")))
    assert alerts == []


def test_severity_escalates_from_medium_to_high_to_critical():
    config = DetectionConfig(
        transformed_files_threshold=2,
        rename_churn_threshold=2,
        canary_paths=("/docs/canary.docx",),
    )
    engine = DetectionEngine(config)
    before = EntropySample(head=4.0)
    after = EntropySample(head=7.5)  # delta 3.5 (>0.1), below absolute (7.95) threshold

    severities = []
    for i in range(2):
        for alert in engine.observe(_write(i * 0.1, f"/docs/f{i}.docx", before, after)):
            severities.append(alert.severity)
    assert severities[-1] == "medium"  # entropy_transition_burst alone

    for i in range(2):
        for alert in engine.observe(
            _rename(2 + i * 0.1, f"/docs/f{i}.locked", f"/docs/f{i}.docx")
        ):
            severities.append(alert.severity)
    assert severities[-1] == "high"  # + extension_churn = bulk transformation

    for alert in engine.observe(_write(3.0, "/docs/canary.docx", before, after)):
        severities.append(alert.severity)
    assert severities[-1] == "critical"  # + canary_mutation = bulk + escalating


def test_alert_coalescing_detected_then_recovered():
    config = DetectionConfig(
        transformed_files_threshold=2,
        window_seconds=5.0,
        cooldown_seconds=2.0,
    )
    engine = DetectionEngine(config)
    before = EntropySample(head=4.0)
    after = EntropySample(head=7.5)

    statuses = []
    for i in range(2):
        for alert in engine.observe(_write(i * 0.1, f"/docs/f{i}.docx", before, after)):
            statuses.append(alert.status)
    assert statuses[0] == "detected"

    recovered = engine.flush(now=0.2 + 10.0)
    assert any(a.status == "recovered" for a in recovered)


def test_telemetry_quality_reflects_actor_availability():
    config = DetectionConfig(transformed_files_threshold=2)
    engine = DetectionEngine(config)
    before = EntropySample(head=4.0)
    after = EntropySample(head=7.5)
    alerts = []
    for i in range(2):
        alerts.extend(
            engine.observe(_write(i * 0.1, f"/docs/f{i}.docx", before, after, actor=None))
        )
    assert alerts[-1].telemetry_quality == {"process_attribution": False}


def test_fast_transform_fixture_escalates_medium_to_high():
    alerts = _run("suspicious/fast_transform.jsonl")
    severities = [a.severity for a in alerts if a.status in ("detected", "updated")]
    assert severities[0] == "medium"
    assert "high" in severities


def test_ransom_note_spread_fixture_fires():
    alerts = _run("suspicious/ransom_note_spread.jsonl")
    assert alerts
    assert "ransom_note_spread" in alerts[0].rules_fired
    assert alerts[0].severity == "medium"  # alone, not combined with a transformation rule


def test_canary_mutation_fixture_is_only_critical_when_canary_configured():
    canary_path = "/docs/.canary/decoy.docx"

    without_canary = _run("suspicious/canary_mutation_critical.jsonl")
    assert without_canary
    assert without_canary[0].severity == "high"
    assert "canary_mutation" not in without_canary[0].rules_fired

    with_canary = _run(
        "suspicious/canary_mutation_critical.jsonl", DetectionConfig(canary_paths=(canary_path,))
    )
    assert with_canary
    assert with_canary[-1].severity == "critical"
    assert "canary_mutation" in with_canary[-1].rules_fired


def test_directory_spread_fixture_fires_alone():
    alerts = _run("suspicious/directory_spread.jsonl")
    assert alerts
    assert alerts[0].rules_fired == ["directory_spread"]
    assert alerts[0].severity == "medium"
