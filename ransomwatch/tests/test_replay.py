from pathlib import Path

from ransomwatch.sources.replay import iter_replay_events

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"


def test_parses_all_field_types():
    events = list(iter_replay_events(FIXTURE_DIR / "suspicious" / "fast_transform.jsonl"))
    assert len(events) == 20

    write_event = events[0]
    assert write_event.operation == "write"
    assert write_event.actor is not None
    assert write_event.actor.id == "proc-0042"
    assert write_event.entropy_before is not None
    assert write_event.entropy_before.head == 4.2

    rename_event = events[10]
    assert rename_event.operation == "rename"
    assert rename_event.previous_path == "/docs/file0.docx"
    assert rename_event.path == "/docs/file0.docx.locked"


def test_missing_optional_fields_default_to_none():
    events = list(iter_replay_events(FIXTURE_DIR / "benign" / "git_clean.jsonl"))
    event = events[0]
    assert event.operation == "delete"
    assert event.entropy_before is None
    assert event.entropy_after is None
    assert event.size_after is None


def test_events_are_time_ordered_by_timestamp_field():
    events = list(iter_replay_events(FIXTURE_DIR / "evasions" / "low_and_slow.jsonl"))
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)
    assert timestamps[-1] - timestamps[0] == 225.0
