"""A detector's test suite should include cases it is expected NOT to
catch. Each of these documents a real, disclosed blind spot (see
PROJECT_NOTES.md / README "Limitations") -- these are not bugs, and
"fixing" one of them without also updating that documentation would be
incorrect.
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


def test_low_and_slow_evades_the_burst_window():
    """One transformed file every 45s, window is 30s -- documented miss."""
    assert _run("evasions/low_and_slow.jsonl") == []


def test_partial_encryption_outside_sampled_regions_is_missed():
    """Encryption occurring outside the sampled head/middle/tail regions
    produces no detectable entropy change in this project's telemetry,
    even though the file size changed substantially."""
    assert _run("evasions/partial_encryption_sampling_miss.jsonl") == []


def test_entropy_reshaping_evasion_with_no_other_signal_is_missed():
    """Content transformed but reshaped to avoid a ciphertext-like entropy
    signature, with no rename/extension/directory change either --
    entropy-only evasion combined with no other behavioral change is a
    genuine, disclosed miss for this rule set."""
    assert _run("evasions/entropy_evasion.jsonl") == []


def test_splitting_across_processes_evades_per_actor_thresholds():
    """The same overall pattern split across three actors, each
    individually under threshold -- even with real process attribution,
    a per-actor-only model doesn't aggregate a host-wide campaign."""
    assert _run("evasions/multiprocess_split.jsonl") == []


def test_avoiding_the_canary_does_not_prevent_detection():
    """A positive control: unlike the misses above, this attack simply
    never touches the configured canary and is still caught via
    orthogonal signals (entropy + high-entropy-output), demonstrating that
    canary absence is not a full bypass on its own."""
    config = DetectionConfig(canary_paths=("/docs/.canary/decoy.docx",))
    alerts = _run("evasions/canary_avoided.jsonl", config)
    assert alerts
    assert "canary_mutation" not in alerts[-1].rules_fired
    assert alerts[-1].severity in {"high", "critical"}
