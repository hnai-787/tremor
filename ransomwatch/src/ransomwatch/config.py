"""Detection configuration, loadable from YAML (see config/default.yaml).

Every threshold here is labeled in PROJECT_NOTES.md by where it came from:
`window_seconds`/`transformed_files_threshold` mirror Objective-See's
RansomWhere? (>=5 encrypted files/30s); `entropy_delta_threshold` is
CryptoDrop-inspired (their write-vs-read entropy delta uses the same 0.1
figure, though it's a different measurement than this project's
before/after per-file delta); `entropy_absolute_threshold` mirrors
RansomWhere?'s ~7.95 bits/byte floor. Every other threshold
(rename/directory/delete-replace/ransom-note counts) is this project's own
operational policy -- none of this is a published, universal standard for
"what ransomware looks like," and the research behind it explicitly warns
against presenting it as one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: float = 30.0

    # entropy_transition_burst / high_entropy_output_burst
    transformed_files_threshold: int = 5
    entropy_delta_threshold: float = 0.1
    entropy_absolute_threshold: float = 7.95

    # extension_churn
    rename_churn_threshold: int = 10

    # directory_spread
    directory_spread_threshold: int = 8

    # delete_replace
    delete_replace_threshold: int = 5

    # mass_delete (supporting only -- never sufficient alone, see detector.py)
    mass_delete_threshold: int = 15

    # ransom_note_spread
    ransom_note_max_size_bytes: int = 10 * 1024
    ransom_note_min_directories: int = 3

    # canary_mutation -- empty by default; must be explicitly configured
    canary_paths: tuple[str, ...] = field(default_factory=tuple)

    # alert coalescing (same design as DeauthGuard)
    cooldown_seconds: float = 30.0
    update_interval_seconds: float = 1.0

    # live-source entropy sampling
    sample_bytes: int = 65536


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "default.yaml"


def load_config(path: str | Path | None = None) -> DetectionConfig:
    """Load a DetectionConfig from YAML, falling back to defaults for any omitted key."""
    data: dict[str, Any] = {}
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        data = loaded.get("detection", {})

    defaults = DetectionConfig()
    return DetectionConfig(
        window_seconds=float(data.get("window_seconds", defaults.window_seconds)),
        transformed_files_threshold=int(
            data.get("transformed_files_threshold", defaults.transformed_files_threshold)
        ),
        entropy_delta_threshold=float(
            data.get("entropy_delta_threshold", defaults.entropy_delta_threshold)
        ),
        entropy_absolute_threshold=float(
            data.get("entropy_absolute_threshold", defaults.entropy_absolute_threshold)
        ),
        rename_churn_threshold=int(
            data.get("rename_churn_threshold", defaults.rename_churn_threshold)
        ),
        directory_spread_threshold=int(
            data.get("directory_spread_threshold", defaults.directory_spread_threshold)
        ),
        delete_replace_threshold=int(
            data.get("delete_replace_threshold", defaults.delete_replace_threshold)
        ),
        mass_delete_threshold=int(
            data.get("mass_delete_threshold", defaults.mass_delete_threshold)
        ),
        ransom_note_max_size_bytes=int(
            data.get("ransom_note_max_size_bytes", defaults.ransom_note_max_size_bytes)
        ),
        ransom_note_min_directories=int(
            data.get("ransom_note_min_directories", defaults.ransom_note_min_directories)
        ),
        canary_paths=tuple(data.get("canary_paths", defaults.canary_paths)),
        cooldown_seconds=float(data.get("cooldown_seconds", defaults.cooldown_seconds)),
        update_interval_seconds=float(
            data.get("update_interval_seconds", defaults.update_interval_seconds)
        ),
        sample_bytes=int(data.get("sample_bytes", defaults.sample_bytes)),
    )
