"""Sliding-window, multi-rule ransomware-behavioral detection engine.

Design principles locked before implementation (full research writeup in
PROJECT_NOTES.md):

- high entropy != encryption: compressed media/archives/Office documents
  can be high-entropy too. Entropy is one signal among several, never a
  standalone verdict.
- bulk file transformation != malicious intent: backup, compression, and
  package-install tooling legitimately touch many files fast. This module
  explicitly does not (and cannot) determine intent -- see `Alert.severity`
  docstring and README "What this tool does not claim".
- one filesystem event != ransomware: every rule here is windowed/rate
  based except `canary_mutation`, which is deliberately a single-event,
  zero-ordinary-reason-to-fire signal.
- unknown process != unknown behavior: when a source can't attribute
  events to a process (the portable default -- see sources/watchdog_source.py),
  correlation degrades to one host-wide actor pool rather than silently
  under-detecting or fabricating identity.

Severity is computed from *which* rules are jointly active for an actor,
never from a single opaque score -- see `_severity_for`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .config import DetectionConfig
from .entropy import is_high_entropy, max_segment_delta
from .models import FileEvent

Severity = Literal["medium", "high", "critical"]
AlertStatus = Literal["detected", "updated", "recovered"]

# Rules whose joint activity constitutes "bulk transformation" for severity
# purposes (see _severity_for). canary_mutation and ransom_note_spread are
# evaluated separately since they escalate severity rather than counting
# toward the bulk-transformation tally on their own.
_TRANSFORMATION_RULES = frozenset(
    {
        "entropy_transition_burst",
        "high_entropy_output_burst",
        "extension_churn",
        "directory_spread",
        "delete_replace",
    }
)
_ESCALATING_RULES = frozenset({"canary_mutation", "ransom_note_spread"})
_CORE_RULES = _TRANSFORMATION_RULES | _ESCALATING_RULES
_SUPPORTING_RULES = frozenset({"mass_delete"})


@dataclass(frozen=True)
class RuleFinding:
    rule: str
    fired_at: float
    evidence: dict


@dataclass(frozen=True)
class Alert:
    timestamp: float
    actor: str
    status: AlertStatus
    severity: Severity | None  # None on "recovered"
    classification: str

    rules_fired: list[str]
    evidence: dict[str, dict]
    telemetry_quality: dict[str, bool]

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "actor": self.actor,
            "status": self.status,
            "severity": self.severity,
            "classification": self.classification,
            "rules_fired": self.rules_fired,
            "evidence": self.evidence,
            "telemetry_quality": self.telemetry_quality,
        }


def _dirname(path: str) -> str:
    return str(Path(path).parent)


def _latest_by_path(events: list[FileEvent]) -> dict[str, FileEvent]:
    latest: dict[str, FileEvent] = {}
    for event in events:
        latest[event.path] = event
    return latest


def _eval_entropy_transition_burst(events: list[FileEvent], config: DetectionConfig) -> dict | None:
    qualifying = []
    for event in _latest_by_path(events).values():
        if event.entropy_before is None:
            continue
        delta = max_segment_delta(event.entropy_before, event.entropy_after)
        if delta is not None and delta >= config.entropy_delta_threshold:
            qualifying.append((event.path, delta))

    if len(qualifying) < config.transformed_files_threshold:
        return None

    deltas = sorted(d for _, d in qualifying)
    median = deltas[len(deltas) // 2]
    return {
        "files": len(qualifying),
        "median_delta": round(median, 3),
        "max_delta": round(max(deltas), 3),
    }


def _eval_high_entropy_output_burst(
    events: list[FileEvent], config: DetectionConfig
) -> dict | None:
    qualifying = [
        event.path
        for event in _latest_by_path(events).values()
        if is_high_entropy(event.entropy_after, config.entropy_absolute_threshold)
    ]
    if len(qualifying) < config.transformed_files_threshold:
        return None
    return {"files": len(qualifying)}


def _eval_extension_churn(events: list[FileEvent], config: DetectionConfig) -> dict | None:
    renamed = 0
    for event in events:
        if event.operation != "rename" or event.previous_path is None:
            continue
        if event.size_before is None:
            continue  # not a pre-existing file
        if Path(event.previous_path).suffix != Path(event.path).suffix:
            renamed += 1
    if renamed < config.rename_churn_threshold:
        return None
    return {"renamed_files": renamed}


def _eval_directory_spread(events: list[FileEvent], config: DetectionConfig) -> dict | None:
    directories: set[str] = set()
    files: set[str] = set()
    for event in events:
        directories.add(_dirname(event.path))
        files.add(event.path)
    if len(directories) < config.directory_spread_threshold:
        return None
    return {"directories": len(directories), "files": len(files)}


def _eval_delete_replace(events: list[FileEvent], config: DetectionConfig) -> dict | None:
    deleted_paths = {e.path for e in events if e.operation == "delete"}
    replaced = {
        e.path
        for e in events
        if e.operation == "rename" and e.path in deleted_paths
    }
    if len(replaced) < config.delete_replace_threshold:
        return None
    return {"replaced_files": len(replaced)}


def _eval_ransom_note_spread(events: list[FileEvent], config: DetectionConfig) -> dict | None:
    candidates: dict[str, set[str]] = {}
    for event in events:
        if event.operation != "create" or event.size_after is None:
            continue
        if event.size_after > config.ransom_note_max_size_bytes:
            continue
        basename = Path(event.path).name
        candidates.setdefault(basename, set()).add(_dirname(event.path))

    for basename, dirs in candidates.items():
        if len(dirs) >= config.ransom_note_min_directories:
            return {"basename": basename, "directories": len(dirs)}
    return None


def _eval_mass_delete(events: list[FileEvent], config: DetectionConfig) -> dict | None:
    count = sum(1 for e in events if e.operation == "delete")
    if count < config.mass_delete_threshold:
        return None
    return {"deleted_files": count}


def _severity_for(active_rules: set[str]) -> Severity | None:
    core_active = active_rules & _CORE_RULES
    if not core_active:
        return None  # supporting-only (or nothing) never alone constitutes an incident

    bulk_transformation = len(core_active) >= 2
    escalating_active = bool(core_active & _ESCALATING_RULES)

    if bulk_transformation and escalating_active:
        return "critical"
    if bulk_transformation:
        return "high"
    return "medium"


@dataclass
class _ActorState:
    window: deque = field(default_factory=deque)
    findings: dict[str, RuleFinding] = field(default_factory=dict)
    open: bool = False
    last_emitted_at: float = 0.0
    last_emitted_signature: tuple[Severity | None, frozenset[str]] = (None, frozenset())
    saw_actor_identity: bool = False


class DetectionEngine:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._actors: dict[str, _ActorState] = {}

    def observe(self, event: FileEvent) -> list[Alert]:
        actor_key = event.actor_key
        state = self._actors.setdefault(actor_key, _ActorState())
        if event.actor is not None:
            state.saw_actor_identity = True

        state.window.append(event)
        self._trim(state.window, event.timestamp)

        window_events = list(state.window)
        evaluated = {
            "entropy_transition_burst": _eval_entropy_transition_burst(
                window_events, self.config
            ),
            "high_entropy_output_burst": _eval_high_entropy_output_burst(
                window_events, self.config
            ),
            "extension_churn": _eval_extension_churn(window_events, self.config),
            "directory_spread": _eval_directory_spread(window_events, self.config),
            "delete_replace": _eval_delete_replace(window_events, self.config),
            "ransom_note_spread": _eval_ransom_note_spread(window_events, self.config),
            "mass_delete": _eval_mass_delete(window_events, self.config),
        }

        if self._touches_canary(event):
            evaluated["canary_mutation"] = {"path": event.path, "operation": event.operation}

        for rule, evidence in evaluated.items():
            if evidence is not None:
                state.findings[rule] = RuleFinding(rule=rule, fired_at=event.timestamp, evidence=evidence)

        self._reap(state, event.timestamp)

        return self._maybe_emit(actor_key, state, event.timestamp)

    def flush(self, now: float) -> list[Alert]:
        alerts: list[Alert] = []
        for actor_key, state in self._actors.items():
            self._reap(state, now)
            alerts.extend(self._maybe_emit(actor_key, state, now))
        return alerts

    def _touches_canary(self, event: FileEvent) -> bool:
        if not self.config.canary_paths:
            return False
        if event.operation == "create":
            return False
        touched = {event.path}
        if event.previous_path:
            touched.add(event.previous_path)
        return bool(touched & set(self.config.canary_paths))

    def _trim(self, window: deque, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while window and window[0].timestamp < cutoff:
            window.popleft()

    def _reap(self, state: _ActorState, now: float) -> None:
        stale = [
            rule
            for rule, finding in state.findings.items()
            if (now - finding.fired_at) > self.config.cooldown_seconds
        ]
        for rule in stale:
            del state.findings[rule]

    def _maybe_emit(self, actor_key: str, state: _ActorState, now: float) -> list[Alert]:
        active_rules = set(state.findings)
        severity = _severity_for(active_rules)
        core_active = sorted(active_rules & _CORE_RULES)
        signature = (severity, frozenset(core_active))

        if severity is None:
            if state.open:
                state.open = False
                state.last_emitted_signature = (None, frozenset())
                return [
                    Alert(
                        timestamp=now,
                        actor=actor_key,
                        status="recovered",
                        severity=None,
                        classification="ransomware-like-file-transformation",
                        rules_fired=[],
                        evidence={},
                        telemetry_quality={"process_attribution": state.saw_actor_identity},
                    )
                ]
            return []

        if not state.open:
            status: AlertStatus = "detected"
        elif signature != state.last_emitted_signature or (
            now - state.last_emitted_at
        ) >= self.config.update_interval_seconds:
            status = "updated"
        else:
            return []

        state.open = True
        state.last_emitted_at = now
        state.last_emitted_signature = signature

        evidence = {rule: state.findings[rule].evidence for rule in core_active}
        return [
            Alert(
                timestamp=now,
                actor=actor_key,
                status=status,
                severity=severity,
                classification="ransomware-like-file-transformation",
                rules_fired=core_active,
                evidence=evidence,
                telemetry_quality={"process_attribution": state.saw_actor_identity},
            )
        ]
