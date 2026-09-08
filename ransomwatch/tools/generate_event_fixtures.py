"""Generate synthetic JSONL filesystem-telemetry fixtures for the offline test suite.

No real file encryption, malware execution, or user data ever appears here
-- every fixture is a hand-built sequence of FileEvent-shaped JSON records
with explicit, deliberately-chosen entropy/size/timestamp values. This is
the same safety boundary DeauthGuard used for its PCAP fixtures: the
detection logic is fully testable without ever touching anything
malicious.

Run from the ransomwatch/ directory:

    python tools/generate_event_fixtures.py
"""

from __future__ import annotations

import json
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "fixtures"

LOW_ENTROPY = {"head": 4.2, "middle": 4.1, "tail": 4.3}  # ordinary document-ish content
COMPRESSED_ENTROPY = {"head": 7.6, "middle": 7.55, "tail": 7.62}  # already-compressed, e.g. JPEG
ENCRYPTED_ENTROPY = {"head": 7.98, "middle": 7.97, "tail": 7.99}  # ciphertext-like
BELOW_ABS_THRESHOLD_HIGH_DELTA = {"head": 7.85, "middle": 7.83, "tail": 7.86}
EVADED_ENTROPY = {"head": 4.28, "middle": 4.15, "tail": 4.35}  # reshaped to avoid looking encrypted


def _event(
    ts: float,
    op: str,
    path: str,
    *,
    previous_path: str | None = None,
    size_before: int | None = None,
    size_after: int | None = None,
    entropy_before: dict | None = None,
    entropy_after: dict | None = None,
    actor: dict | None = None,
) -> dict:
    return {
        "timestamp": ts,
        "operation": op,
        "path": path,
        "previous_path": previous_path,
        "size_before": size_before,
        "size_after": size_after,
        "entropy_before": entropy_before,
        "entropy_after": entropy_after,
        "actor": actor,
    }


def _actor(id_: str, pid: int, image: str) -> dict:
    return {"id": id_, "pid": pid, "executable": image}


def _write(actor, ts, path, before_size, after_size, before_e, after_e):
    return _event(
        ts,
        "write",
        path,
        size_before=before_size,
        size_after=after_size,
        entropy_before=before_e,
        entropy_after=after_e,
        actor=actor,
    )


# ---------------------------------------------------------------- benign ---


def build_normal_interactive() -> list[dict]:
    """A handful of ordinary, spaced-out document saves -- no rule should fire."""
    actor = _actor("proc-user", 100, "winword.exe")
    return [
        _write(actor, 0.0, "/docs/report.docx", 40000, 40120, LOW_ENTROPY, LOW_ENTROPY),
        _write(actor, 30.0, "/docs/notes.txt", 2000, 2050, LOW_ENTROPY, LOW_ENTROPY),
        _write(actor, 90.0, "/docs/report.docx", 40120, 40300, LOW_ENTROPY, LOW_ENTROPY),
    ]


def build_git_clean() -> list[dict]:
    """Many rapid deletes, no entropy transitions, no encrypted output."""
    actor = _actor("proc-git", 200, "git.exe")
    events = []
    for i in range(20):
        events.append(
            _event(i * 0.02, "delete", f"/repo/build/artifact{i}.o", size_before=4096, actor=actor)
        )
    return events


def build_archive_create() -> list[dict]:
    """7-Zip's own documented false-positive case: many reads (invisible to
    this event model), one high-entropy archive output. A single output
    file can never reach the multi-file threshold alone.
    """
    actor = _actor("proc-7z", 300, "7z.exe")
    return [
        _event(
            0.5,
            "create",
            "/docs/backup.7z",
            size_after=9_000_000,
            entropy_after=ENCRYPTED_ENTROPY,
            actor=actor,
        )
    ]


def build_batch_image_transform() -> list[dict]:
    """ImageMagick rotating many JPEGs in place (CryptoDrop's own benign
    fixture: 1073 JPEGs rotated in place did not trigger their detector).
    JPEGs are already compressed (high-ish entropy) and stay there --
    below the absolute high-entropy threshold, and the delta stays small.
    """
    actor = _actor("proc-magick", 400, "convert.exe")
    events = []
    for i in range(30):
        events.append(
            _write(
                actor,
                i * 0.05,
                f"/photos/img{i:03d}.jpg",
                2_000_000,
                2_010_000,
                COMPRESSED_ENTROPY,
                COMPRESSED_ENTROPY,
            )
        )
    return events


def build_backup_borderline() -> list[dict]:
    """The hardest documented false-positive class (see PROJECT_NOTES.md):
    backup software reads many real documents and writes compressed,
    high-entropy output across many files, fast. This fixture is
    DELIBERATELY built to cross this project's own thresholds -- the test
    for it asserts that it fires, and documents why that's an accepted,
    honestly-disclosed limitation rather than a bug.
    """
    actor = _actor("proc-backup", 500, "backup-agent.exe")
    events = []
    for i in range(12):
        events.append(
            _write(
                actor,
                i * 1.0,
                f"/backup/vault/2026-09-09/doc{i}.bak",
                50000,
                48000,
                LOW_ENTROPY,
                ENCRYPTED_ENTROPY,
            )
        )
    return events


# ------------------------------------------------------------ suspicious ---


def build_fast_transform() -> list[dict]:
    """Escalating incident: entropy-transition-burst fires alone first
    (MEDIUM), then extension-churn joins once renames start (HIGH).
    entropy_after is kept just under the absolute high-entropy threshold
    (7.95) so high_entropy_output_burst doesn't also fire simultaneously --
    demonstrating the two rules escalate independently, not in lockstep.
    """
    actor = _actor("proc-0042", 7210, "svchost32.exe")
    events = []
    for i in range(10):
        events.append(
            _write(
                actor,
                i * 0.3,
                f"/docs/file{i}.docx",
                40000,
                40000,
                LOW_ENTROPY,
                BELOW_ABS_THRESHOLD_HIGH_DELTA,
            )
        )
    for i in range(10):
        events.append(
            _event(
                4.0 + i * 0.1,
                "rename",
                f"/docs/file{i}.docx.locked",
                previous_path=f"/docs/file{i}.docx",
                size_before=40000,
                size_after=40000,
                actor=actor,
            )
        )
    return events


def build_ransom_note_spread() -> list[dict]:
    """The same small ransom-note-like artifact created in many directories."""
    actor = _actor("proc-0099", 8888, "svchost32.exe")
    events = []
    for i, directory in enumerate(["/docs", "/photos", "/music", "/desktop"]):
        events.append(
            _event(
                i * 0.2,
                "create",
                f"{directory}/README_RECOVER_FILES.txt",
                size_after=1800,
                actor=actor,
            )
        )
    return events


def build_canary_mutation_critical() -> list[dict]:
    """Bulk transformation (entropy-transition-burst) plus a canary
    mutation together -- the spec's example of a CRITICAL combination.
    """
    actor = _actor("proc-0007", 4242, "svchost32.exe")
    events = []
    for i in range(6):
        events.append(
            _write(
                actor,
                i * 0.3,
                f"/docs/important{i}.xlsx",
                20000,
                20000,
                LOW_ENTROPY,
                ENCRYPTED_ENTROPY,
            )
        )
    events.append(
        _write(
            actor,
            2.0,
            "/docs/.canary/decoy.docx",
            10000,
            10000,
            LOW_ENTROPY,
            ENCRYPTED_ENTROPY,
        )
    )
    return events


def build_directory_spread() -> list[dict]:
    """Plain writes (no entropy field available) spread across many
    directories -- demonstrates directory-spread firing independently of
    any entropy signal.
    """
    actor = _actor("proc-0055", 5151, "unknown-agent.exe")
    events = []
    for i in range(9):
        events.append(
            _event(
                i * 0.2,
                "write",
                f"/data/dept{i}/queue/item.dat",
                size_before=1000,
                size_after=1050,
                actor=actor,
            )
        )
    return events


# -------------------------------------------------------------- evasions ---


def build_low_and_slow() -> list[dict]:
    """One transformed file every 45 seconds -- well under the 30s window,
    so the burst rule never accumulates enough qualifying files at once.
    Documented miss, not a test failure.
    """
    actor = _actor("proc-slow", 6161, "backgroundtask.exe")
    events = []
    for i in range(6):
        events.append(
            _write(
                actor,
                i * 45.0,
                f"/docs/slow{i}.docx",
                20000,
                20000,
                LOW_ENTROPY,
                ENCRYPTED_ENTROPY,
            )
        )
    return events


def build_partial_encryption_sampling_miss() -> list[dict]:
    """Files are being transformed, but only in byte ranges this project's
    head/middle/tail sampling doesn't cover -- entropy_before/after look
    nearly identical in every sampled region despite a real size change.
    Documented blind spot (see README "Limitations").
    """
    actor = _actor("proc-partial", 7171, "unknown-agent.exe")
    events = []
    for i in range(8):
        events.append(
            _write(
                actor,
                i * 0.3,
                f"/docs/large{i}.bin",
                50_000_000,
                50_000_128,
                LOW_ENTROPY,
                LOW_ENTROPY,
            )
        )
    return events


def build_entropy_evasion() -> list[dict]:
    """Content is transformed but reshaped to avoid looking like ciphertext
    (see PROJECT_NOTES.md reference [4]), AND the attacker leaves
    extensions/paths unchanged. Nothing here should fire -- documents that
    entropy-only evasion combined with no other behavioral change is a
    genuine, disclosed miss for this rule set.
    """
    actor = _actor("proc-evasion", 8181, "unknown-agent.exe")
    events = []
    for i in range(8):
        events.append(
            _write(
                actor,
                i * 0.3,
                f"/docs/evaded{i}.docx",
                20000,
                20000,
                LOW_ENTROPY,
                EVADED_ENTROPY,  # delta stays well under entropy_delta_threshold (0.1)
            )
        )
    return events


def build_multiprocess_split() -> list[dict]:
    """The same overall malicious pattern split across three actors, each
    individually under the per-actor threshold. Host-wide total (9 files)
    exceeds what a single process would need, but each process's own
    window never crosses 5 -- documented per-process-correlation blind
    spot (see README "Limitations").
    """
    events = []
    for actor_index in range(3):
        actor = _actor(f"proc-split-{actor_index}", 9000 + actor_index, "unknown-agent.exe")
        for i in range(3):
            events.append(
                _write(
                    actor,
                    actor_index * 0.05 + i * 0.3,
                    f"/docs/split_{actor_index}_{i}.docx",
                    20000,
                    20000,
                    LOW_ENTROPY,
                    ENCRYPTED_ENTROPY,
                )
            )
    return events


def build_canary_avoided() -> list[dict]:
    """A real attack that happens to never touch the configured canary --
    still caught by entropy-transition-burst and extension-churn, showing
    canary absence doesn't prevent detection via orthogonal signals.
    """
    actor = _actor("proc-avoids-canary", 9500, "svchost32.exe")
    events = []
    for i in range(6):
        events.append(
            _write(
                actor,
                i * 0.3,
                f"/docs/target{i}.docx",
                20000,
                20000,
                LOW_ENTROPY,
                ENCRYPTED_ENTROPY,
            )
        )
    for i in range(6):
        events.append(
            _event(
                2.0 + i * 0.1,
                "rename",
                f"/docs/target{i}.docx.locked",
                previous_path=f"/docs/target{i}.docx",
                size_before=20000,
                size_after=20000,
                actor=actor,
            )
        )
    return events


def _write_jsonl(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event))
            fh.write("\n")


def main() -> None:
    fixtures = {
        "benign/normal_interactive.jsonl": build_normal_interactive(),
        "benign/git_clean.jsonl": build_git_clean(),
        "benign/archive_create.jsonl": build_archive_create(),
        "benign/batch_image_transform.jsonl": build_batch_image_transform(),
        "benign/backup_borderline.jsonl": build_backup_borderline(),
        "suspicious/fast_transform.jsonl": build_fast_transform(),
        "suspicious/ransom_note_spread.jsonl": build_ransom_note_spread(),
        "suspicious/canary_mutation_critical.jsonl": build_canary_mutation_critical(),
        "suspicious/directory_spread.jsonl": build_directory_spread(),
        "evasions/low_and_slow.jsonl": build_low_and_slow(),
        "evasions/partial_encryption_sampling_miss.jsonl": build_partial_encryption_sampling_miss(),
        "evasions/entropy_evasion.jsonl": build_entropy_evasion(),
        "evasions/multiprocess_split.jsonl": build_multiprocess_split(),
        "evasions/canary_avoided.jsonl": build_canary_avoided(),
    }
    for relative_path, events in fixtures.items():
        out_path = OUT_DIR / relative_path
        _write_jsonl(out_path, events)
        print(f"wrote {relative_path} ({len(events)} events)")


if __name__ == "__main__":
    main()
