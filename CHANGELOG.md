# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.0.0] - 2026-09-09

### Added

- **`ransomwatch/`**: a passive, host-based behavioral detector for
  ransomware-like file transformations, replacing an earlier
  partially-completed static malware-analysis project in this workspace.
  Analyzes a live-monitored directory or a replayed JSONL event log using
  seven independent, explainable detection rules
  (`entropy_transition_burst`, `high_entropy_output_burst`,
  `extension_churn`, `directory_spread`, `delete_replace`,
  `ransom_note_spread`, `canary_mutation`) plus one supporting-only signal
  (`mass_delete`).
- A `research-inspired-v1` default preset, with every threshold traced to
  its source in `PROJECT.md`: `window_seconds`/`transformed_files_threshold`
  and `entropy_absolute_threshold` mirror Objective-See's real,
  open-source RansomWhere? detector; `entropy_delta_threshold` is
  CryptoDrop-inspired. Every other threshold is this project's own
  documented operational policy.
- Severity computed from which rules are jointly active (medium -> high ->
  critical), never a numeric score.
- Alert coalescing (`detected -> updated -> recovered`) so one long
  incident produces one evolving alert, not one per event.
- 14 synthetic JSONL fixtures (`fixtures/{benign,suspicious,evasions}/`,
  `tools/generate_event_fixtures.py`) -- including real documented
  false-positive classes (a 7-Zip-equivalent single high-entropy output,
  CryptoDrop's own 1073-JPEGs-rotated-in-place benign case, and a
  deliberately-crossing backup-software case kept as an honestly
  documented limitation, not a hidden bug) and real documented evasions
  (low-and-slow, partial-encryption sampling miss, entropy-reshaping,
  per-process splitting).
- 39 pytest tests, fully offline -- no real ransomware, encryption
  routine, or malware sample anywhere in the repository.
- `.github/workflows/ransomwatch-ci.yml`: lint + a full, real pytest run
  (no hardware or live monitoring required).

### Changed

### Fixed
