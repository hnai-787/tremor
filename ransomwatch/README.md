# RansomWatch

A passive, host-based behavioral detector for ransomware-like file
transformations. Analyzes a live-monitored directory or a replayed JSONL
event log using seven independent, explainable detection rules.

## Why this design (research grounding)

Full research writeup, including exactly which threshold traces back to
which real system, is in `../PROJECT.md`. The short version:

- **High entropy is not encryption.** Compressed archives, media, and
  Office documents can already be high-entropy. `entropy_transition_burst`
  requires a *delta*, not just an absolute value; `high_entropy_output_burst`
  requires an absolute floor across *multiple distinct files*, not one.
- **Bulk file transformation is not malicious intent.** Backup and
  compression software legitimately do this -- see
  `fixtures/benign/backup_borderline.jsonl`, a fixture deliberately built
  to demonstrate this project's own honestly-acknowledged false-positive
  risk, matching a real false positive CryptoDrop's own researchers found
  with 7-Zip.
- **One filesystem event is not ransomware.** Every rule is
  windowed/rate-based except `canary_mutation`, which is deliberately the
  one single-event signal -- a configured decoy file has no ordinary
  reason to change at all.
- **Unknown process is not unknown behavior.** Portable live telemetry
  (`watchdog`/inotify) cannot attribute events to a process. Rather than
  fabricate an identity or silently under-detect, events without an actor
  correlate through one host-wide pool instead.

## Requirements

- Python 3.11+
- For live monitoring only: `pip install -e ".[live]"` (installs
  `watchdog`). Offline analysis and the full test suite need nothing
  beyond the base install.

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Usage

```bash
# Analyze an offline JSONL event log
ransomwatch analyze fixtures/suspicious/fast_transform.jsonl

# Same, as JSON (for piping into another tool)
ransomwatch analyze fixtures/suspicious/fast_transform.jsonl --json

# Live monitoring (requires the 'live' extra), with a configured canary
ransomwatch monitor ~/Documents --canary ~/Documents/.canary/decoy.docx

# Override defaults via a config file
ransomwatch analyze trace.jsonl --config config/default.yaml
```

## Detection rules

See the top-level `../README.md` "Detection rules" table for the full
list and defaults. All seven core rules use the same 30-second sliding
window per actor; `canary_mutation` is the one single-event exception.

Alerts are coalesced (`detected -> updated -> recovered`), with `updated`
throttled to once per `update_interval_seconds` -- except an immediate
re-emit whenever the *active rule set itself* changes (a new rule joining
an incident, or severity escalating), so escalation is never silently
swallowed by the throttle.

## Architecture

```text
JSONL Replay ──┐
               ├──> FileEvent ──> DetectionEngine (per-actor sliding windows) ──> Alert ──> text/JSON
Live Directory ┘        ^
                         |
              entropy.py + baseline.py (live source only --
              replay fixtures carry entropy pre-computed)
```

The detector never knows or cares which source produced an event -- see
`src/ransomwatch/sources/`. `entropy.py`/`baseline.py` are exercised only
by the live watchdog source; offline fixtures already carry
`entropy_before`/`entropy_after` directly, computed once by
`tools/generate_event_fixtures.py`.

## Limitations (honest, not hidden)

See the top-level `../README.md` "Limitations" for the full list:
no process attribution in portable live mode, partial/intermittent
encryption blind spots from region sampling, known entropy-reshaping
evasion, low-and-slow window evasion, and per-actor-only correlation.
Every one of these is pinned down by an actual failing-on-purpose test in
`tests/test_limitations.py`, not just asserted in prose.

## Testing

```bash
pytest -q
ruff check src tests tools
```

`fixtures/{benign,suspicious,evasions}/*.jsonl` are committed, synthetic
event logs (`tools/generate_event_fixtures.py`) -- no real ransomware,
encryption, or malware sample exists anywhere in this project.
