# Ransomware Behavioral Detection Engine — Project Notes

## Problem / Motivation

This replaces an earlier project in this workspace
(`netsupport-rat-analysis`) that was removed by explicit decision -- it was
a partially-completed static malware-analysis exercise. Rather than
another one-off "analyze this binary" project, this builds something
reusable: a real behavioral detector for ransomware-like file
transformation, following the same pattern used for
[Squall](../squall/deauthguard/README.md)
(external research first, then a small, tested, explainable tool grounded
in that research -- never an invented heuristic).

## Context & Constraints

- No real ransomware, malware sample, or destructive encryption routine
  may exist anywhere in this repository (workspace-wide safety boundary).
  Every test fixture is a hand-built, synthetic JSON event record.
- The tool is a **detector only** -- no remediation, no process
  suspension, no file restoration, no counterattack.

## Research grounding (external research, summarized)

Full external research is preserved in this project's conversation
history; the parts that directly shaped the implementation:

- **Objective-See's RansomWhere?** (an actively maintained, real
  open-source macOS ransomware detector) is the closest analogue to
  Kismet's role in DeauthGuard's design: a real system whose actual
  thresholds could be inspected. Its current implementation tracks
  encrypted files per process, prunes observations older than 30 seconds,
  and triggers at >=5 encrypted files in that window. That pairing
  (`window_seconds=30`, `transformed_files_threshold=5`) is this
  project's default preset -- documented explicitly as RansomWhere?
  -inspired, not a universal standard.
- RansomWhere?'s entropy classifier uses an absolute floor around **7.95
  bits/byte** but never treats that alone as sufficient -- reused here as
  `entropy_absolute_threshold`, feeding `high_entropy_output_burst`
  only in combination with a multi-file count, never a single-file
  trigger.
- **CryptoDrop** (Scaife, Carter, Traynor & Butler, ICDCS 2016) is the
  strongest direct precedent for combining multiple independent
  behavioral signals rather than trusting one. Their write-vs-read
  process entropy delta uses `>=0.1` specifically because compressed
  files can already be high-entropy and encryption may only nudge that
  further. Reused here as `entropy_delta_threshold`, applied to a
  different measurement (per-file before/after sampled-region delta, not
  CryptoDrop's weighted whole-process read/write delta) -- documented as
  such rather than claimed equivalent.
- CryptoDrop's own published evaluation found exactly **one** false
  positive across 30 tested ordinary Windows applications: **7-Zip**,
  archiving many real user documents into one high-entropy output. That
  real, cited result is directly encoded as `fixtures/benign/archive_create.jsonl`
  and as the batch-image-transform fixture (their own benchmark: 1073
  JPEGs rotated in place did not trigger their detector).
- **MITRE ATT&CK T1486 / DET0215** (current, 2025-2026 detection
  guidance) independently confirms the same underlying signal set --
  high-frequency writes, extension changes, and ransom notes created
  across multiple directories -- validating that this isn't an invented
  heuristic but consistent with current industry detection-engineering
  practice.
- **Two real, cited architectural corrections were made before writing
  any code**, both directly reflected in `models.py`:
  1. Linux inotify (which portable `watchdog` uses) documents explicitly
     that it reports no information about the process responsible for an
     event. So `FileEvent.actor` is `Optional`, never fabricated, and the
     detector's correlation degrades to a host-wide pool when it's
     missing, rather than pretending per-process attribution exists.
  2. An absolute entropy threshold is not itself a detector -- RansomWhere?'s
     own real implementation requires high entropy *plus* additional
     statistical checks, and recent research (Bang, Kim & Lee, 2024)
     demonstrates entropy-reshaping techniques that specifically defeat
     entropy-only detection. Entropy here is always one signal among
     several engineered rules, never a standalone verdict.

## Architecture

```text
JSONL Replay ──┐
               ├──> FileEvent ──> DetectionEngine (per-actor sliding windows, 7 rules) ──> Alert
Live Directory ┘
```

Diagrams beyond this are in `ransomwatch/README.md` "Architecture".

## Key Decisions

- **Seven independent rules, evidence-carrying, no composite score** --
  directly following the research's explicit warning against inventing "a
  pseudoscientific '93.4% malicious' number." Severity is computed from
  *which* rules are jointly active (see `detector.py::_severity_for`),
  not a weighted sum.
- **`canary_mutation` fires on mutation/rename/deletion, never on plain
  creation** -- matching the research's precise wording: nothing existed
  at that path to mutate yet if it was just created there.
- **`mass_delete` is supporting-only, never sufficient alone** -- a
  `git clean`-style rapid-delete burst must never, by itself, read as
  ransomware-like activity. Verified directly:
  `tests/test_rules.py::test_mass_delete_alone_never_produces_an_incident`.
- **PCAP-style replay uses event timestamps, never processing speed** --
  the same principle DeauthGuard used, verified directly in
  `tests/test_windows.py`.

## Challenges

**Getting the "escalating severity" story to actually demonstrate
escalation, not simultaneous firing.** A quick ad-hoc run of the engine
against entropy values around 7.98 bits/byte (ciphertext-like) showed
`entropy_transition_burst` and `high_entropy_output_burst` firing
together in the same alert -- correct behavior, since both conditions
were genuinely true at once, but it meant that value couldn't be used to
demonstrate *escalation* (a second, independent rule joining an already-open
incident later). The `fast_transform` fixture was built instead with
post-transformation entropy just under the absolute floor (7.85 vs. the
7.95 threshold), so only `entropy_transition_burst` fires first, with
`extension_churn` (via renames) joining afterward -- verified in
`tests/test_rules.py::test_fast_transform_fixture_escalates_medium_to_high`.

**An early evasion-fixture design would have proved the wrong thing.**
The first draft of `entropy_evasion.jsonl` reused the "already-compressed
media" entropy profile (~7.6 bits/byte) to represent reshaped ciphertext --
but that's a delta of ~3.4 from the low-entropy baseline, comfortably
above the 0.1 delta threshold, which would have made `entropy_transition_burst`
fire anyway and the fixture would not have demonstrated an evasion at all.
Caught by checking the delta math before ever generating or running it,
not by a failing test -- fixed by using a profile that stays close to the
*baseline* entropy (a small, sub-threshold delta) rather than merely "not
maximally high," matching the actual claim in the cited research
(entropy-reshaping techniques defeat detection by not *looking* like
ciphertext, not by looking like a JPEG).

## Results

39/39 pytest tests pass (`pytest -q`, offline synthetic fixtures only,
0.7s). `ruff check src tests tools` reports zero issues across 18 files.
The CLI was run manually against every committed fixture and its
text/JSON output inspected for correctness -- not just the underlying
engine's return values (see `README.md` "Results" for the exact counts).

## Lessons Learned

Writing test fixtures for the cases a detector is expected to catch is
the easy half. Writing fixtures for the cases it's expected to honestly
**miss** (`tests/test_limitations.py`) took real care to construct
correctly -- it is easy to accidentally build an "evasion" fixture that
still trips a different rule by coincidence, which would test the wrong
thing (see "Challenges" above). A detector's credibility comes as much
from documented, verified blind spots as from documented, verified
detections.

## Future Work

See `README.md` "Future Enhancements" -- a `fanotify`-based Linux source
with real process attribution, multiple window horizons for low-and-slow
detection, and cross-process correlation for split-actor campaigns.
