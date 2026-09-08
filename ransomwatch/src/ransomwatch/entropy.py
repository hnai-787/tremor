"""Shannon entropy computation and file sampling for live monitoring.

Offline replay fixtures carry entropy values directly (computed once, by
the fixture generator) -- this module is only exercised by a live source
reading real files. Sampling head/middle/tail regions (rather than
hashing/reading whole files) is standard defensive-engineering practice
for cost reasons, but it is a real, documented blind spot: ransomware
using partial/intermittent encryption can transform a region this sampler
never reads. See PROJECT_NOTES.md and README "Limitations".
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from .models import EntropySample

DEFAULT_SAMPLE_BYTES = 65536  # 64 KiB per region, an engineering parameter, not a standard


def shannon_entropy(data: bytes) -> float | None:
    """Bits/byte of `data`, or None for empty input."""
    if not data:
        return None
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def sample_file_entropy(
    path: str | Path, sample_bytes: int = DEFAULT_SAMPLE_BYTES
) -> EntropySample | None:
    """Sample head/middle/tail regions of a file and compute entropy for each.

    A file smaller than `sample_bytes` is read once and used for all
    regions it's large enough to cover (so a small file still gets a
    `head` entropy rather than none at all). Returns None only if the file
    can't be read at all (e.g. deleted between the event and this call).
    """
    try:
        size = Path(path).stat().st_size
    except OSError:
        return None
    if size == 0:
        return None

    try:
        with open(path, "rb") as fh:
            head = fh.read(min(sample_bytes, size))

            middle = None
            if size > sample_bytes:
                fh.seek(max(0, size // 2 - sample_bytes // 2))
                middle = fh.read(sample_bytes)

            tail = None
            if size > sample_bytes:
                fh.seek(max(0, size - sample_bytes))
                tail = fh.read(sample_bytes)
    except OSError:
        return None

    return EntropySample(
        head=shannon_entropy(head),
        middle=shannon_entropy(middle) if middle else None,
        tail=shannon_entropy(tail) if tail else None,
    )


def max_segment_delta(before: EntropySample | None, after: EntropySample | None) -> float | None:
    """Largest increase in any one region's entropy, or None if no comparable pair exists.

    Only regions present in BOTH samples are compared -- a region sampled
    only after (e.g. `middle` on a file that grew past the sampling
    threshold) can't be attributed to a change, so it's excluded rather
    than guessed at.
    """
    if before is None or after is None:
        return None
    before_segments = before.segments()
    after_segments = after.segments()
    deltas = [
        after_segments[name] - before_segments[name]
        for name in before_segments
        if name in after_segments
    ]
    return max(deltas) if deltas else None


def is_high_entropy(sample: EntropySample | None, threshold: float) -> bool:
    """True if any sampled region meets/exceeds the high-entropy threshold."""
    if sample is None:
        return False
    value = sample.max_value()
    return value is not None and value >= threshold
