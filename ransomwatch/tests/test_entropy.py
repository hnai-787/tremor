import pytest

from ransomwatch.entropy import is_high_entropy, max_segment_delta, shannon_entropy
from ransomwatch.models import EntropySample


def test_shannon_entropy_of_uniform_bytes_is_zero():
    assert shannon_entropy(b"\x00" * 100) == 0.0


def test_shannon_entropy_of_uniform_random_looking_bytes_is_high():
    # 256 distinct byte values in equal proportion -> exactly 8 bits/byte
    data = bytes(range(256)) * 10
    assert shannon_entropy(data) == 8.0


def test_shannon_entropy_of_empty_is_none():
    assert shannon_entropy(b"") is None


def test_max_segment_delta_compares_matching_regions_only():
    before = EntropySample(head=4.0, middle=4.0, tail=None)
    after = EntropySample(head=4.5, middle=7.9, tail=7.9)
    # tail excluded (no "before" for it); max of head(+0.5) and middle(+3.9) is 3.9
    assert max_segment_delta(before, after) == pytest.approx(3.9)


def test_max_segment_delta_none_when_before_missing():
    assert max_segment_delta(None, EntropySample(head=7.9)) is None


def test_is_high_entropy_checks_any_segment():
    sample = EntropySample(head=4.0, middle=4.0, tail=7.99)
    assert is_high_entropy(sample, threshold=7.95) is True
    assert is_high_entropy(sample, threshold=8.0) is False


def test_is_high_entropy_of_none_is_false():
    assert is_high_entropy(None, threshold=7.95) is False
