"""
tests/test_entropy.py
======================
Unit tests for the Shannon entropy calculation engine (backend.core.entropy).

Tests cover:
  - Predictable plaintext vs high-randomness/encrypted byte structures.
  - Edge cases (empty file, missing file, tiny files, permission handling).
  - Sample size bounds and invalid parameter validation.
  - Batch analysis, delta calculation, classification bands, and encryption heuristics.
"""

import os
from pathlib import Path
import pytest

from backend.core.entropy import (
    calculate_shannon_entropy,
    calculate_entropy_batch,
    classify_entropy,
    compute_entropy_delta,
    is_likely_encrypted,
    MAX_ENTROPY,
)


def test_predictable_text_low_entropy(sandbox: Path) -> None:
    """Predictable plain text should produce a low/medium entropy score (< 5.0)."""
    text_file = sandbox / "plain_document.txt"
    text_file.write_text("A" * 2048, encoding="utf-8")  # Identical repeated byte

    score = calculate_shannon_entropy(text_file)
    assert score == 0.0, "Repeated single byte must have 0.0 entropy"


def test_structured_english_entropy(sandbox: Path) -> None:
    """Structured English prose should yield low/medium entropy (3.0 - 5.0)."""
    prose_file = sandbox / "article.txt"
    prose_file.write_text(
        "The Ransomware Detection and Response System monitors process and filesystem activity in real-time. " * 50,
        encoding="utf-8",
    )

    score = calculate_shannon_entropy(prose_file)
    assert 3.0 <= score <= 5.0, f"Expected prose entropy in [3.0, 5.0], got {score}"
    assert classify_entropy(score) in ("LOW", "MEDIUM")


def test_random_encrypted_high_entropy(sandbox: Path) -> None:
    """Random binary data (simulating encryption) must yield high entropy (>= 7.5)."""
    crypto_file = sandbox / "encrypted.locked"
    # Write 64 KB of cryptographically random bytes
    random_bytes = os.urandom(64 * 1024)
    crypto_file.write_bytes(random_bytes)

    score = calculate_shannon_entropy(crypto_file)
    assert score >= 7.5, f"Expected high entropy >= 7.5 for random bytes, got {score}"
    assert score <= MAX_ENTROPY
    assert classify_entropy(score) in ("HIGH", "VERY_HIGH")
    assert is_likely_encrypted(score, threshold=7.0) is True


def test_empty_file_returns_zero(sandbox: Path) -> None:
    """Empty files must return 0.0 entropy without raising exceptions."""
    empty_file = sandbox / "empty.dat"
    empty_file.write_bytes(b"")

    assert calculate_shannon_entropy(empty_file) == 0.0


def test_missing_file_returns_zero(sandbox: Path) -> None:
    """Non-existent files must return 0.0 entropy gracefully."""
    missing_file = sandbox / "does_not_exist.tmp"
    assert calculate_shannon_entropy(missing_file) == 0.0


def test_tiny_file_below_minimum_size(sandbox: Path) -> None:
    """Files smaller than MIN_FILE_SIZE_BYTES (16 bytes) return 0.0."""
    tiny_file = sandbox / "tiny.bin"
    tiny_file.write_bytes(b"12345")  # 5 bytes

    assert calculate_shannon_entropy(tiny_file) == 0.0


def test_invalid_sample_size_raises_value_error(sandbox_file: Path) -> None:
    """Sample size outside [1, 65536] must raise ValueError."""
    with pytest.raises(ValueError):
        calculate_shannon_entropy(sandbox_file, sample_size_kb=0)

    with pytest.raises(ValueError):
        calculate_shannon_entropy(sandbox_file, sample_size_kb=100000)


def test_compute_entropy_delta() -> None:
    """Test entropy delta calculation between before and after snapshots."""
    delta = compute_entropy_delta(before=3.2, after=7.8)
    assert delta == 4.6

    delta_reverse = compute_entropy_delta(before=7.8, after=3.2)
    assert delta_reverse == 4.6


def test_classify_entropy_bands() -> None:
    """Test full range of classification helper function."""
    assert classify_entropy(0.5) == "VERY_LOW"
    assert classify_entropy(2.0) == "LOW"
    assert classify_entropy(4.5) == "MEDIUM"
    assert classify_entropy(6.5) == "HIGH"
    assert classify_entropy(7.8) == "VERY_HIGH"

    with pytest.raises(ValueError):
        classify_entropy(9.0)


def test_batch_entropy_calculation(sandbox: Path) -> None:
    """Test batch entropy calculation over multiple files."""
    f1 = sandbox / "f1.txt"
    f2 = sandbox / "f2.bin"
    f1.write_text("Hello World! " * 20, encoding="utf-8")
    f2.write_bytes(os.urandom(2048))

    batch_results = calculate_entropy_batch([f1, f2])
    assert len(batch_results) == 2
    assert str(f1.resolve()) in batch_results
    assert str(f2.resolve()) in batch_results
    assert batch_results[str(f2.resolve())] > batch_results[str(f1.resolve())]
