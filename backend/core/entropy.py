"""
backend/core/entropy.py
=======================
Shannon Entropy calculation engine for the RDRS file analysis pipeline.

This module provides a fast, safe, non-blocking Shannon entropy calculator
designed for real-time ransomware detection. Entropy is a key signal because:
  - Encrypted files approach maximum entropy (H ≈ 8.0 bits/byte).
  - Normal plaintext/office documents have low entropy (H ≈ 3.0–5.0).
  - A sudden entropy spike on a file is a strong indicator of encryption.

Algorithm:
  H = -Σ p_i × log₂(p_i)   for i ∈ [0, 255]

  Where p_i = frequency of byte value i / total bytes sampled.

  Result is naturally bounded [0.0, 8.0]:
    0.0 → perfectly uniform (all bytes identical, e.g., a zeroed block)
    8.0 → maximum randomness (uniform distribution, e.g., encrypted/random data)

Performance Design:
  - Files are sampled by reading only the FIRST `sample_size_kb` kilobytes.
    This bounds read time to O(sample_size) regardless of file size, preventing
    the watcher thread from blocking on large files.
  - Byte counting uses a C-backed `collections.Counter` over a bytes buffer,
    which is significantly faster than a pure-Python loop.
  - The entropy calculation itself is vectorized-friendly and avoids math.log
    calls for zero-probability bytes (p_i = 0 → term is 0 by convention).

Safety:
  - All I/O is wrapped in explicit exception handlers.
  - Returns 0.0 (not an exception) for missing, empty, or unreadable files.
  - Never modifies, locks, or holds open the target file beyond the read call.

Usage:
    from backend.core.entropy import calculate_shannon_entropy

    score = calculate_shannon_entropy("/path/to/file.docx")
    # Returns float in [0.0, 8.0]

    # Compute the entropy delta between two snapshots:
    from backend.core.entropy import compute_entropy_delta
    delta = compute_entropy_delta(before=3.2, after=7.8)
    # Returns 4.6
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from loguru import logger

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum theoretical entropy for 8-bit bytes (log2(256) = 8.0).
MAX_ENTROPY: float = 8.0

#: Default sample window in kilobytes. Reading only the first 64 KB ensures
#: sub-millisecond completion even on network-mounted filesystems.
DEFAULT_SAMPLE_SIZE_KB: int = 64

#: Minimum file size in bytes required to compute a meaningful entropy value.
#: Files smaller than this will return 0.0 to avoid misleading scores on
#: trivially small files (e.g., a 1-byte sentinel file).
MIN_FILE_SIZE_BYTES: int = 16


# ===========================================================================
# Core Entropy Function
# ===========================================================================


def calculate_shannon_entropy(
    file_path: str | Path,
    sample_size_kb: int = DEFAULT_SAMPLE_SIZE_KB,
) -> float:
    """
    Calculate the Shannon entropy of a file's byte content.

    Reads up to `sample_size_kb` kilobytes from the beginning of the file
    and computes the Shannon entropy of the byte distribution.

    The result is the standard information-theoretic entropy formula:

        H = -Σ p_i × log₂(p_i)   for i in bytes where p_i > 0

    bounded naturally within [0.0, 8.0] for byte-level analysis.

    Args:
        file_path:      Path to the file to analyze. Accepts str or Path.
        sample_size_kb: Maximum kilobytes to read from the file start.
                        Defaults to 64 KB. Must be between 1 and 65536 (64 MB).

    Returns:
        float: Shannon entropy in bits per byte, in the range [0.0, 8.0].
               Returns 0.0 if the file is empty, missing, unreadable, or
               smaller than MIN_FILE_SIZE_BYTES.

    Raises:
        ValueError: If sample_size_kb is outside the range [1, 65536].

    Examples:
        >>> calculate_shannon_entropy("document.docx")
        4.23                # Typical Office document

        >>> calculate_shannon_entropy("encrypted.locked")
        7.98                # Near-maximum entropy — likely encrypted

        >>> calculate_shannon_entropy("/nonexistent/path.txt")
        0.0                 # Graceful failure, error logged
    """
    # --- Input validation ---
    if not (1 <= sample_size_kb <= 65_536):
        raise ValueError(
            f"sample_size_kb must be between 1 and 65536, got {sample_size_kb}."
        )

    path = Path(file_path)

    # --- File existence and permission checks ---
    try:
        if not path.exists():
            logger.debug(f"Entropy: file does not exist, returning 0.0 | path={path}")
            return 0.0

        if not path.is_file():
            logger.debug(
                f"Entropy: path is not a regular file, returning 0.0 | path={path}"
            )
            return 0.0

        stat = path.stat()
        if stat.st_size == 0:
            logger.debug(f"Entropy: file is empty, returning 0.0 | path={path}")
            return 0.0

        if stat.st_size < MIN_FILE_SIZE_BYTES:
            logger.debug(
                f"Entropy: file too small ({stat.st_size} bytes < {MIN_FILE_SIZE_BYTES}), "
                f"returning 0.0 | path={path}"
            )
            return 0.0

    except PermissionError:
        logger.error(
            f"Entropy: permission denied when accessing file metadata | path={path}"
        )
        return 0.0
    except OSError as exc:
        logger.error(f"Entropy: OS error reading file metadata | path={path} | error={exc}")
        return 0.0

    # --- Read sample ---
    sample_size_bytes = sample_size_kb * 1024
    try:
        with path.open("rb") as fh:
            data: bytes = fh.read(sample_size_bytes)
    except PermissionError:
        logger.error(
            f"Entropy: permission denied when reading file content | path={path}"
        )
        return 0.0
    except OSError as exc:
        logger.error(
            f"Entropy: OS error reading file content | path={path} | error={exc}"
        )
        return 0.0

    # --- Guard: empty read ---
    total_bytes = len(data)
    if total_bytes == 0:
        logger.debug(f"Entropy: read 0 bytes from file, returning 0.0 | path={path}")
        return 0.0

    # --- Compute byte frequency distribution ---
    byte_counts: Counter[int] = Counter(data)

    # --- Shannon entropy calculation ---
    # H = -Σ p_i × log₂(p_i)
    # We skip bytes with count 0 (p_i = 0) since 0 × log₂(0) = 0 by convention.
    entropy: float = 0.0
    for count in byte_counts.values():
        p_i: float = count / total_bytes
        entropy -= p_i * math.log2(p_i)

    # Clamp to [0.0, MAX_ENTROPY] to guard against floating-point edge cases
    entropy = max(0.0, min(entropy, MAX_ENTROPY))

    logger.debug(
        f"Entropy computed | path={path.name} "
        f"| sampled={total_bytes}B | H={entropy:.4f}"
    )
    return round(entropy, 6)


# ===========================================================================
# Batch Entropy Analysis
# ===========================================================================


def calculate_entropy_batch(
    file_paths: list[str | Path],
    sample_size_kb: int = DEFAULT_SAMPLE_SIZE_KB,
) -> dict[str, float]:
    """
    Calculate Shannon entropy for a list of files.

    Processes each file sequentially. For parallel processing of large batches,
    wrap this in a `concurrent.futures.ThreadPoolExecutor` at the call site.

    Args:
        file_paths:     List of file paths to analyze.
        sample_size_kb: Sample size in KB applied to each file.

    Returns:
        dict[str, float]: Mapping of absolute file path string to entropy score.
                          Files that fail are included with a score of 0.0.

    Example:
        results = calculate_entropy_batch(["/home/user/doc.pdf", "/home/user/enc.locked"])
        # {"/home/user/doc.pdf": 4.21, "/home/user/enc.locked": 7.96}
    """
    results: dict[str, float] = {}
    for fp in file_paths:
        path = Path(fp)
        results[str(path.resolve())] = calculate_shannon_entropy(
            path, sample_size_kb=sample_size_kb
        )
    return results


# ===========================================================================
# Delta and Classification Helpers
# ===========================================================================


def compute_entropy_delta(before: float, after: float) -> float:
    """
    Compute the absolute entropy change between two file scans.

    A positive delta indicates entropy increased (file became more random).
    A large positive delta (e.g., > 2.0) is a strong encryption indicator.

    Args:
        before: Entropy score before the file modification event.
        after:  Entropy score after the file modification event.

    Returns:
        float: Absolute difference |after - before|, rounded to 6 decimal places.

    Example:
        >>> compute_entropy_delta(before=3.2, after=7.8)
        4.6
    """
    return round(abs(after - before), 6)


def classify_entropy(score: float) -> str:
    """
    Classify a raw entropy score into a human-readable category.

    Classification bands are calibrated for common file type distributions:
      - 0.0–1.0 : Very low  (highly repetitive data, e.g., padding files)
      - 1.0–3.0 : Low       (structured text, config files, simple code)
      - 3.0–5.5 : Medium    (binary executables, Office documents, images)
      - 5.5–7.0 : High      (compressed archives, video, audio)
      - 7.0–8.0 : Very high (encrypted data, high-quality random data)

    Args:
        score: Shannon entropy value in [0.0, 8.0].

    Returns:
        str: One of "VERY_LOW", "LOW", "MEDIUM", "HIGH", "VERY_HIGH".

    Raises:
        ValueError: If score is outside [0.0, 8.0].
    """
    if not (0.0 <= score <= MAX_ENTROPY):
        raise ValueError(f"Entropy score {score:.4f} is outside valid range [0.0, {MAX_ENTROPY}].")

    if score < 1.0:
        return "VERY_LOW"
    if score < 3.0:
        return "LOW"
    if score < 5.5:
        return "MEDIUM"
    if score < 7.0:
        return "HIGH"
    return "VERY_HIGH"


def is_likely_encrypted(
    score: float,
    threshold: float = 7.0,
) -> bool:
    """
    Heuristic check: returns True if the entropy score suggests encryption.

    Files encrypted with AES, ChaCha20, or similar modern ciphers typically
    exhibit entropy scores above 7.5. A threshold of 7.0 provides a margin
    for partially-encrypted or padded files.

    Args:
        score:     Shannon entropy of the file.
        threshold: Minimum score to classify as likely encrypted (default: 7.0).

    Returns:
        bool: True if score >= threshold.

    Example:
        >>> is_likely_encrypted(7.98)
        True
        >>> is_likely_encrypted(4.23)
        False
    """
    return score >= threshold
