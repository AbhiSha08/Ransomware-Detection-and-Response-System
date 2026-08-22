"""
simulate_attack.py — RDRS Ransomware Outbreak Simulation Utility
===================================================================
Simulates a rapid ransomware attack sequence strictly inside data/sandbox/
to test real-time detection, threat scoring, SSE broadcasting, and quarantine.

Attack Sequence:
1. Target Initialization: Creates benign target documents in data/sandbox/watch_dir/
2. Mass Modification & Encryption: Rewrites files with high-entropy pseudo-random bytes
3. Mass Extension Renaming: Appends .locked / .crypto extensions rapidly
4. Evasion Simulation: Simulates VSS shadow copy deletion command string execution

Usage:
    python scripts/simulate_attack.py
"""

from __future__ import annotations

import os
import sys
import time
import secrets
import argparse
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
SANDBOX_DIR = PROJECT_ROOT / "data" / "sandbox" / "watch_dir"
QUARANTINE_DIR = PROJECT_ROOT / "data" / "sandbox" / "quarantine"

# Ransomware extensions
RANSOM_EXTENSIONS = [".locked", ".crypto", ".enc", ".rdrs_locked"]


def print_banner() -> None:
    print("=" * 70)
    print(" 🚀 RDRS Ransomware Simulation Suite")
    print("=" * 70)
    print(f" Target Sandbox Directory : {SANDBOX_DIR}")
    print(f" Evidence Quarantine Dir : {QUARANTINE_DIR}")
    print(" Security Assurance      : STRICT CONTAINMENT — NO EXTERNAL I/O")
    print("=" * 70)


def setup_sandbox() -> list[Path]:
    """Create benign document files in sandbox."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    created_files: list[Path] = []
    print("\n[+] Step 1: Initializing 25 benign target documents...")

    for i in range(1, 26):
        file_path = SANDBOX_DIR / f"financial_report_{i:02d}.docx"
        # Initial low-entropy text content
        content = f"CONFIDENTIAL FINANCIAL DATA - REPORT RECORD #{i:04d}\n" + ("Standard prose line. " * 50)
        file_path.write_text(content, encoding="utf-8")
        created_files.append(file_path)

    print(f"    ✔ Created {len(created_files)} benign files in {SANDBOX_DIR}")
    return created_files


def execute_attack_burst(files: list[Path]) -> None:
    """Execute rapid encryption & renaming sequence."""
    print("\n[!] Step 2: Launching Simulated High-Entropy Mass Renaming Burst...")
    start_time = time.time()
    modified_count = 0
    renamed_count = 0

    for i, original_path in enumerate(files):
        if not original_path.exists():
            continue

        # 1. High entropy byte rewrite (simulating AES/ChaCha20 encryption)
        high_entropy_bytes = secrets.token_bytes(64 * 1024)
        original_path.write_bytes(high_entropy_bytes)
        modified_count += 1

        # 2. Rapid mass renaming to .locked extension
        new_ext = RANSOM_EXTENSIONS[i % len(RANSOM_EXTENSIONS)]
        locked_path = original_path.with_suffix(original_path.suffix + new_ext)
        original_path.rename(locked_path)
        renamed_count += 1

        print(f"    ⚡ [{i+1:02d}/25] Encrypted & Renamed: {original_path.name} -> {locked_path.name}")
        time.sleep(0.05)  # 50ms burst interval

    elapsed = time.time() - start_time
    print(f"\n[+] Outbreak Complete: {renamed_count} files encrypted & renamed in {elapsed:.2f}s!")
    print(f"    Burst Velocity: {renamed_count / elapsed:.1f} ops/sec")


def main() -> None:
    parser = argparse.ArgumentParser(description="RDRS Attack Simulator")
    parser.add_argument("--cleanup", action="store_true", help="Clean sandbox after run")
    args = parser.parse_args()

    print_banner()
    files = setup_sandbox()
    
    print("\n[?] Pausing 2 seconds before outbreak initiation...")
    time.sleep(2.0)

    execute_attack_burst(files)

    print("\n" + "=" * 70)
    print(" 🔥 Attack Simulation Finished!")
    print(" Check the SOC Dashboard at http://localhost:5173 to view live alerts.")
    print(" Check API Health at http://localhost:8000/api/v1/health")
    print("=" * 70)


if __name__ == "__main__":
    main()
