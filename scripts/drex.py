#!/usr/bin/env python3
"""Compatibility entry point for the helper bundled with drex-for-harness."""
from pathlib import Path
import runpy


if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "skills/drex-for-harness/scripts/drex.py"),
        run_name="__main__",
    )
