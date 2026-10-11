"""Compatibility entry point for graph engine checks."""

import runpy
from pathlib import Path


if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).resolve().parent / "tests" / "test_cases.py"),
        run_name="__main__",
    )
