"""Compatibility entry point for the graph analysis CLI."""

import sys

from analysis.main import main


if __name__ == "__main__":
    sys.exit(main())
