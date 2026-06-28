"""CLI entry point for the StarMetal Python package."""

from __future__ import annotations

import sys

from starmetal.downloader import run_sm


def main() -> None:
    run_sm(sys.argv[1:])


if __name__ == "__main__":
    main()
