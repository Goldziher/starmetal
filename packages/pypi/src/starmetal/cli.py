"""Small namespace-hold CLI for the initial StarMetal package release."""

from __future__ import annotations

import argparse

from starmetal import __version__


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sm",
        description="StarMetal namespace package. Build from source or use Docker for the current server.",
    )
    parser.add_argument("--version", action="version", version=f"sm {__version__}")
    parser.parse_args()
    print(
        "StarMetal 0.0.1\n\n"
        "This PyPI package reserves the public starmetal namespace while the native sm CLI "
        "distribution is finalized.\n"
        "Repository: https://github.com/Goldziher/starmetal"
    )


if __name__ == "__main__":
    main()
