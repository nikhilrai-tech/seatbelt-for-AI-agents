from __future__ import annotations

import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    print(f"seatbelt {__version__}: nothing to do yet, see the README for the roadmap.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
