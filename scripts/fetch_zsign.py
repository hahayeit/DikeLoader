#!/usr/bin/env python3
# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
src = ROOT / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from dikeloader.sign.fetch import fetch_zsign  # noqa: E402


def main() -> int:
    try:
        path = fetch_zsign()
    except Exception as exc:
        print(f"fetch-zsign failed: {exc}", file=sys.stderr)
        return 1
    print(f"Installed {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
