# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import os
import sys


def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        root = Path(base)
    else:
        root = Path.home() / "AppData" / "Local"
    path = root / "DikeLoader"
    path.mkdir(parents=True, exist_ok=True)
    return path


def repo_root() -> Path:
    """Directory that contains pyproject.toml when running from source."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[2], here.parents[1], Path.cwd()):
        if (candidate / "pyproject.toml").exists() or (candidate / "vendor").exists():
            return candidate
    return Path.cwd()


def vendor_dir() -> Path:
    bundled = Path(sys.executable).resolve().parent / "vendor"
    if bundled.is_dir():
        return bundled
    return repo_root() / "vendor"


def anisette_dir() -> Path:
    path = app_data_dir() / "anisette"
    path.mkdir(parents=True, exist_ok=True)
    return path


def certs_dir(email: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "@._-" else "_" for c in email.lower())
    path = app_data_dir() / "certs" / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def ipa_cache_dir() -> Path:
    path = app_data_dir() / "ipa_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path
