# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Local in-process anisette (Apple device identity) — credentials never leave this PC."""

from __future__ import annotations

from pathlib import Path
import threading

from dikeloader.apple.headers import (
    XCODE_CLIENT_INFO,
    sanitize_headers,
)
from dikeloader.exceptions import AppleAuthError
from dikeloader.paths import anisette_dir

_lock = threading.Lock()
_instance = None


def _paths() -> tuple[Path, Path, Path]:
    root = anisette_dir()
    return root / "libs.bin", root / "provisioning.bin", root / "session.bin"


def _load_or_init():
    from anisette import Anisette

    libs, provisioning, session = _paths()
    if session.is_file() and session.stat().st_size > 0:
        return Anisette.load(session)
    files = [p for p in (libs, provisioning) if p.is_file() and p.stat().st_size > 0]
    if files:
        return Anisette.load(*files)
    if libs.is_file() and libs.stat().st_size > 0:
        return Anisette.init(libs)
    return Anisette.init()


def _persist(ani) -> None:
    libs, provisioning, session = _paths()
    try:
        ani.save_libs(libs)
    except Exception:
        pass
    try:
        ani.save_provisioning(provisioning)
    except Exception:
        try:
            ani.save_all(session)
        except Exception:
            pass


def get_anisette_headers(*, xcode_client: bool = True) -> dict[str, str]:
    """Return GSA / developer-services anisette headers generated locally."""
    global _instance
    with _lock:
        try:
            if _instance is None:
                _instance = _load_or_init()
            data = dict(_instance.get_data())
            _persist(_instance)
        except Exception as exc:
            raise AppleAuthError(
                "Could not generate a local Apple device identity (anisette). "
                f"Check your network on first run so the identity libraries can download. Details: {exc}"
            ) from exc

    headers = sanitize_headers({str(k): str(v) for k, v in data.items()})
    if xcode_client:
        headers["X-MMe-Client-Info"] = XCODE_CLIENT_INFO
        headers["X-Mme-Client-Info"] = XCODE_CLIENT_INFO
    headers.setdefault("X-Apple-I-MD-RINFO", "17106176")
    headers.setdefault("X-Apple-I-SRL-NO", "0")
    headers["loc"] = headers.get("X-Apple-Locale", "en_US")
    return headers


def reset_anisette() -> None:
    global _instance
    with _lock:
        _instance = None
