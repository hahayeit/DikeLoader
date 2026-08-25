# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime, timezone
import locale
import re


XCODE_CLIENT_INFO = (
    "<MacBookPro18,3> <Mac OS X;14.6.1;23G93> "
    "<com.apple.AuthKit/1 (com.apple.dt.Xcode/16A242d)>"
)
XCODE_VERSION = "16.0 (16A242d)"
GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"


def utc_client_time() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def ascii_timezone() -> str:
    offset = datetime.now().astimezone().utcoffset()
    if offset is None:
        return "UTC"
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    minutes = abs(minutes)
    return f"GMT{sign}{minutes // 60:02d}:{minutes % 60:02d}"


def ascii_locale() -> str:
    raw = None
    try:
        raw = locale.getlocale()[0]
    except Exception:
        raw = None
    if not raw:
        return "en_US"
    if not raw.isascii():
        return "en_US"
    lowered = raw.replace("-", "_")
    if lowered.lower().startswith("english"):
        return "en_US"
    parts = re.split(r"[._]", lowered)
    if len(parts) >= 2 and parts[0].isalpha() and parts[1].isalpha():
        return f"{parts[0][:2].lower()}_{parts[1][:2].upper()}"
    if parts[0].isalpha():
        return f"{parts[0][:2].lower()}_US"
    return "en_US"


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Force Apple-style ASCII headers (Windows localized TZ names break HTTP)."""
    out = {}
    for key, value in headers.items():
        if value is None:
            continue
        text = str(value)
        if key in {"X-Apple-I-TimeZone"}:
            text = ascii_timezone()
        elif key in {"X-Apple-Locale", "loc"}:
            text = ascii_locale()
        elif key == "X-Apple-I-Client-Time":
            text = utc_client_time()
        if not text.isascii():
            text = text.encode("ascii", "replace").decode("ascii")
        out[key] = text
    return out
