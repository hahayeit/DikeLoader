# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import json

from dikeloader.paths import app_data_dir


def _path() -> Path:
    return app_data_dir() / "accounts.json"


def list_saved_emails() -> list[str]:
    path = _path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    emails = data.get("emails") if isinstance(data, dict) else None
    if not isinstance(emails, list):
        return []
    return [str(e) for e in emails if e]


def remember_account(email: str) -> None:
    email = email.strip()
    emails = list_saved_emails()
    if email.lower() not in {e.lower() for e in emails}:
        emails.append(email)
    _path().write_text(json.dumps({"emails": emails, "active": email}, indent=2), encoding="utf-8")


def forget_account(email: str) -> None:
    emails = [e for e in list_saved_emails() if e.lower() != email.lower()]
    _path().write_text(json.dumps({"emails": emails}, indent=2), encoding="utf-8")


def active_email() -> str | None:
    path = _path()
    if not path.is_file():
        emails = list_saved_emails()
        return emails[0] if emails else None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        active = data.get("active")
        if active:
            return str(active)
    except Exception:
        pass
    emails = list_saved_emails()
    return emails[0] if emails else None
