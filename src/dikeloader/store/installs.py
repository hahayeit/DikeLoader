# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import json

from dikeloader.paths import app_data_dir


@dataclass
class InstallRecord:
    bundle_id: str
    name: str
    email: str
    udid: str
    cache_path: str
    signed_at: str
    expires_at: str | None
    team_id: str = ""
    version: str = ""
    method: str = "apple"

    @property
    def expiry(self) -> datetime | None:
        if not self.expires_at:
            return None
        try:
            return datetime.fromisoformat(self.expires_at)
        except ValueError:
            return None

    def days_left(self) -> int | None:
        when = self.expiry
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        delta = when - datetime.now(timezone.utc)
        return int(delta.total_seconds() // 86400)


def _path() -> Path:
    return app_data_dir() / "installs.json"


def list_installs() -> list[InstallRecord]:
    path = _path()
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    items = raw.get("installs") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return []
    rows: list[InstallRecord] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("bundle_id"):
            continue
        rows.append(
            InstallRecord(
                bundle_id=str(item.get("bundle_id")),
                name=str(item.get("name") or item.get("bundle_id")),
                email=str(item.get("email") or ""),
                udid=str(item.get("udid") or ""),
                cache_path=str(item.get("cache_path") or ""),
                signed_at=str(item.get("signed_at") or ""),
                expires_at=item.get("expires_at"),
                team_id=str(item.get("team_id") or ""),
                version=str(item.get("version") or ""),
                method=str(item.get("method") or "apple"),
            )
        )
    return rows


def _save(rows: list[InstallRecord]) -> None:
    payload = {"installs": [asdict(r) for r in rows]}
    _path().write_text(json.dumps(payload, indent=2), encoding="utf-8")


def record_install(row: InstallRecord) -> None:
    rows = [r for r in list_installs() if r.bundle_id != row.bundle_id or r.udid != row.udid]
    rows.append(row)
    _save(rows)


def forget_install(bundle_id: str, udid: str | None = None) -> None:
    rows = [
        r
        for r in list_installs()
        if not (r.bundle_id == bundle_id and (udid is None or r.udid == udid))
    ]
    _save(rows)
