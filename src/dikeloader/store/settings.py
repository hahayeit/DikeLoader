# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import json

from dikeloader.paths import app_data_dir

METHODS = ("trollstore", "livecontainer", "appsync", "apple")


@dataclass
class Settings:
    install_method: str = "trollstore"
    ssh_user: str = "root"
    use_usb_ssh: bool = True
    usb_ssh_port: int = 2222
    wifi_ssh_host: str = ""
    wifi_ssh_port: int = 22
    prefer_wifi: bool = False
    inject_dylibs: list[str] = field(default_factory=list)


def _path() -> Path:
    return app_data_dir() / "settings.json"


def load_settings() -> Settings:
    path = _path()
    if not path.is_file():
        return Settings()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return Settings()
    if not isinstance(raw, dict):
        return Settings()
    method = str(raw.get("install_method") or "trollstore")
    if method not in METHODS:
        method = "trollstore"
    dylibs = [str(p) for p in (raw.get("inject_dylibs") or []) if p]
    return Settings(
        install_method=method,
        ssh_user=str(raw.get("ssh_user") or "root"),
        use_usb_ssh=bool(raw.get("use_usb_ssh", True)),
        usb_ssh_port=int(raw.get("usb_ssh_port") or 2222),
        wifi_ssh_host=str(raw.get("wifi_ssh_host") or ""),
        wifi_ssh_port=int(raw.get("wifi_ssh_port") or 22),
        prefer_wifi=bool(raw.get("prefer_wifi", False)),
        inject_dylibs=dylibs,
    )


def save_settings(settings: Settings) -> None:
    _path().write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
