# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from dikeloader.exceptions import KikeError
from dikeloader.paths import app_data_dir


TASK_NAME = "DikeLoaderAutoRefresh"


def _python() -> Path:
    return Path(sys.executable)


def _tr() -> str:
    py = str(_python())
    # pythonw avoids a console flash for the scheduled task
    if py.lower().endswith("python.exe"):
        candidate = Path(py).with_name("pythonw.exe")
        if candidate.is_file():
            py = str(candidate)
    return f'"{py}" -m dikeloader refresh-all'


def install_refresh_task(hours: int = 12) -> str:
    if sys.platform != "win32":
        raise KikeError("The auto-refresh service is Windows-only.")
    hours = max(1, min(24, int(hours)))
    log = app_data_dir() / "refresh.log"
    cmd = [
        "schtasks",
        "/Create",
        "/F",
        "/TN",
        TASK_NAME,
        "/SC",
        "HOURLY",
        "/MO",
        str(hours),
        "/RL",
        "LIMITED",
        "/TR",
        _tr(),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        detail = (proc.stdout or "") + (proc.stderr or "")
        raise KikeError(detail.strip() or "schtasks failed. Run DikeLoader as your Windows user.")
    return (
        f"Windows will re-sign Apple ID apps every {hours} hours (task {TASK_NAME}). "
        f"TrollStore / LiveContainer apps do not expire and are skipped. Log: {log}"
    )


def uninstall_refresh_task() -> str:
    proc = subprocess.run(
        ["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0,
    )
    if proc.returncode != 0:
        return "No auto-refresh task was installed."
    return f"Removed Windows task {TASK_NAME}."


def task_installed() -> bool:
    proc = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0,
    )
    return proc.returncode == 0
