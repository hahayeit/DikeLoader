# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys

from dikeloader.exceptions import SignError
from dikeloader.paths import vendor_dir


def find_zsign() -> Path | None:
    env = os.environ.get("DIKELOADER_ZSIGN")
    candidates = []
    if env:
        candidates.append(Path(env))
    vendor = vendor_dir()
    if sys.platform == "win32":
        candidates.extend(
            [
                vendor / "zsign.exe",
                vendor / "zsign" / "zsign.exe",
            ]
        )
    else:
        candidates.extend([vendor / "zsign", Path("/usr/local/bin/zsign")])
    which = _which("zsign.exe" if sys.platform == "win32" else "zsign")
    if which:
        candidates.append(Path(which))
    for path in candidates:
        if path.is_file():
            return path
    return None


def _which(name: str) -> str | None:
    from shutil import which

    return which(name)


def sign_ipa(
    input_ipa: Path,
    output_ipa: Path,
    p12: Path,
    p12_password: str,
    profile: Path,
    *,
    strip_extensions: bool = True,
    dylibs: list[Path] | None = None,
) -> Path:
    zsign = find_zsign()
    if zsign is None:
        raise SignError(
            "zsign is not installed. From the project folder run:  python -m dikeloader fetch-zsign"
        )
    if not p12.is_file():
        raise SignError("Development certificate (.p12) is missing.")
    if not profile.is_file():
        raise SignError("Provisioning profile is missing.")

    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(zsign),
        "-f",
        "-2",
        "-k",
        str(p12),
        "-p",
        p12_password,
        "-m",
        str(profile),
        "-o",
        str(output_ipa),
        "-z",
        "9",
        "-U",
        "-W",
    ]
    if strip_extensions:
        cmd.append("-E")
    for dylib in dylibs or []:
        cmd.extend(["-l", str(dylib)])
    cmd.append(str(input_ipa))

    flags = 0
    if sys.platform == "win32":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            creationflags=flags,
        )
    except subprocess.TimeoutExpired as exc:
        raise SignError("zsign timed out while signing the IPA.") from exc
    except OSError as exc:
        raise SignError(f"Could not start zsign: {exc}") from exc

    log = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0 or not output_ipa.is_file():
        snippet = log.strip().splitlines()[-12:]
        detail = "\n".join(snippet) if snippet else f"exit {proc.returncode}"
        raise SignError(f"zsign failed:\n{detail}")
    return output_ipa
