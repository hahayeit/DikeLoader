# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys

from dikeloader.exceptions import SignError
from dikeloader.sign.zsign import find_zsign


def inject_dylibs(input_ipa: Path, output_ipa: Path, dylibs: list[Path], *, adhoc: bool = True) -> Path:
    """Ad-hoc re-sign and inject dylibs with zsign (-l). TrollStore will CoreTrust-sign on device."""
    zsign = find_zsign()
    if zsign is None:
        raise SignError("zsign is not installed. Run: python -m dikeloader fetch-zsign")
    missing = [str(p) for p in dylibs if not p.is_file()]
    if missing:
        raise SignError("Dylib not found: " + ", ".join(missing))
    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(zsign), "-f"]
    if adhoc:
        cmd.append("-a")
    for dylib in dylibs:
        cmd.extend(["-l", str(dylib)])
    cmd.extend(["-o", str(output_ipa), str(input_ipa)])
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, creationflags=flags)
    except OSError as exc:
        raise SignError(f"Could not start zsign: {exc}") from exc
    log = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode != 0 or not output_ipa.is_file():
        snippet = "\n".join(log.splitlines()[-12:]) or f"exit {proc.returncode}"
        raise SignError(f"zsign dylib inject failed:\n{snippet}")
    return output_ipa


def prepare_ipa(input_ipa: Path, output_ipa: Path, dylibs: list[Path]) -> Path:
    """Build the IPA that TrollStore / AppSync / LiveContainer will consume."""
    if dylibs:
        return inject_dylibs(input_ipa, output_ipa, dylibs, adhoc=True)
    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_ipa, output_ipa)
    return output_ipa
