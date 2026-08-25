# Copyright (C) 2026 DikeLoader contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import hashlib
import io
import json
import urllib.request
import zipfile

from dikeloader.paths import vendor_dir

RELEASES = "https://api.github.com/repos/zhlynn/zsign/releases/latest"
ASSET_NAME = "zsign-windows-x64.zip"


def fetch_zsign(dest: Path | None = None) -> Path:
    dest_dir = dest or vendor_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        RELEASES,
        headers={"User-Agent": "DikeLoader/1.0", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=60) as resp:
        release = json.loads(resp.read().decode("utf-8"))
    asset = next((item for item in release.get("assets") or [] if item.get("name") == ASSET_NAME), None)
    if not asset:
        raise RuntimeError(f"GitHub release has no {ASSET_NAME}.")
    url = asset["browser_download_url"]
    digest = ""
    if isinstance(asset.get("digest"), str) and asset["digest"].startswith("sha256:"):
        digest = asset["digest"].split(":", 1)[1]
    with urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "DikeLoader/1.0"}),
        timeout=120,
    ) as resp:
        blob = resp.read()
    if digest:
        actual = hashlib.sha256(blob).hexdigest()
        if actual.lower() != digest.lower():
            raise RuntimeError("zsign zip hash did not match the GitHub release digest.")
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        found = False
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            target = dest_dir / Path(name).name
            target.write_bytes(zf.read(name))
            if Path(name).name.lower() == "zsign.exe":
                found = True
        if not found:
            raise RuntimeError("The zsign zip did not contain zsign.exe.")
    zsign = dest_dir / "zsign.exe"
    if not zsign.is_file():
        raise RuntimeError("Failed to extract zsign.exe.")
    return zsign
