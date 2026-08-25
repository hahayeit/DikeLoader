# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import shlex
import tempfile
import zipfile
from dikeloader.jailbreak.ssh import SSHSession

LIVECONTAINER_PLISTS = (
    "com.kdt.livecontainer.plist",
    "com.kdt.livecontainer.sidecar.plist",
)


def _data_root(ssh: SSHSession) -> str:
    for name in LIVECONTAINER_PLISTS:
        code, out, _err = ssh.run(
            f'ls /var/mobile/Containers/Data/Application/*/Library/Preferences/{name} 2>/dev/null | head -1'
        )
        path = (out or "").strip().splitlines()
        if code == 0 and path and path[0]:
            # .../Application/<UUID>/Library/Preferences/foo.plist -> data container
            pref = path[0]
            return pref.rsplit("/Library/Preferences/", 1)[0]
    raise JailbreakError(
        "LiveContainer is not installed. Install LiveContainer with TrollStore first, "
        "open it once, then try again."
    )


def install_into_livecontainer(ssh: SSHSession, ipa: Path) -> str:
    """Drop an IPA/.app into LiveContainer's Documents so it can load without a full install."""
    if not ipa.is_file():
        raise JailbreakError(f"IPA missing: {ipa}")
    root = _data_root(ssh)
    docs = f"{root}/Documents"
    apps = f"{docs}/Applications"
    drop = f"{docs}/DikeLoader"
    ssh.check(f'mkdir -p {shlex.quote(apps)} {shlex.quote(drop)}')
    remote_ipa = f"{drop}/{ipa.name}"
    ssh.put(ipa, remote_ipa)

    with tempfile.TemporaryDirectory(prefix="dike-lc-") as tmp:
        with zipfile.ZipFile(ipa) as zf:
            zf.extractall(tmp)
        payload = Path(tmp) / "Payload"
        app_dirs = list(payload.glob("*.app")) if payload.is_dir() else []
        if not app_dirs:
            return (
                f"Copied {ipa.name} to LiveContainer Documents/DikeLoader. "
                "Open LiveContainer and import the IPA."
            )
        app = app_dirs[0]
        remote_app = f"{apps}/{app.name}"
        ssh.check(f'rm -rf {shlex.quote(remote_app)}')
        # tar over SSH keeps Mach-O files and symlinks intact
        import subprocess

        tar = subprocess.run(
            ["tar", "-C", str(app.parent), "-cf", "-", app.name],
            capture_output=True,
            timeout=120,
        )
        if tar.returncode != 0 or not tar.stdout:
            # Windows often has no tar that we like; fall back to IPA import only
            return (
                f"Copied {ipa.name} into LiveContainer. Open LiveContainer → import "
                f"Documents/DikeLoader/{ipa.name}."
            )
        sftp = ssh.client.open_sftp()
        try:
            with sftp.open(f"{drop}/payload.tar", "wb") as fh:
                fh.write(tar.stdout)
        finally:
            sftp.close()
        ssh.check(
            f'tar -C {shlex.quote(apps)} -xf {shlex.quote(drop + "/payload.tar")} && '
            f'chmod -R 0755 {shlex.quote(remote_app)}'
        )
    return (
        f"Installed {app.name} into LiveContainer/Applications. "
        "Open LiveContainer to launch it (no SpringBoard icon)."
    )
