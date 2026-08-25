# Copyright (C) 2026 DikeLoader
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path

from dikeloader.exceptions import JailbreakError
from dikeloader.jailbreak.ssh import SSHSession

REMOTE_DEB = "/var/mobile/Documents/dikeloader-install.deb"


def install_deb(ssh: SSHSession, deb: Path) -> str:
    if not deb.is_file() or deb.suffix.lower() != ".deb":
        raise JailbreakError("Choose a .deb tweak package.")
    ssh.put(deb, REMOTE_DEB)
    ssh.check(f'chmod 0644 "{REMOTE_DEB}"')
    code, out, err = ssh.run(f'dpkg -i "{REMOTE_DEB}"', timeout=180)
    log = (out + "\n" + err).strip()
    ssh.run("dpkg --configure -a || true")
    ssh.run(f'rm -f "{REMOTE_DEB}"')
    if code != 0 and "dependency" not in log.lower():
        raise JailbreakError(log[:600] or "dpkg failed.")
    ssh.run("uicache -a >/dev/null 2>&1 || true")
    return log or "Installed .deb with dpkg (rootless /var/jb)."
